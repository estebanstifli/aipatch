<?php
/**
 * File Classifier — Layered Risk Scoring Engine.
 *
 * Takes heuristic signals, file path, file hash, and optional baseline
 * data for a single file and produces a multi-dimensional risk
 * assessment with a composite score (0–100), classification label,
 * family guess, and detailed reason/flag arrays.
 *
 * Scoring layers:
 *   A) Content  — signal severity, dangerous combos, obfuscation level
 *   B) Context  — path location, extension, naming patterns
 *   C) Integrity — baseline drift (new / modified / missing hash)
 *   D) Reduction — vendor allowlists, benign patterns, hash allowlists
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_File_Classifier
 */
class AIPSC_File_Classifier {

    const CLASS_CLEAN      = 'clean';
    const CLASS_SUSPICIOUS = 'suspicious';
    const CLASS_RISKY      = 'risky';
    const CLASS_MALICIOUS  = 'malicious';

    /* ---------------------------------------------------------------
     * Layer weights (sum = 1.0).
     * ------------------------------------------------------------- */

    const W_CONTENT   = 0.55;
    const W_CONTEXT   = 0.25;
    const W_INTEGRITY = 0.20;

    /* ---------------------------------------------------------------
     * Dangerous signal combinations (bonus penalty).
     * Each combo is an array of tags that, when ALL present, trigger
     * a bonus. The bonus is added to the raw content score.
     * ------------------------------------------------------------- */

    private static $dangerous_combos = array(
        // Tag-based combos.
        array( 'tags' => array( 'exec', 'obfuscation' ),            'bonus' => 15, 'reason' => 'Execution + obfuscation combo' ),
        array( 'tags' => array( 'exec', 'userinput' ),              'bonus' => 20, 'reason' => 'Execution of user input' ),
        array( 'tags' => array( 'obfuscation', 'network' ),         'bonus' => 12, 'reason' => 'Obfuscated + network activity' ),
        array( 'tags' => array( 'exec', 'network' ),                'bonus' => 12, 'reason' => 'Execution + network activity' ),
        array( 'tags' => array( 'exec', 'write' ),                  'bonus' => 10, 'reason' => 'Execution + file writes (dropper)' ),
        array( 'tags' => array( 'obfuscation', 'write', 'exec' ),   'bonus' => 18, 'reason' => 'Obfuscated dropper with execution' ),
        array( 'tags' => array( 'backdoor' ),                       'bonus' => 15, 'reason' => 'Backdoor signature' ),
        array( 'tags' => array( 'hidden_php', 'exec' ),             'bonus' => 20, 'reason' => 'Hidden PHP with code execution' ),
        array( 'tags' => array( 'hidden_php', 'obfuscation' ),      'bonus' => 18, 'reason' => 'Hidden PHP with obfuscation' ),
        array( 'tags' => array( 'upload', 'exec' ),                 'bonus' => 15, 'reason' => 'Upload handling + execution' ),
        array( 'tags' => array( 'network', 'write', 'exec' ),       'bonus' => 20, 'reason' => 'Fetch + write + exec (full dropper chain)' ),
        array( 'tags' => array( 'compound', 'dangerous' ),          'bonus' => 10, 'reason' => 'Compound correlation rule triggered' ),
    );

    /* ---------------------------------------------------------------
     * Context patterns.
     * ------------------------------------------------------------- */

    /** Extensions that should never appear in a WP install. */
    private static $rare_extensions = array( 'pht', 'phps', 'phtml', 'php5', 'php7', 'shtml', 'cgi', 'pl' );

    /** Filename patterns commonly used by malware. */
    private static $suspicious_names = array(
        '/^(?:shell|cmd|r57|c99|wso|b374k|spy|phpspy|phpinfo|adminer|filemanager|0x)/i',
        '/^(?:\.[\w]+\.php)/i', // dot-prefixed hidden PHP files
        '/^(?:wp-(?:tmp|cache|core|conf)\d*\.php)/i', // fake WP core files
        '/^(?:class-wp-(?:tmp|cache|core|conf)\d*\.php)/i',
    );

    /** Paths where PHP is expected (used for benign context). */
    private static $benign_paths = array(
        '#/(vendor|node_modules|tests?|test-data|fixtures|__tests__|spec)/#i',
        '#/\.(?:github|circleci|gitlab)/#i',
    );

    /** Known vendor indicators (reduce FP for legitimate libraries). */
    private static $vendor_indicators = array(
        '#/vendor/autoload\.php$#',
        '#/vendor/composer/#',
        '#/node_modules/#',
        '#/(?:phpunit|codeception|behat|phpstan|psalm)#i',
    );

    /** PHP-executable extensions. */
    private static $php_extensions = array( 'php', 'phtml', 'phar', 'php5', 'php7', 'pht', 'phps', 'shtml', 'cgi' );

    /* ---------------------------------------------------------------
     * Family guess mapping.
     * ------------------------------------------------------------- */

    private static $family_map = array(
        // Individual signatures.
        'web_shell_keywords'      => 'webshell',
        'superglobal_exec'        => 'persistence_backdoor',
        'hidden_iframe'           => 'injector',
        'wp_unauthorized_admin'   => 'persistence_backdoor',
        'wp_option_injection'     => 'injector',
        'disable_security'        => 'persistence_backdoor',
        'gzinflate_obfusc'        => 'obfuscated_loader',
        'hidden_php_full_tag'     => 'cloaked_php',
        'hidden_php_short_echo'   => 'cloaked_php',
        'hidden_php_short_tag'    => 'cloaked_php',
        'dynamic_include'         => 'persistence_backdoor',
        'call_user_func'          => 'persistence_backdoor',
        'register_shutdown'       => 'persistence_backdoor',
        'ini_set_disable'         => 'persistence_backdoor',
        'array_map_exec'          => 'obfuscated_loader',
        // Compound rules.
        'eval_base64'             => 'obfuscated_loader',
        'gzinflate_base64'        => 'obfuscated_loader',
        'assert_superglobal'      => 'persistence_backdoor',
        'remote_fetch_exec'       => 'dropper',
        'remote_fetch_write'      => 'dropper',
        'upload_to_exec'          => 'dropper',
        'stealth_backdoor'        => 'persistence_backdoor',
        'ini_override_exec'       => 'persistence_backdoor',
        'error_suppress_obfusc'   => 'obfuscated_loader',
        'payload_reconstruct'     => 'obfuscated_loader',
        'chr_chain_exec'          => 'obfuscated_loader',
        'hex_assembly_exec'       => 'obfuscated_loader',
        'xor_exec'                => 'obfuscated_loader',
        'preg_replace_callback_exec' => 'obfuscated_loader',
        // Network / fetcher signatures.
        'wp_remote_get'           => 'remote_fetcher',
        'curl_setopt_url'         => 'remote_fetcher',
        'file_get_contents_url'   => 'remote_fetcher',
        'fsockopen'               => 'remote_fetcher',
        // Upload handling.
        'move_uploaded_file'      => 'unexpected_upload_executable',
        'upload_chmod'            => 'dropper',
    );

    /* ---------------------------------------------------------------
     * Family definitions — canonical families with metadata.
     * ------------------------------------------------------------- */

    /**
     * Family metadata: label, description, remediation hint,
     * and tag affinity scores used for weighted family election.
     *
     * @var array<string, array>
     */
    private static $family_definitions = array(
        'webshell' => array(
            'label'            => 'Web Shell',
            'description'      => 'Interactive malicious shell providing remote access to the server.',
            'remediation_hint' => 'Delete the file immediately. Check for additional backdoors and review server access logs.',
            'tag_affinity'     => array( 'backdoor' => 3, 'exec' => 2, 'system' => 2, 'userinput' => 2, 'dangerous' => 1 ),
        ),
        'obfuscated_loader' => array(
            'label'            => 'Obfuscated Loader',
            'description'      => 'Encoded/compressed payload designed to evade detection and execute hidden code.',
            'remediation_hint' => 'Delete the file. Decode payload offline for IOC extraction if needed.',
            'tag_affinity'     => array( 'obfuscation' => 3, 'exec' => 2, 'dangerous' => 1, 'compound' => 2, 'entropy' => 2 ),
        ),
        'dropper' => array(
            'label'            => 'Dropper',
            'description'      => 'Downloads or writes malicious files to disk. Often first stage of multi-phase attacks.',
            'remediation_hint' => 'Delete the file. Scan uploads and writable directories for dropped payloads.',
            'tag_affinity'     => array( 'network' => 3, 'write' => 3, 'exec' => 1, 'upload' => 2, 'dangerous' => 1 ),
        ),
        'remote_fetcher' => array(
            'label'            => 'Remote Fetcher',
            'description'      => 'Fetches remote content using user-controlled or hardcoded URLs; potential SSRF or payload download.',
            'remediation_hint' => 'Review the remote URLs. If user-controlled, patch or delete. Check for data exfiltration.',
            'tag_affinity'     => array( 'network' => 3, 'userinput' => 2, 'dangerous' => 1 ),
        ),
        'persistence_backdoor' => array(
            'label'            => 'Persistence Backdoor',
            'description'      => 'Backdoor designed to maintain access: admin creation, security bypass, or hidden exec.',
            'remediation_hint' => 'Delete the file. Audit admin users, reset passwords, and check for scheduled tasks.',
            'tag_affinity'     => array( 'backdoor' => 3, 'exec' => 2, 'userinput' => 2, 'wp_specific' => 2, 'dangerous' => 1 ),
        ),
        'cloaked_php' => array(
            'label'            => 'Cloaked PHP',
            'description'      => 'PHP code hidden inside a non-PHP file (image, text, etc.) to bypass extension restrictions.',
            'remediation_hint' => 'Delete the file. Check uploads directory for similar cloaked files.',
            'tag_affinity'     => array( 'hidden_php' => 4, 'dangerous' => 1, 'exec' => 1, 'obfuscation' => 1 ),
        ),
        'modified_core' => array(
            'label'            => 'Modified Core File',
            'description'      => 'A WordPress core file has been modified from its original state.',
            'remediation_hint' => 'Reinstall WordPress core files via wp-cli or dashboard. Compare with original using checksums.',
            'tag_affinity'     => array( 'dangerous' => 1 ),
        ),
        'unexpected_upload_executable' => array(
            'label'            => 'Unexpected Upload Executable',
            'description'      => 'Executable PHP file found in the uploads directory where only media should exist.',
            'remediation_hint' => 'Delete the file. Add server-level protection to block PHP execution in uploads.',
            'tag_affinity'     => array( 'upload' => 2, 'exec' => 1, 'dangerous' => 1 ),
        ),
        'injector' => array(
            'label'            => 'Code Injector',
            'description'      => 'Injects malicious content (iframes, scripts, options) into pages or database.',
            'remediation_hint' => 'Delete the file. Scan database for injected content (siteurl, home, blogname).',
            'tag_affinity'     => array( 'injection' => 3, 'wp_specific' => 2, 'write' => 1 ),
        ),
        'unknown_suspicious' => array(
            'label'            => 'Unknown Suspicious',
            'description'      => 'File has suspicious characteristics but does not match a known malware family.',
            'remediation_hint' => 'Review the file manually. Check signals and context for assessment.',
            'tag_affinity'     => array(),
        ),
        'mixed_signals' => array(
            'label'            => 'Mixed Signals',
            'description'      => 'File matches multiple families with no clear winner. May be polymorphic or multi-purpose.',
            'remediation_hint' => 'Review manually. Consider quarantining and analysing offline.',
            'tag_affinity'     => array(),
        ),
    );

    /* ---------------------------------------------------------------
     * Public API
     * ------------------------------------------------------------- */

    /**
     * Classify a file based on its heuristic signals, path context,
     * and optional integrity data.
     *
     * @param array  $signals        Signals from AIPSC_File_Heuristics::analyse().
     * @param string $path           Relative file path.
     * @param array  $integrity_info Optional baseline/integrity data: {
     *     @type string $status        'unchanged'|'modified'|'new'|'missing'|'unknown'
     *     @type string $sha256_was    Previous hash (if modified).
     * }
     * @param string $sha256         Current file hash (for allowlist check).
     * @return array Enriched classification result.
     */
    public static function classify( array $signals, $path = '', array $integrity_info = array(), $sha256 = '' ) {

        // ── A) Content layer ────────────────────────────────────
        $content = self::score_content( $signals );

        // ── B) Context layer ────────────────────────────────────
        $context = self::score_context( $path, $signals );

        // ── C) Integrity layer ──────────────────────────────────
        $integrity = self::score_integrity( $integrity_info, $path, $signals );

        // ── D) Risk reduction ───────────────────────────────────
        $reduction = self::compute_reduction( $path, $sha256, $signals, $integrity_info );

        // ── Composite score ─────────────────────────────────────
        // Weighted sum of layers, then apply reduction multiplier.
        $raw = ( $content['score'] * self::W_CONTENT )
             + ( $context['score'] * self::W_CONTEXT )
             + ( $integrity['score'] * self::W_INTEGRITY );

        $adjusted = $raw * $reduction['multiplier'];

        $score = (int) round( max( 0, min( 100, $adjusted ) ) );

        // ── Build output ────────────────────────────────────────
        $reasons       = array_merge( $content['reasons'], $context['reasons'], $integrity['reasons'], $reduction['reasons'] );
        $matched_rules = array_map( function ( $s ) { return $s['sig_id']; }, $signals );
        $context_flags = $context['flags'];
        $integrity_flags = $integrity['flags'];

        // Top signal.
        $top_signal = '';
        $max_w      = 0;
        foreach ( $signals as $s ) {
            if ( $s['weight'] > $max_w ) {
                $max_w      = $s['weight'];
                $top_signal = $s['label'];
            }
        }

        // Family classification — structured.
        $family_result = self::classify_family( $signals, $context_flags, $integrity_flags, $score );

        return array(
            'risk_score'        => $score,
            'risk_level'        => self::label( $score ),
            'classification'    => self::label( $score ), // backward compat
            'family'            => $family_result['family'],
            'family_label'      => $family_result['label'],
            'family_confidence' => $family_result['confidence'],
            'remediation_hint'  => $family_result['remediation_hint'],
            'family_guess'      => $family_result['family'], // backward compat
            'top_signal'        => $top_signal,
            'signal_count'      => count( $signals ),
            'reasons'           => $reasons,
            'matched_rules'     => $matched_rules,
            'context_flags'     => $context_flags,
            'integrity_flags'   => $integrity_flags,
            'layer_scores'      => array(
                'content'   => $content['score'],
                'context'   => $context['score'],
                'integrity' => $integrity['score'],
                'reduction' => $reduction['multiplier'],
            ),
        );
    }

    /**
     * Map score to classification label.
     *
     * @param int $score 0–100.
     * @return string
     */
    public static function label( $score ) {
        if ( $score >= 75 ) {
            return self::CLASS_MALICIOUS;
        }
        if ( $score >= 45 ) {
            return self::CLASS_RISKY;
        }
        if ( $score >= 15 ) {
            return self::CLASS_SUSPICIOUS;
        }
        return self::CLASS_CLEAN;
    }

    /* ---------------------------------------------------------------
     * Family Classification Engine
     * ------------------------------------------------------------- */

    /**
     * Determine the malware family, confidence level, and remediation hint
     * based on signal families, context flags, integrity flags, and tag
     * affinity scoring.
     *
     * @param array  $signals         Heuristic signals.
     * @param array  $context_flags   Flags from score_context().
     * @param array  $integrity_flags Flags from score_integrity().
     * @param int    $risk_score      Final composite risk score.
     * @return array {family, label, confidence, remediation_hint}
     */
    private static function classify_family( array $signals, array $context_flags, array $integrity_flags, $risk_score ) {

        $fallback = array(
            'family'           => '',
            'label'            => '',
            'confidence'       => 'none',
            'remediation_hint' => '',
        );

        // Nothing to classify for clean files.
        if ( $risk_score < 15 && empty( $signals ) ) {
            return $fallback;
        }

        // ── 1. Context / integrity override families ────────────
        // These flags already carry strong family semantics.
        $override_family = '';

        // Core tampering — highest priority overrides.
        if ( in_array( 'core_file_modified', $integrity_flags, true )
            || in_array( 'core_tampered_with_signals', $integrity_flags, true ) ) {
            $override_family = 'modified_core';
        }
        if ( in_array( 'unexpected_core_file', $integrity_flags, true )
            || in_array( 'unexpected_core_file_with_signals', $integrity_flags, true ) ) {
            // Unexpected file in core path — not an official core file.
            // If it has signals it's more likely a webshell or backdoor injected there.
            $has_exec_tags = false;
            foreach ( $signals as $s ) {
                $tags = isset( $s['tags'] ) ? $s['tags'] : array();
                if ( in_array( 'exec', $tags, true ) || in_array( 'backdoor', $tags, true ) ) {
                    $has_exec_tags = true;
                    break;
                }
            }
            if ( '' === $override_family ) {
                $override_family = $has_exec_tags ? 'webshell' : 'modified_core';
            }
        }

        // Baseline-only core modifications (when official checksums unavailable).
        if ( '' === $override_family
            && ( in_array( 'modified_core_file', $integrity_flags, true )
                || in_array( 'modified_sensitive_file', $integrity_flags, true ) ) ) {
            $override_family = 'modified_core';
        }

        if ( in_array( 'unexpected_upload_executable', $context_flags, true ) && '' === $override_family ) {
            $override_family = 'unexpected_upload_executable';
        }
        if ( in_array( 'cloaked_php_in_non_php_file', $context_flags, true ) && '' === $override_family ) {
            $override_family = 'cloaked_php';
        }

        // ── 2. Count family votes from signal sig_ids ───────────
        $family_votes = array(); // family => weighted count
        $tag_pool     = array(); // tag   => total weight

        foreach ( $signals as $s ) {
            $sid = $s['sig_id'];
            $w   = max( 1, (int) $s['weight'] );

            // Accumulate family votes.
            if ( isset( self::$family_map[ $sid ] ) ) {
                $fam = self::$family_map[ $sid ];
                if ( ! isset( $family_votes[ $fam ] ) ) {
                    $family_votes[ $fam ] = 0;
                }
                $family_votes[ $fam ] += $w;
            }

            // Accumulate tags for affinity scoring.
            if ( ! empty( $s['tags'] ) && is_array( $s['tags'] ) ) {
                foreach ( $s['tags'] as $tag ) {
                    if ( ! isset( $tag_pool[ $tag ] ) ) {
                        $tag_pool[ $tag ] = 0;
                    }
                    $tag_pool[ $tag ] += $w;
                }
            }
        }

        // ── 3. Tag-affinity scoring ─────────────────────────────
        // For each family definition, compute an affinity score by
        // cross-referencing the tag pool with the family's affinities.
        $affinity_scores = array();
        foreach ( self::$family_definitions as $fam_key => $def ) {
            if ( 'unknown_suspicious' === $fam_key || 'mixed_signals' === $fam_key ) {
                continue;
            }
            $aff = 0;
            foreach ( $def['tag_affinity'] as $tag => $multiplier ) {
                if ( isset( $tag_pool[ $tag ] ) ) {
                    $aff += $tag_pool[ $tag ] * $multiplier;
                }
            }
            if ( $aff > 0 ) {
                $affinity_scores[ $fam_key ] = $aff;
            }
        }

        // ── 4. Merge votes + affinity into final scores ─────────
        $final_scores = array();
        $all_families = array_unique( array_merge( array_keys( $family_votes ), array_keys( $affinity_scores ) ) );

        foreach ( $all_families as $fam ) {
            $vote = isset( $family_votes[ $fam ] ) ? $family_votes[ $fam ] : 0;
            $aff  = isset( $affinity_scores[ $fam ] ) ? $affinity_scores[ $fam ] : 0;
            // Vote weight is 60%, affinity is 40%.
            $final_scores[ $fam ] = ( $vote * 0.6 ) + ( $aff * 0.4 );
        }

        // Apply context override boost.
        if ( '' !== $override_family ) {
            if ( ! isset( $final_scores[ $override_family ] ) ) {
                $final_scores[ $override_family ] = 0;
            }
            $final_scores[ $override_family ] += 100;
        }

        // ── 5. Elect winner ─────────────────────────────────────
        if ( empty( $final_scores ) ) {
            // No family signals at all — unknown_suspicious if score warrants.
            if ( $risk_score >= 15 ) {
                $def = self::$family_definitions['unknown_suspicious'];
                return array(
                    'family'           => 'unknown_suspicious',
                    'label'            => $def['label'],
                    'confidence'       => 'low',
                    'remediation_hint' => $def['remediation_hint'],
                );
            }
            return $fallback;
        }

        arsort( $final_scores );
        $ranked  = array_keys( $final_scores );
        $winner  = $ranked[0];
        $top_val = $final_scores[ $winner ];

        // ── 6. Confidence calculation ───────────────────────────
        $confidence = 'low';
        if ( count( $ranked ) >= 2 ) {
            $second_val = $final_scores[ $ranked[1] ];
            $gap        = ( $second_val > 0 ) ? ( $top_val / $second_val ) : PHP_INT_MAX;

            if ( $gap >= 3.0 ) {
                $confidence = 'high';
            } elseif ( $gap >= 1.5 ) {
                $confidence = 'medium';
            } else {
                // Close contest — mixed signals.
                $winner     = 'mixed_signals';
                $confidence = 'low';
            }
        } else {
            // Single family — confidence depends on vote strength.
            $confidence = ( $top_val >= 10 ) ? 'high' : ( ( $top_val >= 4 ) ? 'medium' : 'low' );
        }

        // Override bumps confidence.
        if ( '' !== $override_family && $winner === $override_family ) {
            $confidence = 'high';
        }

        // ── 7. Build result ─────────────────────────────────────
        $def = isset( self::$family_definitions[ $winner ] )
            ? self::$family_definitions[ $winner ]
            : self::$family_definitions['unknown_suspicious'];

        return array(
            'family'           => $winner,
            'label'            => $def['label'],
            'confidence'       => $confidence,
            'remediation_hint' => $def['remediation_hint'],
        );
    }

    /* ---------------------------------------------------------------
     * Layer A — Content Scoring
     * ------------------------------------------------------------- */

    /**
     * Score based purely on signal weights and combinations.
     *
     * @param array $signals Heuristic signals.
     * @return array{ score: int, reasons: string[] }
     */
    private static function score_content( array $signals ) {
        if ( empty( $signals ) ) {
            return array( 'score' => 0, 'reasons' => array() );
        }

        $total_weight = 0;
        $reasons      = array();

        // Collect all unique tags across signals.
        $all_tags = array();
        $tag_counts = array(
            'exec'        => 0,
            'obfuscation' => 0,
            'network'     => 0,
            'write'       => 0,
            'backdoor'    => 0,
            'userinput'   => 0,
            'dangerous'   => 0,
            'compound'    => 0,
            'upload'      => 0,
            'hidden_php'  => 0,
        );

        foreach ( $signals as $signal ) {
            $total_weight += (int) $signal['weight'];
            $tags = isset( $signal['tags'] ) ? $signal['tags'] : array();
            foreach ( $tags as $t ) {
                $all_tags[ $t ] = true;
                if ( isset( $tag_counts[ $t ] ) ) {
                    $tag_counts[ $t ]++;
                }
            }
        }

        // Base score: logarithmic scaling.
        $k     = 25;
        $score = 100 * ( $total_weight / ( $total_weight + $k ) );

        // Obfuscation intensity bonus: multiple obfuscation signals compound.
        if ( $tag_counts['obfuscation'] >= 3 ) {
            $score += 12;
            $reasons[] = 'Heavy obfuscation (' . $tag_counts['obfuscation'] . ' indicators)';
        } elseif ( $tag_counts['obfuscation'] >= 2 ) {
            $score += 6;
            $reasons[] = 'Multiple obfuscation indicators';
        }

        // Dangerous signal count escalation.
        if ( $tag_counts['dangerous'] >= 3 ) {
            $score += 15;
            $reasons[] = 'Multiple dangerous patterns (' . $tag_counts['dangerous'] . ')';
        }

        // Combo bonuses.
        foreach ( self::$dangerous_combos as $combo ) {
            $match = true;
            foreach ( $combo['tags'] as $required_tag ) {
                if ( ! isset( $all_tags[ $required_tag ] ) ) {
                    $match = false;
                    break;
                }
            }
            if ( $match ) {
                $score    += $combo['bonus'];
                $reasons[] = $combo['reason'];
            }
        }

        // Compound rule multiplier: compound signals carry higher confidence.
        if ( $tag_counts['compound'] >= 3 ) {
            $score += 18;
            $reasons[] = 'Multiple compound correlation rules (' . $tag_counts['compound'] . ')';
        } elseif ( $tag_counts['compound'] >= 2 ) {
            $score += 10;
            $reasons[] = 'Two compound correlation rules matched';
        }

        // Signal count factor: many different signals are suspicious.
        $sig_count = count( $signals );
        if ( $sig_count >= 10 ) {
            $score    += 18;
            $reasons[] = 'Very high signal density (' . $sig_count . ' unique matches)';
        } elseif ( $sig_count >= 6 ) {
            $score    += 10;
            $reasons[] = 'High signal density (' . $sig_count . ' unique matches)';
        } elseif ( $sig_count >= 4 ) {
            $score += 5;
        }

        return array(
            'score'   => (int) round( min( 100, max( 0, $score ) ) ),
            'reasons' => $reasons,
        );
    }

    /* ---------------------------------------------------------------
     * Layer B — Context Scoring
     * ------------------------------------------------------------- */

    /**
     * Score based on file path, name, and extension context.
     *
     * @param string $path    Relative file path.
     * @param array  $signals Signals (used to boost in certain locations).
     * @return array{ score: int, reasons: string[], flags: string[] }
     */
    private static function score_context( $path, array $signals ) {
        $score   = 0;
        $reasons = array();
        $flags   = array();

        if ( '' === $path ) {
            return array( 'score' => 0, 'reasons' => array(), 'flags' => array() );
        }

        $basename  = basename( $path );
        $extension = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );

        $in_uploads = self::is_in_uploads( $path );
        $is_php_ext = in_array( $extension, self::$php_extensions, true );

        // ── Uploads-specific scoring ──
        if ( $in_uploads ) {
            // Check if signals contain hidden_php tags (non-PHP file with PHP inside).
            $has_hidden_php = false;
            foreach ( $signals as $s ) {
                if ( in_array( 'hidden_php', isset( $s['tags'] ) ? $s['tags'] : array(), true ) ) {
                    $has_hidden_php = true;
                    break;
                }
            }

            if ( $is_php_ext ) {
                $score    += 50;
                $flags[]   = 'unexpected_upload_executable';
                $reasons[] = 'Executable PHP file in uploads directory';
            } elseif ( $has_hidden_php ) {
                $score    += 55;
                $flags[]   = 'cloaked_php_in_non_php_file';
                $reasons[] = 'Hidden PHP code detected in non-PHP file in uploads';
            }

            // Double extension in uploads.
            if ( preg_match( '/\.\w+\.\w+$/', $basename ) ) {
                if ( $is_php_ext ) {
                    $score    += 30;
                    $flags[]   = 'suspicious_double_extension_upload';
                    $reasons[] = 'Double extension ending in PHP in uploads: ' . $basename;
                } elseif ( preg_match( '/\.(?:php\w*|phtml|phar|pht|shtml)\./i', $basename ) ) {
                    $score    += 25;
                    $flags[]   = 'suspicious_double_extension_upload';
                    $reasons[] = 'Double extension with PHP as inner extension in uploads: ' . $basename;
                }
            }

            // Random/gibberish filename in uploads.
            if ( self::is_random_filename( $basename ) ) {
                $score    += 20;
                $flags[]   = 'random_filename_uploads';
                $reasons[] = 'Random/gibberish filename in uploads: ' . $basename;
            }

            // Suspicious filename patterns in uploads get extra boost.
            foreach ( self::$suspicious_names as $pattern ) {
                if ( preg_match( $pattern, $basename ) ) {
                    $score    += 30;
                    $flags[]   = 'suspicious_filename';
                    $reasons[] = 'Suspicious filename pattern in uploads: ' . $basename;
                    break;
                }
            }
        }

        // ── Path location (non-uploads) ──
        if ( ! $in_uploads ) {
            if ( preg_match( '#^wp-(includes|admin)/#', $path ) && ! empty( $signals ) ) {
                $score    += 20;
                $flags[]   = 'suspicious_in_core';
                $reasons[] = 'Suspicious signals in WordPress core path';
            }

            // Root-level PHP files that aren't standard WP files.
            if ( ! preg_match( '#/#', $path ) && ! self::is_known_root_file( $basename ) ) {
                $score    += 15;
                $flags[]   = 'unknown_root_file';
                $reasons[] = 'Unknown PHP file in site root';
            }

            // ── Suspicious filename (non-uploads) ──
            foreach ( self::$suspicious_names as $pattern ) {
                if ( preg_match( $pattern, $basename ) ) {
                    $score    += 25;
                    $flags[]   = 'suspicious_filename';
                    $reasons[] = 'Suspicious filename pattern: ' . $basename;
                    break;
                }
            }

            // ── Double extensions (non-uploads) ──
            if ( preg_match( '/\.\w+\.\w+$/', $basename ) && $is_php_ext ) {
                $score    += 20;
                $flags[]   = 'double_extension';
                $reasons[] = 'Double extension detected: ' . $basename;
            }
        }

        // ── Rare PHP extension (applies everywhere) ──
        if ( in_array( $extension, self::$rare_extensions, true ) ) {
            $score    += 15;
            $flags[]   = 'rare_extension';
            $reasons[] = 'Unusual PHP extension: .' . $extension;
        }

        // ── Dot-prefixed hidden file ──
        if ( 0 === strpos( $basename, '.' ) && $is_php_ext ) {
            $score    += 20;
            $flags[]   = 'hidden_file';
            $reasons[] = 'Hidden PHP file (dot-prefix)';
        }

        // ── Unexpected location: file in unusual wp-content subdirectory ──
        if ( preg_match( '#wp-content/(?!plugins|themes|mu-plugins|uploads)#', $path ) && ! empty( $signals ) ) {
            $score    += 10;
            $flags[]   = 'unexpected_wp_content';
            $reasons[] = 'Signals in unexpected wp-content subdirectory';
        }

        return array(
            'score'   => (int) round( min( 100, max( 0, $score ) ) ),
            'reasons' => $reasons,
            'flags'   => $flags,
        );
    }

    /* ---------------------------------------------------------------
     * Layer C — Integrity Scoring
     * ------------------------------------------------------------- */

    /**
     * Score based on baseline integrity data, cross-referenced with
     * path context and signal presence.
     *
     * @param array  $info    Integrity info: status, origin_type, first/last_seen, etc.
     * @param string $path    Relative file path (for context-aware scoring).
     * @param array  $signals Heuristic signals (to boost new/modified + signals).
     * @return array{ score: int, reasons: string[], flags: string[] }
     */
    private static function score_integrity( array $info, $path = '', array $signals = array() ) {
        $score   = 0;
        $reasons = array();
        $flags   = array();

        $status      = isset( $info['status'] ) ? $info['status'] : 'unknown';
        $origin_type = isset( $info['origin_type'] ) ? $info['origin_type'] : '';
        $has_signals = ! empty( $signals );
        $in_uploads  = self::is_in_uploads( $path );
        $in_core     = preg_match( '#^wp-(includes|admin)/#', $path );
        $in_root     = ( '' !== $path && false === strpos( $path, '/' ) );

        // ── Official core checksum results (highest authority) ──
        $core_tampered      = ! empty( $info['core_tampered'] );
        $unexpected_in_core = ! empty( $info['unexpected_in_core'] );
        $core_checksum      = isset( $info['core_checksum'] ) ? $info['core_checksum'] : '';

        if ( $core_tampered ) {
            // Verified against api.wordpress.org — definitive tampering.
            $score    += 80;
            $flags[]   = 'core_file_modified';
            $reasons[] = 'Core file modified — checksum mismatch against official WordPress release';

            if ( $has_signals ) {
                $score    += 20;
                $flags[]   = 'core_tampered_with_signals';
                $reasons[] = 'Tampered core file also contains suspicious patterns';
            }

            // Already at/near max. Skip the regular status-based scoring
            // to avoid double-counting.
            return array(
                'score'   => (int) round( min( 100, max( 0, $score ) ) ),
                'reasons' => $reasons,
                'flags'   => $flags,
            );
        }

        if ( $unexpected_in_core ) {
            // File exists in wp-admin/ or wp-includes/ but is NOT in
            // the official core manifest — injected file.
            $score    += 60;
            $flags[]   = 'unexpected_core_file';
            $reasons[] = 'File not part of official WordPress distribution found in core directory';

            if ( $has_signals ) {
                $score    += 25;
                $flags[]   = 'unexpected_core_file_with_signals';
                $reasons[] = 'Unexpected core file also has suspicious code patterns';
            }

            return array(
                'score'   => (int) round( min( 100, max( 0, $score ) ) ),
                'reasons' => $reasons,
                'flags'   => $flags,
            );
        }

        switch ( $status ) {
            case 'new':
                // Base score for new file.
                $score     = 35;
                $flags[]   = 'baseline_new';
                $reasons[] = 'File not present in baseline (new file)';

                // ── Finding: new + uploads ──
                if ( $in_uploads ) {
                    $score    += 25;
                    $flags[]   = 'new_file_in_uploads';
                    $reasons[] = 'New file appeared inside uploads directory';
                }

                // ── Finding: new + dangerous signals ──
                if ( $has_signals ) {
                    $dangerous_count = 0;
                    foreach ( $signals as $s ) {
                        if ( in_array( 'dangerous', isset( $s['tags'] ) ? $s['tags'] : array(), true ) ) {
                            $dangerous_count++;
                        }
                    }
                    if ( $dangerous_count > 0 ) {
                        $bonus     = min( 30, $dangerous_count * 10 );
                        $score    += $bonus;
                        $flags[]   = 'new_suspicious_file';
                        $reasons[] = sprintf( 'New file with %d dangerous signal(s)', $dangerous_count );
                    }
                }

                // ── Finding: new in core path ──
                if ( $in_core ) {
                    $score    += 20;
                    $flags[]   = 'unexpected_core_adjacent_file';
                    $reasons[] = 'New file in WordPress core directory';
                }

                // ── Finding: new in site root with signals ──
                if ( $in_root && $has_signals ) {
                    $score    += 15;
                    $flags[]   = 'new_root_suspicious';
                    $reasons[] = 'New file in site root with signals';
                }
                break;

            case 'modified':
                // Base score for modified file.
                $score     = 40;
                $flags[]   = 'baseline_modified';
                $reasons[] = 'File modified since baseline was built';

                // ── Finding: modified in sensitive path ──
                if ( $in_core || 'core' === $origin_type ) {
                    $score    += 25;
                    $flags[]   = 'modified_sensitive_file';
                    $reasons[] = 'Core file modified — possible compromise';
                }

                // ── Finding: modified + dangerous signals ──
                if ( $has_signals ) {
                    $dangerous_count = 0;
                    foreach ( $signals as $s ) {
                        if ( in_array( 'dangerous', isset( $s['tags'] ) ? $s['tags'] : array(), true ) ) {
                            $dangerous_count++;
                        }
                    }
                    if ( $dangerous_count > 0 ) {
                        $bonus     = min( 25, $dangerous_count * 8 );
                        $score    += $bonus;
                        $flags[]   = 'modified_with_dangerous_signals';
                        $reasons[] = sprintf( 'Modified file now has %d dangerous signal(s)', $dangerous_count );
                    }
                }

                // ── Finding: modified in uploads ──
                if ( $in_uploads ) {
                    $score    += 15;
                    $flags[]   = 'modified_upload_file';
                    $reasons[] = 'File in uploads modified since baseline';
                }

                // ── Finding: modified plugin/theme ──
                if ( in_array( $origin_type, array( 'plugin', 'theme' ), true ) && $has_signals ) {
                    $score    += 10;
                    $flags[]   = 'modified_component_file';
                    $reasons[] = 'Plugin/theme file modified with suspicious signals';
                }
                break;

            case 'missing':
                $score     = 20;
                $flags[]   = 'baseline_missing';
                $reasons[] = 'File was in baseline but no longer exists';
                break;

            case 'unchanged':
                $score     = 0;
                $flags[]   = 'baseline_intact';
                break;

            default: // 'unknown' — no baseline available.
                $score     = 10;
                $flags[]   = 'no_baseline';
                $reasons[] = 'No baseline data available for comparison';

                // Even without baseline, new-looking files in risky places get a bump.
                if ( $in_uploads && $has_signals ) {
                    $score    += 10;
                    $flags[]   = 'no_baseline_uploads_signals';
                    $reasons[] = 'No baseline + signals in uploads directory';
                }
                break;
        }

        return array(
            'score'   => (int) min( 100, max( 0, $score ) ),
            'reasons' => $reasons,
            'flags'   => $flags,
        );
    }

    /* ---------------------------------------------------------------
     * Layer D — Risk Reduction
     * ------------------------------------------------------------- */

    /**
     * Compute a reduction multiplier (0.0–1.0) and reasons.
     *
     * @param string $path           Relative file path.
     * @param string $sha256         Current file hash.
     * @param array  $signals        Signals.
     * @param array  $integrity_info Integrity data from baseline.
     * @return array{ multiplier: float, reasons: string[] }
     */
    private static function compute_reduction( $path, $sha256, array $signals, array $integrity_info = array() ) {
        $multiplier = 1.0;
        $reasons    = array();

        // Files in uploads with signals should not get vendor/benign reductions.
        $in_uploads       = self::is_in_uploads( $path );
        $integrity_status = isset( $integrity_info['status'] ) ? $integrity_info['status'] : 'unknown';

        // ── Baseline-intact reduction ──
        // Files confirmed unchanged since baseline are far less suspicious.
        if ( 'unchanged' === $integrity_status && ! $in_uploads ) {
            $multiplier *= 0.55;
            $reasons[]   = 'File unchanged since baseline (integrity confirmed)';
        }

        // ── Known vendor path (skip in uploads) ──
        if ( ! $in_uploads ) {
            foreach ( self::$vendor_indicators as $pattern ) {
                if ( preg_match( $pattern, $path ) ) {
                    $multiplier *= 0.35;
                    $reasons[]   = 'File in known vendor/dev path';
                    break;
                }
            }
        }

        // ── Generic benign path (tests, fixtures, CI — skip in uploads) ──
        if ( ! $in_uploads ) {
            foreach ( self::$benign_paths as $pattern ) {
                if ( preg_match( $pattern, $path ) ) {
                    $multiplier *= 0.50;
                    $reasons[]   = 'File in test/fixture/CI directory';
                    break;
                }
            }
        }

        // ── Hash allowlist ──
        $allowlist = self::get_hash_allowlist();
        if ( '' !== $sha256 && isset( $allowlist[ $sha256 ] ) ) {
            $multiplier *= 0.10;
            $reasons[]   = 'SHA-256 matches known-good allowlist (' . $allowlist[ $sha256 ] . ')';
        }

        // ── Low signal count with only benign-ish patterns ──
        // If we only have 1 signal and it's a common benign hit (e.g. base64_decode
        // alone, or file_write alone), reduce.
        if ( count( $signals ) === 1 ) {
            $benign_singles = array( 'base64_decode', 'file_write', 'curl_exec', 'file_get_contents_url', 'str_rot13' );
            if ( in_array( $signals[0]['sig_id'], $benign_singles, true ) ) {
                $multiplier *= 0.60;
                $reasons[]   = 'Single low-risk signal (common in legitimate code)';
            }
        }

        return array(
            'multiplier' => round( max( 0.05, min( 1.0, $multiplier ) ), 3 ),
            'reasons'    => $reasons,
        );
    }

    /* ---------------------------------------------------------------
     * Helpers
     * ------------------------------------------------------------- */

    /**
     * Filter to allow extending the SHA-256 hash allowlist.
     *
     * @return array<string, string> sha256 => label.
     */
    private static function get_hash_allowlist() {
        /**
         * Filters the hash allowlist for the file classifier.
         *
         * @param array<string, string> $allowlist sha256 => description.
         */
        return apply_filters( 'aipatch_file_classifier_hash_allowlist', array() );
    }

    /**
     * Check if a root-level file is a known WordPress file.
     *
     * @param string $basename File basename.
     * @return bool
     */
    private static function is_known_root_file( $basename ) {
        $known = array(
            'index.php',
            'wp-config.php',
            'wp-config-sample.php',
            'wp-settings.php',
            'wp-load.php',
            'wp-blog-header.php',
            'wp-cron.php',
            'wp-login.php',
            'wp-signup.php',
            'wp-activate.php',
            'wp-comments-post.php',
            'wp-links-opml.php',
            'wp-mail.php',
            'wp-trackback.php',
            'xmlrpc.php',
            'wp-config-local.php',
        );
        return in_array( $basename, $known, true );
    }

    /**
     * Check if a path is inside the uploads directory.
     *
     * @param string $path Relative file path.
     * @return bool
     */
    private static function is_in_uploads( $path ) {
        return ( false !== strpos( $path, '/uploads/' ) || 0 === strpos( $path, 'uploads/' ) );
    }

    /**
     * Detect random/gibberish filenames commonly used by malware droppers.
     *
     * @param string $basename File basename.
     * @return bool
     */
    private static function is_random_filename( $basename ) {
        $name = pathinfo( $basename, PATHINFO_FILENAME );
        $len  = strlen( $name );

        // Single-character names (except common ones).
        if ( 1 === $len ) {
            return true;
        }

        // Pure hex string >= 8 chars.
        if ( $len >= 8 && preg_match( '/^[a-f0-9]+$/i', $name ) ) {
            return true;
        }

        // Long alphanumeric with very low vowel ratio (consonant soup).
        if ( $len >= 8 && preg_match( '/^[a-z0-9]+$/i', $name ) ) {
            $vowels = preg_match_all( '/[aeiou]/i', $name );
            if ( $len > 0 && ( $vowels / $len ) < 0.15 ) {
                return true;
            }
        }

        // Typical dropper temp-style names.
        if ( $len > 10 && preg_match( '/^(?:tmp|temp|cache|sess)[_\-]?[a-z0-9]+$/i', $name ) ) {
            return true;
        }

        return false;
    }
}
