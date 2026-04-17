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
        'superglobal_exec'        => 'backdoor',
        'hidden_iframe'           => 'injector',
        'wp_unauthorized_admin'   => 'backdoor',
        'wp_option_injection'     => 'injector',
        'disable_security'        => 'backdoor',
        'gzinflate_obfusc'        => 'obfuscated-payload',
        'hidden_php_full_tag'     => 'cloaked-php',
        'hidden_php_short_echo'   => 'cloaked-php',
        'hidden_php_short_tag'    => 'cloaked-php',
        'dynamic_include'         => 'backdoor',
        'call_user_func'          => 'backdoor',
        'register_shutdown'       => 'backdoor',
        'ini_set_disable'         => 'backdoor',
        'array_map_exec'          => 'obfuscated-payload',
        // Compound rules.
        'eval_base64'             => 'obfuscated-payload',
        'gzinflate_base64'        => 'obfuscated-payload',
        'assert_superglobal'      => 'backdoor',
        'remote_fetch_exec'       => 'dropper',
        'remote_fetch_write'      => 'dropper',
        'upload_to_exec'          => 'dropper',
        'stealth_backdoor'        => 'backdoor',
        'ini_override_exec'       => 'backdoor',
        'error_suppress_obfusc'   => 'obfuscated-payload',
        'payload_reconstruct'     => 'obfuscated-payload',
        'chr_chain_exec'          => 'obfuscated-payload',
        'hex_assembly_exec'       => 'obfuscated-payload',
        'xor_exec'                => 'obfuscated-payload',
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
        $integrity = self::score_integrity( $integrity_info );

        // ── D) Risk reduction ───────────────────────────────────
        $reduction = self::compute_reduction( $path, $sha256, $signals );

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

        // Top signal and family guess.
        $top_signal   = '';
        $family_guess = '';
        $max_w        = 0;
        foreach ( $signals as $s ) {
            if ( $s['weight'] > $max_w ) {
                $max_w      = $s['weight'];
                $top_signal = $s['label'];
                if ( isset( self::$family_map[ $s['sig_id'] ] ) ) {
                    $family_guess = self::$family_map[ $s['sig_id'] ];
                }
            }
        }
        // If no specific family from top signal, try any matched family.
        if ( '' === $family_guess && ! empty( $signals ) ) {
            foreach ( $signals as $s ) {
                if ( isset( self::$family_map[ $s['sig_id'] ] ) ) {
                    $family_guess = self::$family_map[ $s['sig_id'] ];
                    break;
                }
            }
        }

        return array(
            'risk_score'      => $score,
            'risk_level'      => self::label( $score ),
            'classification'  => self::label( $score ), // backward compat
            'family_guess'    => $family_guess,
            'top_signal'      => $top_signal,
            'signal_count'    => count( $signals ),
            'reasons'         => $reasons,
            'matched_rules'   => $matched_rules,
            'context_flags'   => $context_flags,
            'integrity_flags' => $integrity_flags,
            'layer_scores'    => array(
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
     * Score based on baseline integrity data.
     *
     * @param array $info Integrity info: status, sha256_was, etc.
     * @return array{ score: int, reasons: string[], flags: string[] }
     */
    private static function score_integrity( array $info ) {
        $score   = 0;
        $reasons = array();
        $flags   = array();

        $status = isset( $info['status'] ) ? $info['status'] : 'unknown';

        switch ( $status ) {
            case 'new':
                $score     = 40;
                $flags[]   = 'baseline_new';
                $reasons[] = 'File not present in baseline (new file)';
                break;

            case 'modified':
                $score     = 55;
                $flags[]   = 'baseline_modified';
                $reasons[] = 'File modified since baseline was built';
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
                break;
        }

        return array(
            'score'   => $score,
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
     * @param string $path    Relative file path.
     * @param string $sha256  Current file hash.
     * @param array  $signals Signals.
     * @return array{ multiplier: float, reasons: string[] }
     */
    private static function compute_reduction( $path, $sha256, array $signals ) {
        $multiplier = 1.0;
        $reasons    = array();

        // Files in uploads with signals should not get vendor/benign reductions.
        $in_uploads = self::is_in_uploads( $path );

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
