<?php
/**
 * File Heuristics Engine.
 *
 * Stateless pattern-matching engine that scans PHP file contents for
 * suspicious constructs, obfuscation, known malware signatures, and
 * risky function usage. Returns an array of signal objects.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_File_Heuristics
 */
class AIPSC_File_Heuristics {

    /**
     * Dangerous function patterns and their weights.
     *
     * Each signature includes a 'tags' array for semantic categorization
     * used by the classifier to detect dangerous combinations.
     *
     * @var array<string, array{pattern: string, weight: int, label: string, description: string, tags: string[]}>
     */
    private static $signatures = array();

    /**
     * Initialise signatures (lazy).
     */
    private static function init_signatures() {
        if ( ! empty( self::$signatures ) ) {
            return;
        }

        self::$signatures = array(
            // Code execution / injection.
            'eval_usage' => array(
                'pattern'     => '/\beval\s*\(/i',
                'weight'      => 8,
                'label'       => 'eval() usage',
                'description' => 'Dynamic code execution via eval().',
                'tags'        => array( 'exec', 'dangerous' ),
            ),
            'assert_usage' => array(
                'pattern'     => '/\bassert\s*\(/i',
                'weight'      => 7,
                'label'       => 'assert() as code exec',
                'description' => 'assert() can execute arbitrary code.',
                'tags'        => array( 'exec', 'dangerous' ),
            ),
            'create_function' => array(
                'pattern'     => '/\bcreate_function\s*\(/i',
                'weight'      => 7,
                'label'       => 'create_function()',
                'description' => 'Deprecated function that evaluates code strings.',
                'tags'        => array( 'exec', 'dangerous' ),
            ),
            'preg_replace_e' => array(
                'pattern'     => '/preg_replace\s*\(\s*[\'"][^"\']*\/e[\'"]/',
                'weight'      => 8,
                'label'       => 'preg_replace /e modifier',
                'description' => 'Deprecated /e modifier evaluates replacement as PHP.',
                'tags'        => array( 'exec', 'dangerous' ),
            ),

            // System commands.
            'shell_exec' => array(
                'pattern'     => '/\b(shell_exec|exec|system|passthru|popen|proc_open)\s*\(/i',
                'weight'      => 7,
                'label'       => 'System command execution',
                'description' => 'Functions that execute system commands.',
                'tags'        => array( 'exec', 'system', 'dangerous' ),
            ),
            'backtick_exec' => array(
                'pattern'     => '/`[^`]{5,}`/',
                'weight'      => 6,
                'label'       => 'Backtick operator',
                'description' => 'Backtick strings execute shell commands.',
                'tags'        => array( 'exec', 'system' ),
            ),

            // Obfuscation indicators.
            'base64_decode' => array(
                'pattern'     => '/\bbase64_decode\s*\(/i',
                'weight'      => 5,
                'label'       => 'base64_decode()',
                'description' => 'Often used to hide malicious payloads.',
                'tags'        => array( 'obfuscation' ),
            ),
            'hex_decode' => array(
                'pattern'     => '/\\\\x[0-9a-fA-F]{2}(?:\\\\x[0-9a-fA-F]{2}){3,}/',
                'weight'      => 6,
                'label'       => 'Hex-encoded strings',
                'description' => 'Long hex-encoded sequences suggest obfuscation.',
                'tags'        => array( 'obfuscation' ),
            ),
            'long_hex_string' => array(
                'pattern'     => '/["\'][0-9a-fA-F]{60,}["\']/',
                'weight'      => 5,
                'label'       => 'Long hex constant',
                'description' => 'Suspiciously long hex string literal.',
                'tags'        => array( 'obfuscation' ),
            ),
            'str_rot13' => array(
                'pattern'     => '/\bstr_rot13\s*\(/i',
                'weight'      => 4,
                'label'       => 'str_rot13()',
                'description' => 'ROT13 used for trivial obfuscation.',
                'tags'        => array( 'obfuscation' ),
            ),
            'gzinflate_obfusc' => array(
                'pattern'     => '/\b(gzinflate|gzuncompress|gzdecode)\s*\(\s*(base64_decode|str_rot13)/i',
                'weight'      => 9,
                'label'       => 'Compressed + encoded payload',
                'description' => 'Classic malware pattern: decompress(decode(…)).',
                'tags'        => array( 'obfuscation', 'exec', 'dangerous' ),
            ),
            'chr_concat' => array(
                'pattern'     => '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr/i',
                'weight'      => 6,
                'label'       => 'chr() concatenation',
                'description' => 'Building strings character-by-character to evade detection.',
                'tags'        => array( 'obfuscation' ),
            ),
            'variable_variables' => array(
                'pattern'     => '/\$\{\s*\$[a-zA-Z_]/',
                'weight'      => 5,
                'label'       => 'Variable variables',
                'description' => 'Dynamic variable names used to obscure intent.',
                'tags'        => array( 'obfuscation' ),
            ),
            'long_single_line' => array(
                'pattern'     => '/^.{2000,}$/m',
                'weight'      => 4,
                'label'       => 'Extremely long line',
                'description' => 'Very long lines suggest minified/obfuscated code.',
                'tags'        => array( 'obfuscation' ),
            ),

            // Network / exfiltration.
            'curl_exec' => array(
                'pattern'     => '/\bcurl_exec\s*\(/i',
                'weight'      => 3,
                'label'       => 'cURL execution',
                'description' => 'Outbound HTTP requests.',
                'tags'        => array( 'network' ),
            ),
            'fsockopen' => array(
                'pattern'     => '/\b(fsockopen|pfsockopen)\s*\(/i',
                'weight'      => 5,
                'label'       => 'Socket connections',
                'description' => 'Raw socket connections — unusual in themes/plugins.',
                'tags'        => array( 'network', 'dangerous' ),
            ),
            'file_get_contents_url' => array(
                'pattern'     => '/file_get_contents\s*\(\s*[\'"]https?:/i',
                'weight'      => 3,
                'label'       => 'file_get_contents(URL)',
                'description' => 'Fetching remote content. Legitimate in some cases.',
                'tags'        => array( 'network' ),
            ),

            // Filesystem manipulation.
            'file_write' => array(
                'pattern'     => '/\b(file_put_contents|fwrite|fputs)\s*\(/i',
                'weight'      => 4,
                'label'       => 'File write operations',
                'description' => 'Writing files — may indicate dropper behavior.',
                'tags'        => array( 'filesystem', 'write' ),
            ),
            'chmod_usage' => array(
                'pattern'     => '/\bchmod\s*\(\s*[^,]+,\s*0?7/',
                'weight'      => 5,
                'label'       => 'chmod to world-writable',
                'description' => 'Setting permissive file permissions.',
                'tags'        => array( 'filesystem', 'write', 'dangerous' ),
            ),

            // Backdoor indicators.
            'web_shell_keywords' => array(
                'pattern'     => '/\b(c99|r57|wso|b374k|weevely|FilesMan)\b/i',
                'weight'      => 10,
                'label'       => 'Known web shell signature',
                'description' => 'Known web shell family name detected.',
                'tags'        => array( 'backdoor', 'dangerous' ),
            ),
            'superglobal_exec' => array(
                'pattern'     => '/(eval|assert|system|exec|passthru)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
                'weight'      => 10,
                'label'       => 'Superglobal code execution',
                'description' => 'Direct execution of user-supplied input — classic backdoor.',
                'tags'        => array( 'backdoor', 'exec', 'userinput', 'dangerous' ),
            ),
            'hidden_iframe' => array(
                'pattern'     => '/iframe[^>]*(?:width|height)\s*=\s*["\']?0/i',
                'weight'      => 7,
                'label'       => 'Hidden iframe',
                'description' => 'Zero-dimension iframe — common injection technique.',
                'tags'        => array( 'backdoor', 'injection' ),
            ),

            // WordPress specific.
            'wp_unauthorized_admin' => array(
                'pattern'     => '/wp_insert_user\s*\([^)]*role[^)]*administrator/i',
                'weight'      => 9,
                'label'       => 'Admin user creation',
                'description' => 'Code that creates administrator users.',
                'tags'        => array( 'backdoor', 'wp_specific', 'dangerous' ),
            ),
            'wp_option_injection' => array(
                'pattern'     => '/update_option\s*\(\s*[\'"](?:siteurl|home|admin_email|blogname)[\'"]/',
                'weight'      => 7,
                'label'       => 'Critical option override',
                'description' => 'Modifying critical WordPress options.',
                'tags'        => array( 'wp_specific', 'write', 'dangerous' ),
            ),
            'disable_security' => array(
                'pattern'     => '/(?:remove_action|remove_filter)\s*\(\s*[\'"](?:auth_redirect|check_admin_referer|wp_verify_nonce)/',
                'weight'      => 8,
                'label'       => 'Security function removal',
                'description' => 'Disabling WordPress authentication/nonce checks.',
                'tags'        => array( 'wp_specific', 'dangerous' ),
            ),
        );
    }

    /**
     * Analyse a file's contents and return detected signals.
     *
     * @param string $content File content (PHP source).
     * @param string $path    Relative file path (for context).
     * @return array Array of signal arrays: [
     *     'sig_id'      => string,
     *     'label'       => string,
     *     'weight'      => int,
     *     'description' => string,
     *     'tags'        => string[],
     *     'line'        => int|null,
     *     'snippet'     => string,
     * ]
     */
    public static function analyse( $content, $path = '' ) {
        self::init_signatures();

        $signals = array();

        foreach ( self::$signatures as $sig_id => $sig ) {
            if ( preg_match_all( $sig['pattern'], $content, $matches, PREG_OFFSET_CAPTURE ) ) {
                // Report only first occurrence per signature.
                $offset  = $matches[0][0][1];
                $line    = substr_count( $content, "\n", 0, $offset ) + 1;
                $snippet = self::extract_snippet( $content, $offset );

                $signals[] = array(
                    'sig_id'      => $sig_id,
                    'label'       => $sig['label'],
                    'weight'      => $sig['weight'],
                    'description' => $sig['description'],
                    'tags'        => isset( $sig['tags'] ) ? $sig['tags'] : array(),
                    'line'        => $line,
                    'snippet'     => $snippet,
                    'occurrences' => count( $matches[0] ),
                );
            }
        }

        // Entropy check for high-entropy blobs.
        $entropy_signal = self::check_entropy( $content );
        if ( $entropy_signal ) {
            $signals[] = $entropy_signal;
        }

        return $signals;
    }

    /**
     * Shannon entropy check for the file.
     *
     * @param string $content File content.
     * @return array|null Signal or null.
     */
    private static function check_entropy( $content ) {
        // Only check files with substantial content.
        $len = strlen( $content );
        if ( $len < 500 ) {
            return null;
        }

        // Sample a chunk to avoid slow computation on huge files.
        $sample = $len > 10000 ? substr( $content, 0, 10000 ) : $content;

        $freq = array();
        $slen = strlen( $sample );
        for ( $i = 0; $i < $slen; $i++ ) {
            $byte = ord( $sample[ $i ] );
            if ( ! isset( $freq[ $byte ] ) ) {
                $freq[ $byte ] = 0;
            }
            $freq[ $byte ]++;
        }

        $entropy = 0.0;
        foreach ( $freq as $count ) {
            $p = $count / $slen;
            if ( $p > 0 ) {
                $entropy -= $p * log( $p, 2 );
            }
        }

        // PHP source typically has entropy < 5.5. Encoded blobs push above 6.0.
        if ( $entropy > 6.0 ) {
            return array(
                'sig_id'      => 'high_entropy',
                'label'       => 'High entropy content',
                'weight'      => (int) min( 8, round( ( $entropy - 5.5 ) * 4 ) ),
                'description' => sprintf( 'Shannon entropy %.2f — likely encoded or encrypted payload.', $entropy ),
                'tags'        => array( 'obfuscation', 'entropy' ),
                'line'        => null,
                'snippet'     => '',
                'occurrences' => 1,
            );
        }

        return null;
    }

    /**
     * Extract a short context snippet around an offset.
     *
     * @param string $content Full content.
     * @param int    $offset  Byte offset.
     * @return string
     */
    private static function extract_snippet( $content, $offset ) {
        $start = max( 0, $offset - 40 );
        $raw   = substr( $content, $start, 120 );
        $clean = preg_replace( '/\s+/', ' ', $raw );
        return mb_substr( $clean, 0, 100 );
    }
}
