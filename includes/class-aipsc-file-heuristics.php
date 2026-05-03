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

            // ── Dangerous execution (additional) ─────────────────
            'dynamic_include' => array(
                'pattern'     => '/\b(include|include_once|require|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/i',
                'weight'      => 10,
                'label'       => 'Dynamic include with user input',
                'description' => 'File inclusion directly from superglobal — LFI/RFI vector.',
                'tags'        => array( 'exec', 'userinput', 'dangerous' ),
            ),
            'dynamic_include_var' => array(
                'pattern'     => '/\b(include|include_once|require|require_once)\s*\(\s*\$[a-zA-Z_]\w*\s*\.\s*/i',
                'weight'      => 5,
                'label'       => 'Dynamic include with variable',
                'description' => 'Include path built from variable concatenation.',
                'tags'        => array( 'exec' ),
            ),
            'call_user_func' => array(
                'pattern'     => '/\bcall_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
                'weight'      => 9,
                'label'       => 'call_user_func with user input',
                'description' => 'Arbitrary function call controlled by user input.',
                'tags'        => array( 'exec', 'userinput', 'dangerous' ),
            ),
            'error_suppress_exec' => array(
                'pattern'     => '/@\s*(eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(/i',
                'weight'      => 8,
                'label'       => 'Error-suppressed execution',
                'description' => 'Error suppression (@) on dangerous function — hiding failures.',
                'tags'        => array( 'exec', 'obfuscation', 'dangerous' ),
            ),

            // ── Obfuscation (additional) ─────────────────────────
            'xor_assembly' => array(
                'pattern'     => '/\$\w+\s*(?:\^|\|)\s*["\'][^"\']{5,}["\']/i',
                'weight'      => 6,
                'label'       => 'XOR/OR string assembly',
                'description' => 'Building strings via XOR/OR bitwise operations.',
                'tags'        => array( 'obfuscation' ),
            ),
            'str_replace_decode' => array(
                'pattern'     => '/str_replace\s*\([^)]+\)\s*\.\s*str_replace|str_ireplace\s*\([^)]{30,}\)/i',
                'weight'      => 4,
                'label'       => 'Multi-stage str_replace',
                'description' => 'Chained string replacements, common in payload reconstruction.',
                'tags'        => array( 'obfuscation' ),
            ),
            'pack_unpack' => array(
                'pattern'     => '/\b(pack|unpack)\s*\(\s*[\'"]H\*/i',
                'weight'      => 5,
                'label'       => 'pack/unpack hex conversion',
                'description' => 'Binary pack/unpack used to reconstruct payloads.',
                'tags'        => array( 'obfuscation' ),
            ),
            'array_map_exec' => array(
                'pattern'     => '/\barray_map\s*\(\s*[\'"](assert|eval|system|exec|base64_decode)[\'"]/i',
                'weight'      => 8,
                'label'       => 'array_map with dangerous callback',
                'description' => 'Execution via array_map callback — common shell trick.',
                'tags'        => array( 'exec', 'obfuscation', 'dangerous' ),
            ),
            'preg_replace_callback_exec' => array(
                'pattern'     => '/preg_replace_callback\s*\([^,]+,\s*[\'"](eval|assert|system)[\'"]/i',
                'weight'      => 8,
                'label'       => 'preg_replace_callback exec',
                'description' => 'Execution via preg_replace_callback — code injection trick.',
                'tags'        => array( 'exec', 'obfuscation', 'dangerous' ),
            ),

            // ── Remote fetch / payload download ──────────────────
            'wp_remote_get' => array(
                'pattern'     => '/\bwp_remote_get\s*\(\s*\$_(GET|POST|REQUEST)/i',
                'weight'      => 7,
                'label'       => 'wp_remote_get with user input',
                'description' => 'Remote fetch URL controlled by user input (SSRF).',
                'tags'        => array( 'network', 'userinput', 'dangerous' ),
            ),
            'curl_setopt_url' => array(
                'pattern'     => '/curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_(GET|POST|REQUEST)/i',
                'weight'      => 7,
                'label'       => 'cURL URL from user input',
                'description' => 'cURL destination set by user-controlled input.',
                'tags'        => array( 'network', 'userinput', 'dangerous' ),
            ),

            // ── Persistence / backdoor (additional) ──────────────
            'move_uploaded_file' => array(
                'pattern'     => '/\bmove_uploaded_file\s*\(/i',
                'weight'      => 4,
                'label'       => 'move_uploaded_file()',
                'description' => 'File upload handler — benign alone, risky in context.',
                'tags'        => array( 'upload', 'filesystem' ),
            ),
            'register_shutdown' => array(
                'pattern'     => '/\bregister_shutdown_function\s*\(\s*[\'"](eval|assert|system)[\'"]/i',
                'weight'      => 9,
                'label'       => 'Shutdown function exec',
                'description' => 'Registering dangerous function in shutdown hook.',
                'tags'        => array( 'exec', 'backdoor', 'dangerous' ),
            ),
            'ini_set_disable' => array(
                'pattern'     => '/\bini_set\s*\(\s*[\'"](?:disable_functions|open_basedir|safe_mode)[\'"]/i',
                'weight'      => 7,
                'label'       => 'ini_set security bypass',
                'description' => 'Attempting to override PHP security directives.',
                'tags'        => array( 'dangerous', 'backdoor' ),
            ),
            'set_time_limit_zero' => array(
                'pattern'     => '/\bset_time_limit\s*\(\s*0\s*\)/i',
                'weight'      => 2,
                'label'       => 'set_time_limit(0)',
                'description' => 'Removing execution time limit — often used by shells.',
                'tags'        => array( 'backdoor' ),
            ),
            'error_reporting_zero' => array(
                'pattern'     => '/\berror_reporting\s*\(\s*0\s*\)/i',
                'weight'      => 3,
                'label'       => 'error_reporting(0)',
                'description' => 'Disabling error reporting to hide activity.',
                'tags'        => array( 'obfuscation', 'backdoor' ),
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

        // Compound rules — multi-pattern correlations.
        $compound_signals = self::analyse_compound( $content );
        foreach ( $compound_signals as $cs ) {
            $signals[] = $cs;
        }

        return $signals;
    }

    /**
     * Compound heuristic rules.
     *
     * Each rule checks for a specific multi-pattern correlation that is
     * much more suspicious than any single pattern alone. Returns high-weight
     * signals only when the combination is present.
     *
     * @var array
     */
    private static $compound_rules = array();

    /**
     * Initialise compound rules (lazy).
     */
    private static function init_compound_rules() {
        if ( ! empty( self::$compound_rules ) ) {
            return;
        }

        self::$compound_rules = array(
            // ── Obfuscation combos ───────────────────────────────
            'eval_base64' => array(
                'patterns'    => array(
                    '/\beval\s*\(/i',
                    '/\bbase64_decode\s*\(/i',
                ),
                'weight'      => 10,
                'label'       => 'eval(base64_decode(…))',
                'description' => 'Classic obfuscated payload: decode then execute.',
                'tags'        => array( 'exec', 'obfuscation', 'dangerous', 'compound' ),
            ),
            'gzinflate_base64' => array(
                'patterns'    => array(
                    '/\b(gzinflate|gzuncompress|gzdecode)\s*\(/i',
                    '/\bbase64_decode\s*\(/i',
                ),
                'weight'      => 10,
                'label'       => 'Decompress + decode combo',
                'description' => 'Compressed and encoded payload — multi-layer obfuscation.',
                'tags'        => array( 'obfuscation', 'dangerous', 'compound' ),
            ),
            'chr_chain_exec' => array(
                'patterns'    => array(
                    '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr/i',
                    '/\b(eval|assert|system|exec|passthru)\s*\(/i',
                ),
                'weight'      => 9,
                'label'       => 'chr() chain + execution',
                'description' => 'Character-by-character string building fed to exec.',
                'tags'        => array( 'exec', 'obfuscation', 'dangerous', 'compound' ),
            ),
            'hex_assembly_exec' => array(
                'patterns'    => array(
                    '/\\\\x[0-9a-fA-F]{2}(?:\\\\x[0-9a-fA-F]{2}){3,}/',
                    '/\b(eval|assert|system|exec|passthru|call_user_func)\s*\(/i',
                ),
                'weight'      => 9,
                'label'       => 'Hex assembly + execution',
                'description' => 'Hex-encoded string reconstruction fed to exec.',
                'tags'        => array( 'exec', 'obfuscation', 'dangerous', 'compound' ),
            ),
            'xor_exec' => array(
                'patterns'    => array(
                    '/\$\w+\s*\^=?\s*["\'][^"\']{5,}["\']/',
                    '/\b(eval|assert|system|exec)\s*\(/i',
                ),
                'weight'      => 9,
                'label'       => 'XOR reconstruction + execution',
                'description' => 'XOR string decoding paired with code execution.',
                'tags'        => array( 'exec', 'obfuscation', 'dangerous', 'compound' ),
            ),

            // ── Dangerous execution combos ───────────────────────
            'assert_superglobal' => array(
                'patterns'    => array(
                    '/\bassert\s*\(/i',
                    '/\$_(POST|GET|REQUEST|COOKIE)\b/',
                ),
                'weight'      => 10,
                'label'       => 'assert() with superglobal input',
                'description' => 'Assert used with user input — code injection backdoor.',
                'tags'        => array( 'exec', 'userinput', 'backdoor', 'dangerous', 'compound' ),
            ),
            'create_func_exec' => array(
                'patterns'    => array(
                    '/\bcreate_function\s*\(/i',
                    '/\bbase64_decode\s*\(/i',
                ),
                'weight'      => 9,
                'label'       => 'create_function + base64',
                'description' => 'Deprecated function builder with encoded payload.',
                'tags'        => array( 'exec', 'obfuscation', 'dangerous', 'compound' ),
            ),
            'payload_reconstruct' => array(
                'patterns'    => array(
                    '/str_replace\s*\(/i',
                    '/\b(eval|assert|preg_replace)\s*\(/i',
                    '/\bbase64_decode\s*\(/i',
                ),
                'weight'      => 9,
                'label'       => 'Payload reconstruction + exec',
                'description' => 'String manipulation + decode + execution — staged payload.',
                'tags'        => array( 'exec', 'obfuscation', 'dangerous', 'compound' ),
            ),

            // ── Remote fetch + persistence ───────────────────────
            'remote_fetch_write' => array(
                'patterns'    => array(
                    '/\b(file_get_contents|curl_exec|wp_remote_get)\s*\(/i',
                    '/\b(file_put_contents|fwrite|fputs)\s*\(/i',
                ),
                'weight'      => 8,
                'label'       => 'Remote fetch + local write',
                'description' => 'Downloading content and writing to disk — dropper behavior.',
                'tags'        => array( 'network', 'write', 'dangerous', 'compound' ),
            ),
            'remote_fetch_exec' => array(
                'patterns'    => array(
                    '/\b(file_get_contents|curl_exec|wp_remote_get)\s*\(/i',
                    '/\b(eval|assert|system|exec|passthru)\s*\(/i',
                ),
                'weight'      => 10,
                'label'       => 'Remote fetch + execution',
                'description' => 'Fetching remote code and executing — remote shell.',
                'tags'        => array( 'network', 'exec', 'dangerous', 'compound' ),
            ),

            // ── Suspicious upload handling ───────────────────────
            'upload_to_exec' => array(
                'patterns'    => array(
                    '/\bmove_uploaded_file\s*\(/i',
                    '/\b(include|include_once|require|require_once|eval)\s*\(/i',
                ),
                'weight'      => 9,
                'label'       => 'Upload + include/exec',
                'description' => 'File upload immediately included or executed.',
                'tags'        => array( 'upload', 'exec', 'dangerous', 'compound' ),
            ),
            'upload_chmod' => array(
                'patterns'    => array(
                    '/\bmove_uploaded_file\s*\(/i',
                    '/\bchmod\s*\(/i',
                ),
                'weight'      => 7,
                'label'       => 'Upload + chmod',
                'description' => 'Uploaded file with permission changes — dropper setup.',
                'tags'        => array( 'upload', 'write', 'dangerous', 'compound' ),
            ),

            // ── Cloaked / stealth ────────────────────────────────
            'error_suppress_obfusc' => array(
                'patterns'    => array(
                    '/@\s*(eval|assert|system|exec|passthru)\s*\(/i',
                    '/\b(base64_decode|str_rot13|gzinflate|gzuncompress)\s*\(/i',
                ),
                'weight'      => 10,
                'label'       => 'Error-suppressed exec + obfuscation',
                'description' => 'Silenced execution with encoded payload — stealth shell.',
                'tags'        => array( 'exec', 'obfuscation', 'dangerous', 'compound' ),
            ),
            'stealth_backdoor' => array(
                'patterns'    => array(
                    '/\berror_reporting\s*\(\s*0\s*\)/i',
                    '/\bset_time_limit\s*\(\s*0\s*\)/i',
                    '/\b(eval|assert|system|exec|passthru)\s*\(/i',
                ),
                'weight'      => 10,
                'label'       => 'Stealth setup + execution',
                'description' => 'Error hiding + no time limit + exec — classic shell init.',
                'tags'        => array( 'exec', 'backdoor', 'dangerous', 'compound' ),
            ),
            'ini_override_exec' => array(
                'patterns'    => array(
                    '/\bini_set\s*\(\s*[\'"](?:disable_functions|open_basedir)[\'"]/i',
                    '/\b(eval|assert|system|exec|passthru|shell_exec)\s*\(/i',
                ),
                'weight'      => 10,
                'label'       => 'Security bypass + execution',
                'description' => 'Overriding PHP security + code execution.',
                'tags'        => array( 'exec', 'backdoor', 'dangerous', 'compound' ),
            ),
        );
    }

    /**
     * Run compound (multi-pattern correlation) analysis.
     *
     * Each compound rule requires ALL of its patterns to match for the
     * rule to fire. This produces much higher-confidence signals than
     * any single pattern match.
     *
     * @param string $content File content.
     * @return array Array of signal arrays.
     */
    private static function analyse_compound( $content ) {
        self::init_compound_rules();

        $signals = array();

        foreach ( self::$compound_rules as $rule_id => $rule ) {
            $all_match  = true;
            $first_off  = null;
            $first_snip = '';

            foreach ( $rule['patterns'] as $pattern ) {
                if ( preg_match( $pattern, $content, $m, PREG_OFFSET_CAPTURE ) ) {
                    if ( null === $first_off || $m[0][1] < $first_off ) {
                        $first_off  = $m[0][1];
                        $first_snip = self::extract_snippet( $content, $m[0][1] );
                    }
                } else {
                    $all_match = false;
                    break;
                }
            }

            if ( $all_match ) {
                $line = null !== $first_off
                    ? substr_count( $content, "\n", 0, $first_off ) + 1
                    : null;

                $signals[] = array(
                    'sig_id'      => $rule_id,
                    'label'       => $rule['label'],
                    'weight'      => $rule['weight'],
                    'description' => $rule['description'],
                    'tags'        => $rule['tags'],
                    'line'        => $line,
                    'snippet'     => $first_snip,
                    'occurrences' => 1,
                );
            }
        }

        return $signals;
    }

    /**
     * Analyse a non-PHP file for hidden PHP code.
     *
     * Used to detect PHP code embedded in files with non-PHP extensions
     * (e.g., PHP inside .jpg, .png, .ico files in uploads).
     *
     * @param string $content File content.
     * @param string $path    Relative file path (for context).
     * @return array Array of signal arrays (same format as analyse()).
     */
    public static function analyse_non_php( $content, $path = '' ) {
        $signals = array();

        // ── Detect PHP opening tags ──────────────────────────────
        $php_tag_checks = array(
            'hidden_php_full_tag' => array(
                'pattern'     => '/<\?php\b/i',
                'weight'      => 9,
                'label'       => 'PHP opening tag in non-PHP file',
                'description' => '<?php tag found inside a non-PHP file.',
            ),
            'hidden_php_short_echo' => array(
                'pattern'     => '/<\?=/',
                'weight'      => 8,
                'label'       => 'PHP short echo tag in non-PHP file',
                'description' => '<?= short echo tag found inside a non-PHP file.',
            ),
            'hidden_php_short_tag' => array(
                'pattern'     => '/<\?\s+(?:\$|echo|print|if|for|while|function|class|return|eval|assert)\b/',
                'weight'      => 8,
                'label'       => 'PHP short open tag in non-PHP file',
                'description' => 'PHP short open tag followed by PHP keyword.',
            ),
        );

        $has_php = false;

        foreach ( $php_tag_checks as $sig_id => $sig ) {
            if ( preg_match( $sig['pattern'], $content, $match, PREG_OFFSET_CAPTURE ) ) {
                $offset  = $match[0][1];
                $line    = substr_count( $content, "\n", 0, $offset ) + 1;
                $snippet = self::extract_snippet( $content, $offset );

                $signals[] = array(
                    'sig_id'      => $sig_id,
                    'label'       => $sig['label'],
                    'weight'      => $sig['weight'],
                    'description' => $sig['description'],
                    'tags'        => array( 'hidden_php', 'dangerous' ),
                    'line'        => $line,
                    'snippet'     => $snippet,
                    'occurrences' => 1,
                );

                $has_php = true;
            }
        }

        // If PHP code detected, run full signature analysis on the content.
        if ( $has_php ) {
            $full_signals = self::analyse( $content, $path );
            foreach ( $full_signals as $sig ) {
                if ( ! in_array( 'hidden_php', $sig['tags'], true ) ) {
                    $sig['tags'][] = 'hidden_php';
                }
                $signals[] = $sig;
            }
        } else {
            // Even without PHP tags, check for high entropy (encoded payloads).
            $entropy_signal = self::check_entropy( $content );
            if ( $entropy_signal ) {
                $entropy_signal['tags'][] = 'hidden_php';
                $signals[] = $entropy_signal;
            }
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
