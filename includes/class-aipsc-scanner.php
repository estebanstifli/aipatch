<?php
/**
 * Security scanner module.
 *
 * Now delegates to the modular AIPSC_Audit_Engine while keeping
 * the public API unchanged for backward compatibility.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Scanner
 *
 * Backward-compatible bridge over the modular audit engine.
 */
class AIPSC_Scanner {

    /**
     * @var AIPSC_Logger
     */
    private $logger;

    /**
     * @var AIPSC_Audit_Engine|null
     */
    private $engine;

    /**
     * @var AIPSC_Findings_Store|null
     */
    private $findings_store;

    /**
     * Constructor.
     *
     * @param AIPSC_Logger              $logger         Logger instance.
     * @param AIPSC_Audit_Engine|null   $engine         Audit engine (null for legacy compat).
     * @param AIPSC_Findings_Store|null $findings_store Findings persistence store.
     */
    public function __construct( AIPSC_Logger $logger, AIPSC_Audit_Engine $engine = null, AIPSC_Findings_Store $findings_store = null ) {
        $this->logger         = $logger;
        $this->engine         = $engine;
        $this->findings_store = $findings_store;
    }

    /**
     * Get the audit engine instance.
     *
     * @return AIPSC_Audit_Engine|null
     */
    public function get_engine() {
        return $this->engine;
    }

    /**
     * Sync raw audit results to the findings store.
     *
     * Used by the step-by-step REST scan flow.
     *
     * @param AIPSC_Audit_Check_Result[] $raw_results Audit check results.
     */
    public function sync_findings( array $raw_results ) {
        if ( $this->findings_store && ! empty( $raw_results ) ) {
            $this->findings_store->sync( $raw_results );
        }
    }

    /**
     * Run a full security scan.
     *
     * @param string $scan_type Scan type (manual|cron).
     * @return array Scan results with 'score', 'issues', 'timestamp'.
     */
    public function run_full_scan( $scan_type = 'manual' ) {
        if ( ! $this->engine ) {
            return array(
                'score'     => 0,
                'issues'    => array(),
                'timestamp' => time(),
                'version'   => AIPATCH_VERSION,
            );
        }

        // Delegate to audit engine.
        $results = $this->engine->run_legacy( $scan_type );

        $score       = $results['score'];
        $issues      = $results['issues'];
        $duration_ms = $results['duration_ms'];

        // Store results (backward compatible).
        AIPSC_Utils::update_option( 'scan_results', $results );
        AIPSC_Utils::update_option( 'last_scan', time() );
        AIPSC_Utils::update_option( 'security_score', $score );

        // Persist findings to DB (deduplication via fingerprint).
        if ( $this->findings_store && ! empty( $results['raw_results'] ) ) {
            $this->findings_store->sync( $results['raw_results'] );
        }

        // Save to scan history table.
        $this->save_scan_history( $scan_type, $score, $issues, $duration_ms );

        /**
         * Fires after a security scan completes.
         *
         * @param array $results Scan results.
         */
        do_action( 'aipatch_scan_completed', $results );

        return $results;
    }

    /**
     * Save a scan record to the history table.
     *
     * @param string $scan_type   manual|cron.
     * @param int    $score       Security score.
     * @param array  $issues      Issue list.
     * @param int    $duration_ms Duration in milliseconds.
     */
    private function save_scan_history( $scan_type, $score, $issues, $duration_ms ) {
        global $wpdb;

        $table = $wpdb->prefix . 'aipsc_scan_history';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $table,
            array(
                'scan_type'    => sanitize_key( $scan_type ),
                'score'        => absint( $score ),
                'issues_count' => count( $issues ),
                'issues_json'  => wp_json_encode( $issues ),
                'duration_ms'  => absint( $duration_ms ),
                'created_at'   => current_time( 'mysql', true ),
            ),
            array( '%s', '%d', '%d', '%s', '%d', '%s' )
        );
    }

    /**
     * Get the last scan results (cached).
     *
     * @return array|false
     */
    public function get_last_results() {
        return AIPSC_Utils::get_option( 'scan_results', false );
    }

    /**
     * Get quick summary data for dashboard cards.
     *
     * @return array
     */
    public function get_summary() {
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        global $wp_version, $wpdb;

        $all_plugins    = get_plugins();
        $active_plugins = get_option( 'active_plugins', array() );
        $update_plugins = get_site_transient( 'update_plugins' );
        $update_themes  = get_site_transient( 'update_themes' );
        $admins         = get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) );
        $hardening      = AIPSC_Utils::get_hardening();
        $file_editor_off = defined( 'DISALLOW_FILE_EDIT' ) ? (bool) constant( 'DISALLOW_FILE_EDIT' ) : false;

        $outdated_plugins = 0;
        if ( isset( $update_plugins->response ) ) {
            foreach ( $update_plugins->response as $file => $data ) {
                if ( in_array( $file, $active_plugins, true ) ) {
                    $outdated_plugins++;
                }
            }
        }

        $outdated_themes = 0;
        if ( isset( $update_themes->response ) ) {
            $outdated_themes = count( $update_themes->response );
        }

        $registry    = $this->engine ? $this->engine->get_registry() : null;
        $total_checks = $registry ? $registry->count() : 28;

        return array(
            'wp_version'         => $wp_version,
            'php_version'        => PHP_VERSION,
            'active_plugins'     => count( $active_plugins ),
            'total_plugins'      => count( $all_plugins ),
            'outdated_plugins'   => $outdated_plugins,
            'inactive_plugins'   => count( $all_plugins ) - count( $active_plugins ),
            'outdated_themes'    => $outdated_themes,
            'unused_themes'      => max( 0, count( wp_get_themes() ) - 2 ),
            'admin_count'        => count( $admins ),
            'admin_user_exists'  => (bool) get_user_by( 'login', 'admin' ),
            'db_prefix_default'  => 'wp_' === $wpdb->prefix,
            'xmlrpc_disabled'    => ! empty( $hardening['disable_xmlrpc'] ),
            'rest_restricted'    => ! empty( $hardening['restrict_rest_api'] ),
            'file_editor_off'    => $file_editor_off,
            'debug_active'       => defined( 'WP_DEBUG' ) && WP_DEBUG,
            'ssl_active'         => is_ssl(),
            'login_protected'    => ! empty( $hardening['login_protection'] ),
            'wp_version_hidden'  => ! empty( $hardening['hide_wp_version'] ),
            'auto_updates_core'  => ( ! defined( 'WP_AUTO_UPDATE_CORE' ) || false !== constant( 'WP_AUTO_UPDATE_CORE' ) ),
            'total_checks'       => $total_checks,
        );
    }
}
