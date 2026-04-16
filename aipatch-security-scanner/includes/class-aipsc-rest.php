<?php
/**
 * REST API module – internal REST endpoints.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Rest
 */
class AIPSC_Rest {

    /** @var AIPSC_Scanner|null */
    private $scanner;

    /** @var AIPSC_Dashboard */
    private $dashboard;

    /** @var AIPSC_Vulnerabilities|null */
    private $vulnerabilities;

    /** @var AIPSC_Hardening|null */
    private $hardening;

    /** @var AIPSC_Logger */
    private $logger;

    /** @var AIPSC_Performance|null */
    private $performance;

    /**
     * Constructor.
     */
    public function __construct(
        $scanner,
        AIPSC_Dashboard $dashboard,
        $vulnerabilities,
        $hardening,
        AIPSC_Logger $logger,
        $performance = null
    ) {
        $this->scanner         = $scanner;
        $this->dashboard       = $dashboard;
        $this->vulnerabilities = $vulnerabilities;
        $this->hardening       = $hardening;
        $this->logger          = $logger;
        $this->performance     = $performance;
    }

    /**
     * Register REST routes.
     */
    public function register_routes() {
        register_rest_route( AIPATCH_REST_NAMESPACE, '/run-scan', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'handle_run_scan' ),
            'permission_callback' => array( $this, 'check_admin_permission' ),
        ) );

        register_rest_route( AIPATCH_REST_NAMESPACE, '/get-summary', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'handle_get_summary' ),
            'permission_callback' => array( $this, 'check_admin_permission' ),
        ) );

        register_rest_route( AIPATCH_REST_NAMESPACE, '/get-vulnerabilities', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'handle_get_vulnerabilities' ),
            'permission_callback' => array( $this, 'check_admin_permission' ),
        ) );

        register_rest_route( AIPATCH_REST_NAMESPACE, '/toggle-hardening', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'handle_toggle_hardening' ),
            'permission_callback' => array( $this, 'check_admin_permission' ),
            'args'                => array(
                'key' => array(
                    'required'          => true,
                    'type'              => 'string',
                    'sanitize_callback' => 'sanitize_key',
                ),
                'value' => array(
                    'required'          => true,
                    'type'              => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ),
            ),
        ) );

        register_rest_route( AIPATCH_REST_NAMESPACE, '/dismiss-issue', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'handle_dismiss_issue' ),
            'permission_callback' => array( $this, 'check_admin_permission' ),
            'args'                => array(
                'issue_id' => array(
                    'required'          => true,
                    'type'              => 'string',
                    'sanitize_callback' => 'sanitize_key',
                ),
            ),
        ) );

        register_rest_route( AIPATCH_REST_NAMESPACE, '/scan-history', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'handle_get_scan_history' ),
            'permission_callback' => array( $this, 'check_admin_permission' ),
            'args'                => array(
                'limit' => array(
                    'required'          => false,
                    'type'              => 'integer',
                    'default'           => 30,
                    'sanitize_callback' => 'absint',
                ),
            ),
        ) );

        register_rest_route( AIPATCH_REST_NAMESPACE, '/export-logs', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'handle_export_logs' ),
            'permission_callback' => array( $this, 'check_admin_permission' ),
        ) );

        register_rest_route( AIPATCH_REST_NAMESPACE, '/export-scans', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'handle_export_scans' ),
            'permission_callback' => array( $this, 'check_admin_permission' ),
        ) );

        register_rest_route( AIPATCH_REST_NAMESPACE, '/run-performance', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'handle_run_performance' ),
            'permission_callback' => array( $this, 'check_admin_permission' ),
        ) );

        register_rest_route( AIPATCH_REST_NAMESPACE, '/get-performance', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'handle_get_performance' ),
            'permission_callback' => array( $this, 'check_admin_permission' ),
        ) );

        /**
         * Fires after Aipatch Security Scanner REST routes are registered.
         * Allows adding custom endpoints.
         */
        do_action( 'aipatch_rest_routes_registered' );
    }

    /**
     * Permission callback: require manage_options.
     *
     * @param WP_REST_Request $request Request object.
     * @return bool|WP_Error
     */
    public function check_admin_permission( $request ) {
        if ( ! current_user_can( 'manage_options' ) ) {
            return new WP_Error(
                'rest_forbidden',
                __( 'You do not have permission to access this endpoint.', 'aipatch-security-scanner' ),
                array( 'status' => 403 )
            );
        }
        return true;
    }

    /**
     * Handle: run-scan.
     *
     * @param WP_REST_Request $request Request.
     * @return WP_REST_Response
     */
    public function handle_run_scan( $request ) {
        if ( ! $this->scanner ) {
            return new WP_REST_Response( array(
                'success' => false,
                'message' => __( 'Scanner module is disabled.', 'aipatch-security-scanner' ),
            ), 400 );
        }

        $results = $this->scanner->run_full_scan();

        $this->logger->info( 'rest_scan', __( 'Security scan triggered via REST API.', 'aipatch-security-scanner' ) );

        return new WP_REST_Response( array(
            'success' => true,
            'score'   => $results['score'],
            'issues'  => count( $results['issues'] ),
        ), 200 );
    }

    /**
     * Handle: get-summary.
     *
     * @param WP_REST_Request $request Request.
     * @return WP_REST_Response
     */
    public function handle_get_summary( $request ) {
        $data = $this->dashboard->get_dashboard_data();

        return new WP_REST_Response( array(
            'success' => true,
            'data'    => $data,
        ), 200 );
    }

    /**
     * Handle: get-vulnerabilities.
     *
     * @param WP_REST_Request $request Request.
     * @return WP_REST_Response
     */
    public function handle_get_vulnerabilities( $request ) {
        if ( ! $this->vulnerabilities ) {
            return new WP_REST_Response( array(
                'success' => true,
                'data'    => array(),
                'count'   => 0,
            ), 200 );
        }

        $vulns = $this->vulnerabilities->get_all_vulnerabilities();

        return new WP_REST_Response( array(
            'success' => true,
            'data'    => $vulns,
            'count'   => count( $vulns ),
        ), 200 );
    }

    /**
     * Handle: toggle-hardening.
     *
     * @param WP_REST_Request $request Request.
     * @return WP_REST_Response
     */
    public function handle_toggle_hardening( $request ) {
        if ( ! $this->hardening ) {
            return new WP_REST_Response( array(
                'success' => false,
                'message' => __( 'Hardening module is disabled.', 'aipatch-security-scanner' ),
            ), 400 );
        }

        $key   = $request->get_param( 'key' );
        $value = $request->get_param( 'value' );

        $result = $this->hardening->toggle( $key, $value );

        if ( ! $result ) {
            return new WP_REST_Response( array(
                'success' => false,
                'message' => __( 'Invalid hardening option.', 'aipatch-security-scanner' ),
            ), 400 );
        }

        return new WP_REST_Response( array(
            'success' => true,
            'key'     => $key,
            'value'   => $value,
        ), 200 );
    }

    /**
     * Handle: dismiss-issue.
     *
     * @param WP_REST_Request $request Request.
     * @return WP_REST_Response
     */
    public function handle_dismiss_issue( $request ) {
        $issue_id = $request->get_param( 'issue_id' );
        $this->dashboard->dismiss_issue( $issue_id );

        return new WP_REST_Response( array(
            'success' => true,
        ), 200 );
    }

    /**
     * Handle: scan-history.
     *
     * @param WP_REST_Request $request Request.
     * @return WP_REST_Response
     */
    public function handle_get_scan_history( $request ) {
        global $wpdb;

        $limit = min( absint( $request->get_param( 'limit' ) ), 90 );
        if ( $limit < 1 ) {
            $limit = 30;
        }

        $table = $wpdb->prefix . 'aipsc_scan_history';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT score, issues_count, scan_type, duration_ms, created_at FROM %i ORDER BY created_at DESC LIMIT %d",
                $table,
                $limit
            ),
            ARRAY_A
        );

        // Reverse so chart goes oldest → newest.
        $rows = array_reverse( $rows ?: array() );

        return new WP_REST_Response( array(
            'success' => true,
            'data'    => $rows,
        ), 200 );
    }

    /**
     * Handle: export-logs (CSV).
     *
     * @param WP_REST_Request $request Request.
     * @return WP_REST_Response
     */
    public function handle_export_logs( $request ) {
        $log_data = $this->logger->get_logs( array(
            'per_page' => 5000,
            'page'     => 1,
        ) );

        $csv_rows = array();
        $csv_rows[] = array( 'Date', 'Severity', 'Event', 'Message' );

        foreach ( $log_data['items'] as $log ) {
            $csv_rows[] = array(
                $log->created_at,
                $log->severity,
                $log->event_type,
                $log->message,
            );
        }

        return new WP_REST_Response( array(
            'success'  => true,
            'filename' => 'aipatch-logs-' . gmdate( 'Y-m-d' ) . '.csv',
            'data'     => $csv_rows,
        ), 200 );
    }

    /**
     * Handle: export-scans (CSV).
     *
     * @param WP_REST_Request $request Request.
     * @return WP_REST_Response
     */
    public function handle_export_scans( $request ) {
        global $wpdb;

        $table = $wpdb->prefix . 'aipsc_scan_history';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT scan_type, score, issues_count, duration_ms, created_at FROM %i ORDER BY created_at DESC LIMIT 500",
                $table
            ),
            ARRAY_A
        );

        $csv_rows = array();
        $csv_rows[] = array( 'Date', 'Type', 'Score', 'Issues', 'Duration (ms)' );

        foreach ( $rows ?: array() as $row ) {
            $csv_rows[] = array(
                $row['created_at'],
                $row['scan_type'],
                $row['score'],
                $row['issues_count'],
                $row['duration_ms'],
            );
        }

        return new WP_REST_Response( array(
            'success'  => true,
            'filename' => 'aipatch-scans-' . gmdate( 'Y-m-d' ) . '.csv',
            'data'     => $csv_rows,
        ), 200 );
    }

    /**
     * Handle: run-performance.
     *
     * @param WP_REST_Request $request Request.
     * @return WP_REST_Response
     */
    public function handle_run_performance( $request ) {
        if ( ! $this->performance ) {
            return new WP_REST_Response( array(
                'success' => false,
                'message' => __( 'Performance module is not available.', 'aipatch-security-scanner' ),
            ), 400 );
        }

        $results = $this->performance->run_diagnostics();

        $this->logger->info( 'rest_performance', __( 'Performance diagnostics triggered via REST API.', 'aipatch-security-scanner' ) );

        return new WP_REST_Response( array(
            'success' => true,
            'data'    => $results,
        ), 200 );
    }

    /**
     * Handle: get-performance.
     *
     * @param WP_REST_Request $request Request.
     * @return WP_REST_Response
     */
    public function handle_get_performance( $request ) {
        if ( ! $this->performance ) {
            return new WP_REST_Response( array(
                'success' => true,
                'data'    => null,
            ), 200 );
        }

        $results = $this->performance->get_last_results();

        return new WP_REST_Response( array(
            'success' => true,
            'data'    => $results ? $results : null,
        ), 200 );
    }
}
