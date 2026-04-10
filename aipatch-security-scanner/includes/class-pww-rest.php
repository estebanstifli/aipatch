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
 * Class PWW_Rest
 */
class PWW_Rest {

    /** @var PWW_Scanner|null */
    private $scanner;

    /** @var PWW_Dashboard */
    private $dashboard;

    /** @var PWW_Vulnerabilities|null */
    private $vulnerabilities;

    /** @var PWW_Hardening|null */
    private $hardening;

    /** @var PWW_Logger */
    private $logger;

    /**
     * Constructor.
     */
    public function __construct(
        $scanner,
        PWW_Dashboard $dashboard,
        $vulnerabilities,
        $hardening,
        PWW_Logger $logger
    ) {
        $this->scanner         = $scanner;
        $this->dashboard       = $dashboard;
        $this->vulnerabilities = $vulnerabilities;
        $this->hardening       = $hardening;
        $this->logger          = $logger;
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
}
