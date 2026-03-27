<?php
/**
 * REST API module – internal REST endpoints.
 *
 * @package PatchWatch
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class PWW_Rest
 */
class PWW_Rest {

    /** @var PWW_Scanner */
    private $scanner;

    /** @var PWW_Dashboard */
    private $dashboard;

    /** @var PWW_Vulnerabilities */
    private $vulnerabilities;

    /** @var PWW_Hardening */
    private $hardening;

    /**
     * Constructor.
     */
    public function __construct(
        PWW_Scanner $scanner,
        PWW_Dashboard $dashboard,
        PWW_Vulnerabilities $vulnerabilities,
        PWW_Hardening $hardening
    ) {
        $this->scanner         = $scanner;
        $this->dashboard       = $dashboard;
        $this->vulnerabilities = $vulnerabilities;
        $this->hardening       = $hardening;
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
         * Fires after AI PatchWatch REST routes are registered.
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
                __( 'You do not have permission to access this endpoint.', 'patchwatch' ),
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
        $results = $this->scanner->run_full_scan();

        $logger = new PWW_Logger();
        $logger->info( 'rest_scan', __( 'Security scan triggered via REST API.', 'patchwatch' ) );

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
        $key   = $request->get_param( 'key' );
        $value = $request->get_param( 'value' );

        $result = $this->hardening->toggle( $key, $value );

        if ( ! $result ) {
            return new WP_REST_Response( array(
                'success' => false,
                'message' => __( 'Invalid hardening option.', 'patchwatch' ),
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
