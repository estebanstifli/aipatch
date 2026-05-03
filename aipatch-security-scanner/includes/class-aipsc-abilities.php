<?php
/**
 * Abilities API integration for external MCP/AI agents.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Abilities
 *
 * Registers read-only security abilities for the WordPress Abilities API.
 */
class AIPSC_Abilities {

    /** @var AIPSC_Scanner|null */
    private $scanner;

    /** @var AIPSC_Vulnerabilities|null */
    private $vulnerabilities;

    /** @var AIPSC_Logger */
    private $logger;

    /** @var AIPSC_File_Scanner|null */
    private $file_scanner;

    /** @var AIPSC_Findings_Store|null */
    private $findings_store;

    /** @var AIPSC_File_Baseline|null */
    private $file_baseline;

    /** @var AIPSC_Job_Manager|null */
    private $job_manager;

    /** @var AIPSC_Remediation_Engine|null */
    private $remediation_engine;

    /** @var AIPSC_Core_Verifier|null */
    private $core_verifier;

    /**
     * Constructor.
     *
     * @param AIPSC_Scanner|null         $scanner         Scanner module.
     * @param AIPSC_Vulnerabilities|null $vulnerabilities Vulnerabilities module.
     * @param AIPSC_Logger               $logger          Logger instance.
     * @param array                      $extra_modules   Extra modules keyed by name.
     */
    public function __construct( $scanner, $vulnerabilities, AIPSC_Logger $logger, array $extra_modules = array() ) {
        $this->scanner            = $scanner;
        $this->vulnerabilities    = $vulnerabilities;
        $this->logger             = $logger;
        $this->file_scanner       = isset( $extra_modules['file_scanner'] ) ? $extra_modules['file_scanner'] : null;
        $this->findings_store     = isset( $extra_modules['findings_store'] ) ? $extra_modules['findings_store'] : null;
        $this->file_baseline      = isset( $extra_modules['file_baseline'] ) ? $extra_modules['file_baseline'] : null;
        $this->job_manager        = isset( $extra_modules['job_manager'] ) ? $extra_modules['job_manager'] : null;
        $this->remediation_engine = isset( $extra_modules['remediation_engine'] ) ? $extra_modules['remediation_engine'] : null;
        $this->core_verifier      = isset( $extra_modules['core_verifier'] ) ? $extra_modules['core_verifier'] : null;
    }

    /**
     * Register Abilities API hooks when available.
     */
    public function init() {
        if ( ! $this->is_abilities_api_available() ) {
            return;
        }

        add_action( 'wp_abilities_api_categories_init', array( $this, 'register_categories' ) );
        add_action( 'wp_abilities_api_init', array( $this, 'register_abilities' ) );
        add_action( 'aipatch_run_async_ability_job', array( $this, 'handle_async_ability_job' ), 10, 3 );
    }

    /**
     * Register ability categories.
     */
    public function register_categories() {
        if ( ! function_exists( 'wp_register_ability_category' ) ) {
            return;
        }

        call_user_func(
            'wp_register_ability_category',
            'aipatch-security',
            array(
                'label'       => __( 'Aipatch Security', 'aipatch-security-scanner' ),
                'description' => __( 'Read-only security and malware-oriented audit tools for MCP agents.', 'aipatch-security-scanner' ),
            )
        );
    }

    /**
     * Register all abilities.
     */
    public function register_abilities() {
        if ( ! function_exists( 'wp_register_ability' ) ) {
            return;
        }

        if ( $this->is_ability_enabled( 'aipatch/audit-site' ) ) {
            $this->register_site_audit_ability( 'aipatch/audit-site', __( 'Audit Site', 'aipatch-security-scanner' ), __( 'Runs a full site security audit and returns a structured report for external AI agents.', 'aipatch-security-scanner' ) );
        }

        if ( $this->is_ability_enabled( 'aipatch/audit-suspicious' ) ) {
            $this->register_suspicious_audit_ability( 'aipatch/audit-suspicious', __( 'Audit Suspicious Files', 'aipatch-security-scanner' ), __( 'Scans for suspicious files and returns indicators for deep analysis by an external AI agent.', 'aipatch-security-scanner' ) );
        }

        if ( $this->is_ability_enabled( 'aipatch/get-async-job-status' ) ) {
            $this->register_async_status_ability();
        }

        $this->register_new_abilities();
    }

    /**
     * Check whether an ability is enabled in plugin settings.
     *
     * @param string $ability_name Full ability name.
     * @return bool
     */
    private function is_ability_enabled( $ability_name ) {
        $ability_name = sanitize_text_field( (string) $ability_name );
        $name_map     = array_flip( AIPSC_Utils::get_ability_settings_map() );

        if ( ! isset( $name_map[ $ability_name ] ) ) {
            return true;
        }

        $settings = AIPSC_Utils::get_settings();
        $enabled  = isset( $settings['abilities_enabled'] ) && is_array( $settings['abilities_enabled'] )
            ? $settings['abilities_enabled']
            : array();

        return ! empty( $enabled[ $name_map[ $ability_name ] ] );
    }

    /**
     * Permission callback for read-only abilities.
     *
     * @return bool|WP_Error
     */
    public function can_run_readonly_abilities() {
        $capability = apply_filters( 'aipatch_abilities_required_capability', 'manage_options' );

        if ( current_user_can( $capability ) ) {
            return true;
        }

        return new WP_Error(
            'aipatch_ability_forbidden',
            __( 'You do not have permission to run this ability.', 'aipatch-security-scanner' ),
            array( 'status' => 403 )
        );
    }

    /**
     * Execute callback for the site audit ability.
     *
     * @param array $input Ability input.
     * @return array|WP_Error
     */
    public function execute_audit_site( $input = array() ) {
        $input = is_array( $input ) ? $input : array();
        $async = isset( $input['async'] ) ? rest_sanitize_boolean( $input['async'] ) : false;

        if ( $async ) {
            unset( $input['async'] );
            return $this->enqueue_async_job( 'audit-site', $input );
        }

        return $this->run_audit_site_sync( $input );
    }

    /**
     * Execute callback for suspicious-file audit ability.
     *
     * @param array $input Ability input.
     * @return array|WP_Error
     */
    public function execute_audit_suspicious( $input = array() ) {
        $input = is_array( $input ) ? $input : array();
        $async = isset( $input['async'] ) ? rest_sanitize_boolean( $input['async'] ) : false;

        if ( $async ) {
            unset( $input['async'] );
            return $this->enqueue_async_job( 'audit-suspicious', $input );
        }

        return $this->run_audit_suspicious_sync( $input );
    }

    /**
     * Execute callback for async status ability.
     *
     * @param array $input Ability input.
     * @return array|WP_Error
     */
    public function execute_get_async_job_status( $input = array() ) {
        $input = is_array( $input ) ? $input : array();
        $job_id = isset( $input['job_id'] ) ? sanitize_text_field( $input['job_id'] ) : '';

        if ( '' === $job_id ) {
            return new WP_Error(
                'aipatch_missing_job_id',
                __( 'job_id is required.', 'aipatch-security-scanner' ),
                array( 'status' => 400 )
            );
        }

        $job = $this->get_async_job( $job_id );
        if ( ! is_array( $job ) ) {
            return new WP_Error(
                'aipatch_job_not_found',
                __( 'Async job not found or expired.', 'aipatch-security-scanner' ),
                array( 'status' => 404 )
            );
        }

        return array(
            'success'         => true,
            'async'           => true,
            'job_id'          => $job['job_id'],
            'job_type'        => $job['job_type'],
            'status'          => $job['status'],
            'created_at_gmt'  => $job['created_at_gmt'],
            'updated_at_gmt'  => $job['updated_at_gmt'],
            'error'           => $job['error'],
            'has_result'      => ! empty( $job['result'] ),
            'result'          => $job['result'],
        );
    }

    /**
     * Execute a site audit synchronously.
     *
     * @param array $input Ability input.
     * @return array|WP_Error
     */
    private function run_audit_site_sync( $input = array() ) {
        if ( ! $this->scanner ) {
            return new WP_Error(
                'aipatch_scanner_disabled',
                __( 'Scanner module is disabled.', 'aipatch-security-scanner' ),
                array( 'status' => 400 )
            );
        }

        $refresh_scan           = isset( $input['refresh_scan'] ) ? rest_sanitize_boolean( $input['refresh_scan'] ) : true;
        $include_dismissed      = isset( $input['include_dismissed'] ) ? rest_sanitize_boolean( $input['include_dismissed'] ) : false;
        $include_vulnerabilities = isset( $input['include_vulnerabilities'] ) ? rest_sanitize_boolean( $input['include_vulnerabilities'] ) : true;
        $include_summary        = isset( $input['include_summary'] ) ? rest_sanitize_boolean( $input['include_summary'] ) : true;

        $scan = $refresh_scan
            ? $this->scanner->run_full_scan( 'ability_audit_site' )
            : $this->scanner->get_last_results();

        if ( ! $scan ) {
            $scan = $this->scanner->run_full_scan( 'ability_audit_site' );
        }

        $dismissed = AIPSC_Utils::get_option( 'dismissed', array() );
        $issues    = isset( $scan['issues'] ) && is_array( $scan['issues'] ) ? $scan['issues'] : array();

        if ( ! $include_dismissed ) {
            $issues = array_values( array_filter( $issues, function ( $issue ) use ( $dismissed ) {
                return ! isset( $dismissed[ $issue['id'] ] );
            } ) );
        }

        usort( $issues, function ( $a, $b ) {
            return AIPSC_Utils::severity_weight( $b['severity'] ) - AIPSC_Utils::severity_weight( $a['severity'] );
        } );

        $severity_map = array(
            'critical' => 0,
            'high'     => 0,
            'medium'   => 0,
            'low'      => 0,
            'info'     => 0,
        );

        foreach ( $issues as $issue ) {
            $severity = isset( $issue['severity'] ) ? sanitize_key( $issue['severity'] ) : 'low';
            if ( ! isset( $severity_map[ $severity ] ) ) {
                $severity_map[ $severity ] = 0;
            }
            $severity_map[ $severity ]++;
        }

        $response = array(
            'success'          => true,
            'generated_at_gmt' => gmdate( 'c' ),
            'scan_mode'        => $refresh_scan ? 'fresh' : 'cached',
            'score'            => isset( $scan['score'] ) ? (int) $scan['score'] : 0,
            'issues_count'     => count( $issues ),
            'issues_by_severity' => $severity_map,
            'issues'           => $issues,
            'site'             => array(
                'home_url'    => home_url( '/' ),
                'wp_version'  => get_bloginfo( 'version' ),
                'php_version' => PHP_VERSION,
                'is_ssl'      => is_ssl(),
            ),
            'hardening'        => AIPSC_Utils::get_hardening(),
        );

        if ( $include_summary ) {
            $response['summary'] = $this->scanner->get_summary();
        }

        if ( $include_vulnerabilities ) {
            $vulns = $this->vulnerabilities ? $this->vulnerabilities->get_all_vulnerabilities() : array();
            $response['vulnerabilities'] = $vulns;
            $response['vulnerabilities_count'] = count( $vulns );
        }

        $this->logger->info(
            'ability_audit_site',
            __( 'Site audit ability executed.', 'aipatch-security-scanner' ),
            array(
                'scan_mode'    => $response['scan_mode'],
                'score'        => $response['score'],
                'issues_count' => $response['issues_count'],
            )
        );

        return $response;
    }

    /**
     * Execute suspicious-file audit synchronously.
     *
     * @param array $input Ability input.
     * @return array|WP_Error
     */
    private function run_audit_suspicious_sync( $input = array() ) {
        $input = is_array( $input ) ? $input : array();

        $scope         = isset( $input['scope'] ) ? sanitize_key( $input['scope'] ) : 'uploads';
        $max_files     = isset( $input['max_files'] ) ? absint( $input['max_files'] ) : 25;
        $max_file_size = isset( $input['max_file_size'] ) ? absint( $input['max_file_size'] ) : 262144;
        $with_hashes   = isset( $input['with_hashes'] ) ? rest_sanitize_boolean( $input['with_hashes'] ) : true;
        $with_excerpt  = isset( $input['with_excerpt'] ) ? rest_sanitize_boolean( $input['with_excerpt'] ) : false;

        $max_files     = max( 1, min( 200, $max_files ) );
        $max_file_size = max( 4096, min( 1048576, $max_file_size ) );

        $scan = $this->scan_suspicious_files(
            $scope,
            $max_files,
            $max_file_size,
            $with_hashes,
            $with_excerpt
        );

        $this->logger->warning(
            'ability_audit_suspicious',
            __( 'Suspicious file audit ability executed.', 'aipatch-security-scanner' ),
            array(
                'scope'      => $scan['scope'],
                'found'      => $scan['suspicious_count'],
                'scanned'    => $scan['scanned_files'],
                'truncated'  => $scan['truncated'],
            )
        );

        return $scan;
    }

    /**
     * Handle asynchronous ability jobs.
     *
     * @param string $job_id   Async job id.
     * @param string $job_type audit-site|audit-suspicious.
     * @param array  $input    Original ability input.
     */
    public function handle_async_ability_job( $job_id, $job_type, $input = array() ) {
        $job = $this->get_async_job( $job_id );
        if ( ! is_array( $job ) ) {
            return;
        }

        $job['status']         = 'running';
        $job['updated_at_gmt'] = gmdate( 'c' );
        $this->set_async_job( $job_id, $job );

        try {
            if ( 'audit-site' === $job_type ) {
                $result = $this->run_audit_site_sync( is_array( $input ) ? $input : array() );
            } elseif ( 'audit-suspicious' === $job_type ) {
                $result = $this->run_audit_suspicious_sync( is_array( $input ) ? $input : array() );
            } else {
                throw new Exception( __( 'Unknown async job type.', 'aipatch-security-scanner' ) );
            }

            if ( is_wp_error( $result ) ) {
                throw new Exception( $result->get_error_message() );
            }

            $job['status'] = 'completed';
            $job['result'] = $result;
            $job['error']  = null;
        } catch ( Throwable $error ) {
            $job['status'] = 'failed';
            $job['result'] = null;
            $job['error']  = $error->getMessage();

            $this->logger->error(
                'ability_async_job_failed',
                __( 'Async ability job failed.', 'aipatch-security-scanner' ),
                array(
                    'job_id'   => $job_id,
                    'job_type' => $job_type,
                    'error'    => $job['error'],
                )
            );
        }

        $job['updated_at_gmt'] = gmdate( 'c' );
        $this->set_async_job( $job_id, $job );
    }

    /**
    * Register audit-site ability.
     *
     * @param string $name        Ability name.
     * @param string $label       Human label.
     * @param string $description Human description.
     */
    private function register_site_audit_ability( $name, $label, $description ) {
        $result = call_user_func(
            'wp_register_ability',
            $name,
            array(
                'label'               => $label,
                'description'         => $description,
                'category'            => 'aipatch-security',
                'input_schema'        => array(
                    'type'       => 'object',
                    'properties' => array(
                        'refresh_scan' => array(
                            'type'        => 'boolean',
                            'description' => __( 'If true, run a fresh scan before returning results.', 'aipatch-security-scanner' ),
                            'default'     => true,
                        ),
                        'include_dismissed' => array(
                            'type'        => 'boolean',
                            'description' => __( 'If true, include dismissed issues in the report.', 'aipatch-security-scanner' ),
                            'default'     => false,
                        ),
                        'include_vulnerabilities' => array(
                            'type'        => 'boolean',
                            'description' => __( 'If true, include vulnerability provider results.', 'aipatch-security-scanner' ),
                            'default'     => true,
                        ),
                        'include_summary' => array(
                            'type'        => 'boolean',
                            'description' => __( 'If true, include dashboard summary metrics.', 'aipatch-security-scanner' ),
                            'default'     => true,
                        ),
                        'async' => array(
                            'type'        => 'boolean',
                            'description' => __( 'Queue this audit in background and return a job_id.', 'aipatch-security-scanner' ),
                            'default'     => false,
                        ),
                    ),
                ),
                'output_schema'       => array(
                    'type' => 'object',
                ),
                'execute_callback'    => array( $this, 'execute_audit_site' ),
                'permission_callback' => array( $this, 'can_run_readonly_abilities' ),
                'meta'                => array(
                    'show_in_rest' => true,
                    'mcp'          => array(
                        'public'   => true,
                        'type'     => 'tool',
                        'readonly' => true,
                    ),
                ),
            )
        );

        if ( is_wp_error( $result ) ) {
            $this->logger->warning(
                'ability_register_failed',
                sprintf(
                    /* translators: 1: Ability name, 2: Error message. */
                    __( 'Failed to register ability %1$s: %2$s', 'aipatch-security-scanner' ),
                    $name,
                    $result->get_error_message()
                )
            );
        }
    }

    /**
        * Register audit-suspicious ability.
     *
     * @param string $name        Ability name.
     * @param string $label       Human label.
     * @param string $description Human description.
     */
    private function register_suspicious_audit_ability( $name, $label, $description ) {
        $result = call_user_func(
            'wp_register_ability',
            $name,
            array(
                'label'               => $label,
                'description'         => $description,
                'category'            => 'aipatch-security',
                'input_schema'        => array(
                    'type'       => 'object',
                    'properties' => array(
                        'scope' => array(
                            'type'        => 'string',
                            'description' => __( 'Scan scope: uploads, plugins, themes, or all.', 'aipatch-security-scanner' ),
                            'enum'        => array( 'uploads', 'plugins', 'themes', 'all' ),
                            'default'     => 'uploads',
                        ),
                        'max_files' => array(
                            'type'        => 'integer',
                            'description' => __( 'Maximum suspicious files to return (1-200).', 'aipatch-security-scanner' ),
                            'minimum'     => 1,
                            'maximum'     => 200,
                            'default'     => 25,
                        ),
                        'max_file_size' => array(
                            'type'        => 'integer',
                            'description' => __( 'Maximum file size in bytes to inspect deeply.', 'aipatch-security-scanner' ),
                            'minimum'     => 4096,
                            'maximum'     => 1048576,
                            'default'     => 262144,
                        ),
                        'with_hashes' => array(
                            'type'        => 'boolean',
                            'description' => __( 'Include SHA-256 hashes in suspicious file results.', 'aipatch-security-scanner' ),
                            'default'     => true,
                        ),
                        'with_excerpt' => array(
                            'type'        => 'boolean',
                            'description' => __( 'Include a safe text excerpt for AI triage.', 'aipatch-security-scanner' ),
                            'default'     => false,
                        ),
                        'async' => array(
                            'type'        => 'boolean',
                            'description' => __( 'Queue this scan in background and return a job_id.', 'aipatch-security-scanner' ),
                            'default'     => false,
                        ),
                    ),
                ),
                'output_schema'       => array(
                    'type' => 'object',
                ),
                'execute_callback'    => array( $this, 'execute_audit_suspicious' ),
                'permission_callback' => array( $this, 'can_run_readonly_abilities' ),
                'meta'                => array(
                    'show_in_rest' => true,
                    'mcp'          => array(
                        'public'   => true,
                        'type'     => 'tool',
                        'readonly' => true,
                    ),
                ),
            )
        );

        if ( is_wp_error( $result ) ) {
            $this->logger->warning(
                'ability_register_failed',
                sprintf(
                    /* translators: 1: Ability name, 2: Error message. */
                    __( 'Failed to register ability %1$s: %2$s', 'aipatch-security-scanner' ),
                    $name,
                    $result->get_error_message()
                )
            );
        }
    }

    /**
     * Register async status ability.
     */
    private function register_async_status_ability() {
        $result = call_user_func(
            'wp_register_ability',
            'aipatch/get-async-job-status',
            array(
                'label'               => __( 'Get Async Job Status', 'aipatch-security-scanner' ),
                'description'         => __( 'Returns status and result for asynchronous Aipatch abilities.', 'aipatch-security-scanner' ),
                'category'            => 'aipatch-security',
                'input_schema'        => array(
                    'type'       => 'object',
                    'properties' => array(
                        'job_id' => array(
                            'type'        => 'string',
                            'description' => __( 'Job id returned by an async ability call.', 'aipatch-security-scanner' ),
                        ),
                    ),
                    'required'   => array( 'job_id' ),
                ),
                'output_schema'       => array(
                    'type' => 'object',
                ),
                'execute_callback'    => array( $this, 'execute_get_async_job_status' ),
                'permission_callback' => array( $this, 'can_run_readonly_abilities' ),
                'meta'                => array(
                    'show_in_rest' => true,
                    'mcp'          => array(
                        'public'   => true,
                        'type'     => 'tool',
                        'readonly' => true,
                    ),
                ),
            )
        );

        if ( is_wp_error( $result ) ) {
            $this->logger->warning(
                'ability_register_failed',
                sprintf(
                    /* translators: 1: Ability name, 2: Error message. */
                    __( 'Failed to register ability %1$s: %2$s', 'aipatch-security-scanner' ),
                    'aipatch/get-async-job-status',
                    $result->get_error_message()
                )
            );
        }
    }

    /**
     * Enqueue an asynchronous ability job.
     *
     * @param string $job_type audit-site|audit-suspicious.
     * @param array  $input    Ability input.
     * @return array
     */
    private function enqueue_async_job( $job_type, $input ) {
        $job_id = function_exists( 'wp_generate_uuid4' ) ? wp_generate_uuid4() : uniqid( 'aipatch_', true );

        $job = array(
            'job_id'         => $job_id,
            'job_type'       => sanitize_key( $job_type ),
            'status'         => 'queued',
            'created_at_gmt' => gmdate( 'c' ),
            'updated_at_gmt' => gmdate( 'c' ),
            'input'          => is_array( $input ) ? $input : array(),
            'result'         => null,
            'error'          => null,
        );

        $this->set_async_job( $job_id, $job );

        wp_schedule_single_event(
            time() + 1,
            'aipatch_run_async_ability_job',
            array( $job_id, $job['job_type'], $job['input'] )
        );

        $this->logger->info(
            'ability_async_job_queued',
            __( 'Async ability job queued.', 'aipatch-security-scanner' ),
            array(
                'job_id'   => $job_id,
                'job_type' => $job['job_type'],
            )
        );

        return array(
            'success'        => true,
            'async'          => true,
            'job_id'         => $job_id,
            'status'         => 'queued',
            'job_type'       => $job['job_type'],
            'created_at_gmt' => $job['created_at_gmt'],
            'poll_ability'   => 'aipatch/get-async-job-status',
        );
    }

    /**
     * Get async job details.
     *
     * @param string $job_id Async job id.
     * @return array|false
     */
    private function get_async_job( $job_id ) {
        return get_transient( $this->get_async_job_key( $job_id ) );
    }

    /**
     * Store async job details.
     *
     * @param string $job_id Async job id.
     * @param array  $job    Job payload.
     */
    private function set_async_job( $job_id, $job ) {
        set_transient( $this->get_async_job_key( $job_id ), $job, DAY_IN_SECONDS );
    }

    /**
     * Build async job transient key.
     *
     * @param string $job_id Async job id.
     * @return string
     */
    private function get_async_job_key( $job_id ) {
        return 'aipatch_ability_job_' . md5( (string) $job_id );
    }

    /**
     * Scan selected directories for suspicious files.
     *
     * @param string $scope         uploads|plugins|themes|all.
     * @param int    $max_files     Max suspicious files to return.
     * @param int    $max_file_size Max size for deep content inspection.
     * @param bool   $with_hashes   Include SHA-256 hashes.
     * @param bool   $with_excerpt  Include content excerpt.
     * @return array
     */
    private function scan_suspicious_files( $scope, $max_files, $max_file_size, $with_hashes, $with_excerpt ) {
        $roots = $this->resolve_scan_roots( $scope );
        $scope = in_array( $scope, array( 'uploads', 'plugins', 'themes', 'all' ), true ) ? $scope : 'uploads';

        $results         = array();
        $scanned_files   = 0;
        $inspected_files = 0;
        $skipped_large   = 0;

        foreach ( $roots as $root ) {
            if ( ! is_dir( $root ) || ! is_readable( $root ) ) {
                continue;
            }

            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS )
                );
            } catch ( Exception $e ) {
                continue;
            }

            foreach ( $iterator as $file ) {
                if ( count( $results ) >= $max_files ) {
                    break 2;
                }

                if ( ! $file->isFile() ) {
                    continue;
                }

                $path = wp_normalize_path( $file->getPathname() );
                if ( $this->should_skip_path( $path ) ) {
                    continue;
                }

                $scanned_files++;
                $size = (int) $file->getSize();

                if ( $size > $max_file_size ) {
                    $skipped_large++;
                    continue;
                }

                $inspected_files++;

                $analysis = $this->analyze_file_for_suspicion( $path, $size, $scope, $with_excerpt );
                if ( empty( $analysis['reasons'] ) ) {
                    continue;
                }

                $entry = array(
                    'path'         => $analysis['path'],
                    'size'         => $size,
                    'modified_gmt' => gmdate( 'c', (int) $file->getMTime() ),
                    'risk_level'   => $this->map_reasons_to_risk( $analysis['reasons'] ),
                    'reasons'      => $analysis['reasons'],
                );

                if ( $with_hashes ) {
                    $entry['sha256'] = hash_file( 'sha256', $path );
                }

                if ( $with_excerpt && ! empty( $analysis['excerpt'] ) ) {
                    $entry['excerpt'] = $analysis['excerpt'];
                }

                $results[] = $entry;
            }
        }

        return array(
            'success'          => true,
            'generated_at_gmt' => gmdate( 'c' ),
            'scope'            => $scope,
            'suspicious_count' => count( $results ),
            'scanned_files'    => $scanned_files,
            'inspected_files'  => $inspected_files,
            'skipped_large'    => $skipped_large,
            'max_files'        => $max_files,
            'truncated'        => count( $results ) >= $max_files,
            'items'            => $results,
        );
    }

    /**
     * Return scan roots based on scope.
     *
     * @param string $scope Scope.
     * @return array
     */
    private function resolve_scan_roots( $scope ) {
        $uploads = wp_upload_dir();
        $roots   = array();

        if ( 'uploads' === $scope || 'all' === $scope ) {
            if ( ! empty( $uploads['basedir'] ) ) {
                $roots[] = wp_normalize_path( $uploads['basedir'] );
            }
        }

        if ( 'plugins' === $scope || 'all' === $scope ) {
            $roots[] = wp_normalize_path( WP_PLUGIN_DIR );
        }

        if ( 'themes' === $scope || 'all' === $scope ) {
            $roots[] = wp_normalize_path( get_theme_root() );
        }

        if ( empty( $roots ) ) {
            if ( ! empty( $uploads['basedir'] ) ) {
                $roots[] = wp_normalize_path( $uploads['basedir'] );
            }
        }

        return array_values( array_unique( $roots ) );
    }

    /**
     * Decide if a path should be skipped in suspicious-file scans.
     *
     * @param string $path Absolute path.
     * @return bool
     */
    private function should_skip_path( $path ) {
        $skip_fragments = array(
            '/node_modules/',
            '/vendor/',
            '/.git/',
            '/cache/',
            '/upgrade/',
            '/languages/',
        );

        foreach ( $skip_fragments as $fragment ) {
            if ( false !== strpos( $path, $fragment ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Analyze one file for suspicious indicators.
     *
     * @param string $path         Absolute path.
     * @param int    $size         File size.
     * @param string $scope        Scan scope.
     * @param bool   $with_excerpt Include excerpt.
     * @return array
     */
    private function analyze_file_for_suspicion( $path, $size, $scope, $with_excerpt ) {
        $reasons   = array();
        $filename  = strtolower( basename( $path ) );
        $extension = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
        $relative  = $this->to_relative_path( $path );

        $php_extensions = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phar' );

        if ( in_array( $extension, $php_extensions, true ) && false !== strpos( $relative, 'wp-content/uploads/' ) ) {
            $reasons[] = 'php_file_in_uploads';
        }

        if ( preg_match( '/(shell|backdoor|wso|c99|r57|b374k|cmd|mini|mailer)/i', $filename ) ) {
            $reasons[] = 'suspicious_filename_pattern';
        }

        if ( in_array( $extension, array( 'ico', 'jpg', 'jpeg', 'png', 'gif', 'txt' ), true ) ) {
            $head = @file_get_contents( $path, false, null, 0, 256 );
            if ( is_string( $head ) && false !== stripos( $head, '<?php' ) ) {
                $reasons[] = 'code_hidden_in_non_php_extension';
            }
        }

        $content = @file_get_contents( $path, false, null, 0, min( 65536, $size ) );
        if ( is_string( $content ) ) {
            if ( preg_match( '/eval\s*\(\s*base64_decode\s*\(/i', $content ) ) {
                $reasons[] = 'obfuscated_eval_base64';
            }

            if ( preg_match( '/(gzinflate\s*\(|str_rot13\s*\(|assert\s*\(\s*\$_(POST|REQUEST|GET))/i', $content ) ) {
                $reasons[] = 'obfuscated_or_dangerous_runtime_pattern';
            }

            if ( preg_match( '/preg_replace\s*\(\s*["\'].*\/e["\']/i', $content ) ) {
                $reasons[] = 'deprecated_preg_replace_e_modifier';
            }
        }

        $reasons = array_values( array_unique( $reasons ) );
        $excerpt = '';

        if ( $with_excerpt && ! empty( $reasons ) && is_string( $content ) ) {
            $excerpt = $this->build_excerpt( $content );
        }

        return array(
            'path'    => $relative,
            'reasons' => $reasons,
            'excerpt' => $excerpt,
        );
    }

    /**
     * Convert absolute path to a stable relative path.
     *
     * @param string $path Absolute path.
     * @return string
     */
    private function to_relative_path( $path ) {
        $path    = wp_normalize_path( $path );
        $abspath = wp_normalize_path( ABSPATH );

        if ( 0 === strpos( $path, $abspath ) ) {
            return ltrim( substr( $path, strlen( $abspath ) ), '/' );
        }

        return $path;
    }

    /**
     * Build a short safe text excerpt from file content.
     *
     * @param string $content Raw content chunk.
     * @return string
     */
    private function build_excerpt( $content ) {
        $excerpt = str_replace( array( "\r", "\0" ), '', $content );
        $excerpt = substr( $excerpt, 0, 500 );
        $excerpt = preg_replace( '/[^\x09\x0A\x0D\x20-\x7E]/', '?', $excerpt );

        return trim( $excerpt );
    }

    /**
     * Map reason list to a coarse risk level.
     *
     * @param array $reasons Suspicion reasons.
     * @return string
     */
    private function map_reasons_to_risk( $reasons ) {
        $critical_reasons = array(
            'obfuscated_eval_base64',
            'obfuscated_or_dangerous_runtime_pattern',
            'php_file_in_uploads',
        );

        foreach ( $critical_reasons as $critical ) {
            if ( in_array( $critical, $reasons, true ) ) {
                return 'high';
            }
        }

        if ( in_array( 'code_hidden_in_non_php_extension', $reasons, true ) ) {
            return 'medium';
        }

        return 'low';
    }

    /**
     * Check if Abilities API is available on this WordPress install.
     *
     * @return bool
     */
    private function is_abilities_api_available() {
        return function_exists( 'wp_register_ability' )
            && function_exists( 'wp_register_ability_category' );
    }

    /* ---------------------------------------------------------------
     * New MCP Abilities (Block 8)
     * ------------------------------------------------------------- */

    /**
     * Register abilities for new modules (findings, file scanner, baseline, jobs).
     */
    private function register_new_abilities() {
        if ( ! function_exists( 'wp_register_ability' ) ) {
            return;
        }

        $abilities = array(
            array(
                'name'        => 'aipatch/list-findings',
                'label'       => __( 'List Findings', 'aipatch-security-scanner' ),
                'description' => __( 'Query persistent security findings with filters.', 'aipatch-security-scanner' ),
                'input'       => array(
                    'status'   => array( 'type' => 'string', 'enum' => array( 'open', 'dismissed', 'resolved' ), 'default' => 'open' ),
                    'severity' => array( 'type' => 'string', 'enum' => array( 'critical', 'high', 'medium', 'low', 'info' ) ),
                    'category' => array( 'type' => 'string' ),
                    'limit'    => array( 'type' => 'integer', 'default' => 50, 'minimum' => 1, 'maximum' => 200 ),
                ),
                'callback'    => 'execute_list_findings',
            ),
            array(
                'name'        => 'aipatch/findings-stats',
                'label'       => __( 'Findings Statistics', 'aipatch-security-scanner' ),
                'description' => __( 'Returns aggregate statistics for all persistent findings.', 'aipatch-security-scanner' ),
                'input'       => array(),
                'callback'    => 'execute_findings_stats',
            ),
            array(
                'name'        => 'aipatch/dismiss-finding',
                'label'       => __( 'Dismiss Finding', 'aipatch-security-scanner' ),
                'description' => __( 'Dismiss a specific finding by fingerprint (accepted risk).', 'aipatch-security-scanner' ),
                'input'       => array(
                    'fingerprint' => array( 'type' => 'string', 'description' => 'SHA-256 fingerprint of the finding.' ),
                ),
                'callback'    => 'execute_dismiss_finding',
                'readonly'    => false,
            ),
            array(
                'name'        => 'aipatch/start-file-scan',
                'label'       => __( 'Start File Scan', 'aipatch-security-scanner' ),
                'description' => __( 'Start an asynchronous malware/heuristic file scan job.', 'aipatch-security-scanner' ),
                'input'       => array(
                    'root'       => array( 'type' => 'string', 'description' => 'Scan root directory (must be inside ABSPATH). Default: ABSPATH.' ),
                    'max_files'  => array( 'type' => 'integer', 'default' => 10000 ),
                ),
                'callback'    => 'execute_start_file_scan',
            ),
            array(
                'name'        => 'aipatch/file-scan-progress',
                'label'       => __( 'File Scan Progress', 'aipatch-security-scanner' ),
                'description' => __( 'Get progress and status of a file scan job.', 'aipatch-security-scanner' ),
                'input'       => array(
                    'job_id' => array( 'type' => 'string', 'description' => 'Job UUID.' ),
                ),
                'callback'    => 'execute_file_scan_progress',
            ),
            array(
                'name'        => 'aipatch/file-scan-results',
                'label'       => __( 'File Scan Results', 'aipatch-security-scanner' ),
                'description' => __( 'Get results from a completed file scan job.', 'aipatch-security-scanner' ),
                'input'       => array(
                    'job_id'    => array( 'type' => 'string', 'description' => 'Job UUID.' ),
                    'min_risk'  => array( 'type' => 'integer', 'default' => 15, 'description' => 'Minimum risk score to include.' ),
                    'limit'     => array( 'type' => 'integer', 'default' => 100, 'minimum' => 1, 'maximum' => 500 ),
                ),
                'callback'    => 'execute_file_scan_results',
            ),
            array(
                'name'        => 'aipatch/process-file-scan-batch',
                'label'       => __( 'Process File Scan Batch', 'aipatch-security-scanner' ),
                'description' => __( 'Process the next batch of files for a running scan job. Call repeatedly until progress reaches 100.', 'aipatch-security-scanner' ),
                'input'       => array(
                    'job_id'     => array( 'type' => 'string', 'description' => 'Job UUID.' ),
                    'batch_size' => array( 'type' => 'integer', 'default' => 50, 'minimum' => 1, 'maximum' => 200 ),
                ),
                'callback'    => 'execute_process_file_scan_batch',
            ),
            array(
                'name'        => 'aipatch/baseline-build',
                'label'       => __( 'Build File Baseline', 'aipatch-security-scanner' ),
                'description' => __( 'Build or refresh the known-good file hash baseline.', 'aipatch-security-scanner' ),
                'input'       => array(),
                'callback'    => 'execute_baseline_build',
            ),
            array(
                'name'        => 'aipatch/baseline-diff',
                'label'       => __( 'Baseline Integrity Diff', 'aipatch-security-scanner' ),
                'description' => __( 'Compare current filesystem against the stored baseline to detect modified, missing, and new files.', 'aipatch-security-scanner' ),
                'input'       => array(),
                'callback'    => 'execute_baseline_diff',
            ),
            array(
                'name'        => 'aipatch/baseline-stats',
                'label'       => __( 'Baseline Statistics', 'aipatch-security-scanner' ),
                'description' => __( 'Returns statistics about the stored file baseline.', 'aipatch-security-scanner' ),
                'input'       => array(),
                'callback'    => 'execute_baseline_stats',
            ),
            array(
                'name'        => 'aipatch/list-jobs',
                'label'       => __( 'List Jobs', 'aipatch-security-scanner' ),
                'description' => __( 'List scan/audit jobs with optional filters.', 'aipatch-security-scanner' ),
                'input'       => array(
                    'job_type' => array( 'type' => 'string' ),
                    'status'   => array( 'type' => 'string' ),
                    'limit'    => array( 'type' => 'integer', 'default' => 20 ),
                ),
                'callback'    => 'execute_list_jobs',
            ),
            array(
                'name'        => 'aipatch/apply-remediation',
                'label'       => __( 'Apply Remediation', 'aipatch-security-scanner' ),
                'description' => __( 'Apply a security fix for a finding. Stores rollback data for undo capability.', 'aipatch-security-scanner' ),
                'input'       => array(
                    'finding_fingerprint' => array( 'type' => 'string', 'required' => true ),
                    'action_type'         => array( 'type' => 'string', 'required' => true, 'enum' => array( 'wp_option', 'delete_file', 'rename_file', 'file_patch', 'htaccess_rule', 'manual' ) ),
                    'description'         => array( 'type' => 'string' ),
                    'params'              => array( 'type' => 'object' ),
                ),
                'callback'    => 'execute_apply_remediation',
                'readonly'    => false,
            ),
            array(
                'name'        => 'aipatch/rollback-remediation',
                'label'       => __( 'Rollback Remediation', 'aipatch-security-scanner' ),
                'description' => __( 'Roll back a previously applied remediation and reopen the linked finding.', 'aipatch-security-scanner' ),
                'input'       => array(
                    'remediation_id' => array( 'type' => 'integer', 'required' => true ),
                ),
                'callback'    => 'execute_rollback_remediation',
                'readonly'    => false,
            ),
            array(
                'name'        => 'aipatch/list-remediations',
                'label'       => __( 'List Remediations', 'aipatch-security-scanner' ),
                'description' => __( 'List remediation records with optional filters.', 'aipatch-security-scanner' ),
                'input'       => array(
                    'finding_fingerprint' => array( 'type' => 'string' ),
                    'action_type'         => array( 'type' => 'string' ),
                    'status'              => array( 'type' => 'string' ),
                    'limit'               => array( 'type' => 'integer', 'default' => 50 ),
                    'offset'              => array( 'type' => 'integer', 'default' => 0 ),
                ),
                'callback'    => 'execute_list_remediations',
            ),
            array(
                'name'        => 'aipatch/findings-diff',
                'label'       => __( 'Findings Diff', 'aipatch-security-scanner' ),
                'description' => __( 'Compare findings since a point in time: new findings, resolved findings. Useful to see what changed between scans.', 'aipatch-security-scanner' ),
                'input'       => array(
                    'since'  => array( 'type' => 'string', 'description' => 'UTC datetime (Y-m-d H:i:s). Defaults to 24 hours ago.' ),
                    'source' => array( 'type' => 'string', 'description' => 'Filter by source: file_scanner, scanner, or empty for all.' ),
                ),
                'callback'    => 'execute_findings_diff',
            ),

            /* ── Phase 8: New enriched abilities ──────────────── */

            array(
                'name'        => 'aipatch/verify-core-integrity',
                'label'       => __( 'Verify Core Integrity', 'aipatch-security-scanner' ),
                'description' => __( 'Verify WordPress core files against official checksums from api.wordpress.org. Returns modified, missing, and unexpected files in core directories.', 'aipatch-security-scanner' ),
                'input'       => array(
                    'force_refresh' => array( 'type' => 'boolean', 'default' => false, 'description' => 'Force refresh of cached checksums.' ),
                ),
                'callback'    => 'execute_verify_core_integrity',
            ),
            array(
                'name'        => 'aipatch/list-suspicious-files',
                'label'       => __( 'List Suspicious Files', 'aipatch-security-scanner' ),
                'description' => __( 'Query file scan results filtered by minimum risk score and classification. Returns enriched data with family, reasons, integrity flags, and core tampering indicators.', 'aipatch-security-scanner' ),
                'input'       => array(
                    'min_risk'       => array( 'type' => 'integer', 'default' => 30, 'minimum' => 1, 'maximum' => 100, 'description' => 'Minimum risk score threshold.' ),
                    'classification' => array( 'type' => 'string', 'enum' => array( 'suspicious', 'risky', 'malicious' ), 'description' => 'Filter by classification level.' ),
                    'limit'          => array( 'type' => 'integer', 'default' => 50, 'minimum' => 1, 'maximum' => 200 ),
                ),
                'callback'    => 'execute_list_suspicious_files',
            ),
            array(
                'name'        => 'aipatch/get-file-finding-detail',
                'label'       => __( 'Get File Finding Detail', 'aipatch-security-scanner' ),
                'description' => __( 'Get detailed information about a specific finding by fingerprint, including decoded metadata with family classification, integrity flags, core tampering, and layer scores.', 'aipatch-security-scanner' ),
                'input'       => array(
                    'fingerprint' => array( 'type' => 'string', 'description' => 'SHA-256 fingerprint of the finding.' ),
                ),
                'callback'    => 'execute_get_file_finding_detail',
            ),
            array(
                'name'        => 'aipatch/get-scan-summary',
                'label'       => __( 'Get Scan Summary', 'aipatch-security-scanner' ),
                'description' => __( 'Get a comprehensive summary of the latest completed file scan job including scan statistics, classification breakdown, findings synchronization results, and core integrity status.', 'aipatch-security-scanner' ),
                'input'       => array(),
                'callback'    => 'execute_get_scan_summary',
            ),
            array(
                'name'        => 'aipatch/get-baseline-drift',
                'label'       => __( 'Get Baseline Drift', 'aipatch-security-scanner' ),
                'description' => __( 'Get a combined integrity report with baseline drift (modified, missing, new files) plus core integrity verification (tampered core files, unexpected core files).', 'aipatch-security-scanner' ),
                'input'       => array(
                    'include_core_check' => array( 'type' => 'boolean', 'default' => true, 'description' => 'Include WordPress core integrity verification.' ),
                ),
                'callback'    => 'execute_get_baseline_drift',
            ),
        );

        foreach ( $abilities as $ability ) {
            if ( ! $this->is_ability_enabled( $ability['name'] ) ) {
                continue;
            }

            $is_readonly = isset( $ability['readonly'] ) ? $ability['readonly'] : true;
            $result = call_user_func(
                'wp_register_ability',
                $ability['name'],
                array(
                    'label'               => $ability['label'],
                    'description'         => $ability['description'],
                    'category'            => 'aipatch-security',
                    'input_schema'        => array(
                        'type'       => 'object',
                        'properties' => $ability['input'],
                    ),
                    'output_schema'       => array( 'type' => 'object' ),
                    'execute_callback'    => array( $this, $ability['callback'] ),
                    'permission_callback' => array( $this, 'can_run_readonly_abilities' ),
                    'meta'                => array(
                        'show_in_rest' => true,
                        'mcp'          => array(
                            'public'   => true,
                            'type'     => 'tool',
                            'readonly' => $is_readonly,
                        ),
                    ),
                )
            );

            if ( is_wp_error( $result ) ) {
                $this->logger->warning(
                    'ability_register_failed',
                    sprintf( 'Failed to register %s: %s', $ability['name'], $result->get_error_message() )
                );
            }
        }
    }

    /* -- Execute callbacks for new abilities -- */

    /**
     * List persistent findings.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_list_findings( $input = array() ) {
        if ( ! $this->findings_store ) {
            return new WP_Error( 'aipatch_module_unavailable', 'Findings store not available.', array( 'status' => 400 ) );
        }
        $input = is_array( $input ) ? $input : array();

        $rows = $this->findings_store->query( array(
            'status'   => isset( $input['status'] ) ? sanitize_key( $input['status'] ) : 'open',
            'severity' => isset( $input['severity'] ) ? sanitize_key( $input['severity'] ) : '',
            'category' => isset( $input['category'] ) ? sanitize_text_field( $input['category'] ) : '',
            'limit'    => isset( $input['limit'] ) ? absint( $input['limit'] ) : 50,
        ) );

        return array( 'success' => true, 'count' => count( $rows ), 'findings' => $rows );
    }

    /**
     * Findings statistics.
     *
     * @return array|WP_Error
     */
    public function execute_findings_stats() {
        if ( ! $this->findings_store ) {
            return new WP_Error( 'aipatch_module_unavailable', 'Findings store not available.', array( 'status' => 400 ) );
        }
        return array( 'success' => true, 'stats' => $this->findings_store->stats() );
    }

    /**
     * Findings diff since a point in time.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_findings_diff( $input = array() ) {
        if ( ! $this->findings_store ) {
            return new WP_Error( 'aipatch_module_unavailable', 'Findings store not available.', array( 'status' => 400 ) );
        }
        $input  = is_array( $input ) ? $input : array();
        $since  = isset( $input['since'] ) ? sanitize_text_field( $input['since'] ) : '';
        $source = isset( $input['source'] ) ? sanitize_key( $input['source'] ) : '';

        if ( empty( $since ) ) {
            $since = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
        }

        $diff = $this->findings_store->diff_since( $since, $source );

        return array(
            'success' => true,
            'since'   => $since,
            'source'  => $source,
            'new'     => array(
                'count'    => count( $diff['new'] ),
                'findings' => $diff['new'],
            ),
            'resolved' => array(
                'count'    => count( $diff['resolved'] ),
                'findings' => $diff['resolved'],
            ),
        );
    }

    /**
     * Dismiss a finding.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_dismiss_finding( $input = array() ) {
        if ( ! $this->findings_store ) {
            return new WP_Error( 'aipatch_module_unavailable', 'Findings store not available.', array( 'status' => 400 ) );
        }
        $input = is_array( $input ) ? $input : array();
        $fp    = isset( $input['fingerprint'] ) ? sanitize_text_field( $input['fingerprint'] ) : '';
        if ( empty( $fp ) ) {
            return new WP_Error( 'aipatch_missing_param', 'fingerprint is required.', array( 'status' => 400 ) );
        }

        $dismissed = $this->findings_store->dismiss( $fp );
        return array( 'success' => $dismissed, 'fingerprint' => $fp );
    }

    /**
     * Start a file scan job.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_start_file_scan( $input = array() ) {
        if ( ! $this->file_scanner ) {
            return new WP_Error( 'aipatch_module_unavailable', 'File scanner not available.', array( 'status' => 400 ) );
        }
        $input   = is_array( $input ) ? $input : array();
        $options = array();

        if ( isset( $input['root'] ) && '' !== trim( (string) $input['root'] ) ) {
            $root = $this->sanitize_scan_root( $input['root'] );
            if ( is_wp_error( $root ) ) {
                return $root;
            }

            $options['root'] = $root;
        }

        if ( ! empty( $input['max_files'] ) ) {
            $options['max_files'] = absint( $input['max_files'] );
        }

        $job_id = $this->file_scanner->start( $options );
        if ( ! $job_id ) {
            return new WP_Error( 'aipatch_scan_start_failed', 'Failed to start file scan.', array( 'status' => 500 ) );
        }

        return array(
            'success' => true,
            'job_id'  => $job_id,
            'message' => 'File scan job created. Use aipatch/process-file-scan-batch to advance.',
        );
    }

    /**
     * Validate and normalize file scan root input.
     *
     * @param string $root Raw root input.
     * @return string|WP_Error
     */
    private function sanitize_scan_root( $root ) {
        $root = trim( (string) $root );
        if ( '' === $root ) {
            return new WP_Error( 'aipatch_invalid_root', 'root cannot be empty.', array( 'status' => 400 ) );
        }

        // If root is relative, resolve it from ABSPATH.
        if ( ! preg_match( '#^(?:[A-Za-z]:)?[\\/]+#', $root ) ) {
            $root = ABSPATH . ltrim( str_replace( '\\', '/', $root ), '/' );
        }

        $root_resolved = realpath( $root );
        if ( false === $root_resolved || ! is_dir( $root_resolved ) || ! is_readable( $root_resolved ) ) {
            return new WP_Error( 'aipatch_invalid_root', 'root must be a readable directory.', array( 'status' => 400 ) );
        }

        $root_resolved = wp_normalize_path( $root_resolved );

        $wp_root = realpath( ABSPATH );
        if ( false === $wp_root ) {
            return new WP_Error( 'aipatch_root_unavailable', 'Could not resolve WordPress root.', array( 'status' => 500 ) );
        }

        $wp_root      = wp_normalize_path( $wp_root );
        $wp_root_base = trailingslashit( $wp_root );

        if ( $root_resolved !== $wp_root && 0 !== strpos( trailingslashit( $root_resolved ), $wp_root_base ) ) {
            return new WP_Error( 'aipatch_root_outside', 'root must be inside WordPress root.', array( 'status' => 400 ) );
        }

        return $root_resolved;
    }

    /**
     * Get file scan progress.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_file_scan_progress( $input = array() ) {
        if ( ! $this->job_manager ) {
            return new WP_Error( 'aipatch_module_unavailable', 'Job manager not available.', array( 'status' => 400 ) );
        }
        $input  = is_array( $input ) ? $input : array();
        $job_id = isset( $input['job_id'] ) ? sanitize_text_field( $input['job_id'] ) : '';
        if ( empty( $job_id ) ) {
            return new WP_Error( 'aipatch_missing_param', 'job_id is required.', array( 'status' => 400 ) );
        }

        $summary = $this->job_manager->summary( $job_id );
        if ( ! $summary ) {
            return new WP_Error( 'aipatch_job_not_found', 'Job not found.', array( 'status' => 404 ) );
        }

        return array( 'success' => true, 'job' => $summary );
    }

    /**
     * Get file scan results.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_file_scan_results( $input = array() ) {
        if ( ! $this->file_scanner ) {
            return new WP_Error( 'aipatch_module_unavailable', 'File scanner not available.', array( 'status' => 400 ) );
        }
        $input  = is_array( $input ) ? $input : array();
        $job_id = isset( $input['job_id'] ) ? sanitize_text_field( $input['job_id'] ) : '';
        if ( empty( $job_id ) ) {
            return new WP_Error( 'aipatch_missing_param', 'job_id is required.', array( 'status' => 400 ) );
        }

        $raw = $this->file_scanner->get_results( $job_id, array(
            'min_risk' => isset( $input['min_risk'] ) ? absint( $input['min_risk'] ) : 15,
            'limit'    => isset( $input['limit'] ) ? absint( $input['limit'] ) : 100,
        ) );

        // Enrich each result row by decoding signals_json.
        $enriched = array();
        if ( ! empty( $raw['results'] ) && is_array( $raw['results'] ) ) {
            foreach ( $raw['results'] as $row ) {
                $item = array(
                    'file_path'      => isset( $row->file_path ) ? $row->file_path : '',
                    'risk_score'     => isset( $row->risk_score ) ? (int) $row->risk_score : 0,
                    'classification' => isset( $row->classification ) ? $row->classification : '',
                    'sha256'         => isset( $row->sha256 ) ? $row->sha256 : '',
                    'file_size'      => isset( $row->file_size ) ? (int) $row->file_size : 0,
                    'scanned_at'     => isset( $row->scanned_at ) ? $row->scanned_at : '',
                );

                $decoded = ! empty( $row->signals_json ) ? json_decode( $row->signals_json, true ) : array();
                if ( is_array( $decoded ) ) {
                    $item['family']             = isset( $decoded['family'] ) ? $decoded['family'] : '';
                    $item['family_label']       = isset( $decoded['family_label'] ) ? $decoded['family_label'] : '';
                    $item['family_confidence']  = isset( $decoded['family_confidence'] ) ? $decoded['family_confidence'] : '';
                    $item['risk_level']         = isset( $decoded['risk_level'] ) ? $decoded['risk_level'] : '';
                    $item['reasons']            = isset( $decoded['reasons'] ) ? $decoded['reasons'] : array();
                    $item['matched_rules']      = isset( $decoded['matched_rules'] ) ? $decoded['matched_rules'] : array();
                    $item['context_flags']      = isset( $decoded['context_flags'] ) ? $decoded['context_flags'] : array();
                    $item['integrity_flags']    = isset( $decoded['integrity_flags'] ) ? $decoded['integrity_flags'] : array();
                    $item['layer_scores']       = isset( $decoded['layer_scores'] ) ? $decoded['layer_scores'] : array();
                    $item['remediation_hint']   = isset( $decoded['remediation_hint'] ) ? $decoded['remediation_hint'] : '';
                    $item['core_tampered']      = ! empty( $decoded['core_tampered'] );
                    $item['unexpected_in_core'] = ! empty( $decoded['unexpected_in_core'] );
                    $item['core_checksum']      = isset( $decoded['core_checksum'] ) ? $decoded['core_checksum'] : '';
                    $item['is_new']             = ! empty( $decoded['is_new'] );
                    $item['is_modified']        = ! empty( $decoded['is_modified'] );
                }

                $enriched[] = $item;
            }
        }

        return array(
            'success' => true,
            'data'    => array(
                'job'     => isset( $raw['job'] ) ? $raw['job'] : null,
                'results' => $enriched,
                'stats'   => isset( $raw['stats'] ) ? $raw['stats'] : array(),
            ),
        );
    }

    /**
     * Process next batch of a file scan.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_process_file_scan_batch( $input = array() ) {
        if ( ! $this->file_scanner ) {
            return new WP_Error( 'aipatch_module_unavailable', 'File scanner not available.', array( 'status' => 400 ) );
        }
        $input      = is_array( $input ) ? $input : array();
        $job_id     = isset( $input['job_id'] ) ? sanitize_text_field( $input['job_id'] ) : '';
        $batch_size = isset( $input['batch_size'] ) ? absint( $input['batch_size'] ) : 50;

        if ( empty( $job_id ) ) {
            return new WP_Error( 'aipatch_missing_param', 'job_id is required.', array( 'status' => 400 ) );
        }

        $processed = $this->file_scanner->process_batch( $job_id, $batch_size );
        $summary   = $this->job_manager ? $this->job_manager->summary( $job_id ) : null;

        return array(
            'success'   => true,
            'processed' => $processed,
            'job'       => $summary,
        );
    }

    /**
     * Build file baseline.
     *
     * @return array|WP_Error
     */
    public function execute_baseline_build() {
        if ( ! $this->file_baseline ) {
            return new WP_Error( 'aipatch_module_unavailable', 'File baseline not available.', array( 'status' => 400 ) );
        }

        $stats = $this->file_baseline->build();
        return array( 'success' => true, 'build_stats' => $stats, 'baseline_stats' => $this->file_baseline->stats() );
    }

    /**
     * Baseline integrity diff.
     *
     * @return array|WP_Error
     */
    public function execute_baseline_diff() {
        if ( ! $this->file_baseline ) {
            return new WP_Error( 'aipatch_module_unavailable', 'File baseline not available.', array( 'status' => 400 ) );
        }

        $diff = $this->file_baseline->diff();
        return array(
            'success'         => true,
            'modified_count'  => count( $diff['modified'] ),
            'missing_count'   => count( $diff['missing'] ),
            'new_count'       => count( $diff['new'] ),
            'diff'            => $diff,
        );
    }

    /**
     * Baseline statistics.
     *
     * @return array|WP_Error
     */
    public function execute_baseline_stats() {
        if ( ! $this->file_baseline ) {
            return new WP_Error( 'aipatch_module_unavailable', 'File baseline not available.', array( 'status' => 400 ) );
        }
        return array( 'success' => true, 'stats' => $this->file_baseline->stats() );
    }

    /**
     * List jobs.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_list_jobs( $input = array() ) {
        if ( ! $this->job_manager ) {
            return new WP_Error( 'aipatch_module_unavailable', 'Job manager not available.', array( 'status' => 400 ) );
        }
        $input = is_array( $input ) ? $input : array();

        $jobs = $this->job_manager->list_jobs( array(
            'job_type' => isset( $input['job_type'] ) ? sanitize_key( $input['job_type'] ) : '',
            'status'   => isset( $input['status'] ) ? sanitize_key( $input['status'] ) : '',
            'limit'    => isset( $input['limit'] ) ? absint( $input['limit'] ) : 20,
        ) );

        return array( 'success' => true, 'count' => count( $jobs ), 'jobs' => $jobs );
    }

    /* ---------------------------------------------------------------
     * Remediation callbacks
     * ------------------------------------------------------------- */

    /**
     * Apply a remediation.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_apply_remediation( $input = array() ) {
        if ( ! $this->remediation_engine ) {
            return new WP_Error( 'aipatch_module_unavailable', 'Remediation engine not available.', array( 'status' => 400 ) );
        }
        $input = is_array( $input ) ? $input : array();

        $result = $this->remediation_engine->apply( array(
            'finding_fingerprint' => isset( $input['finding_fingerprint'] ) ? $input['finding_fingerprint'] : '',
            'action_type'         => isset( $input['action_type'] ) ? $input['action_type'] : '',
            'description'         => isset( $input['description'] ) ? $input['description'] : '',
            'params'              => isset( $input['params'] ) && is_array( $input['params'] ) ? $input['params'] : array(),
        ) );

        if ( is_wp_error( $result ) ) {
            return $result;
        }

        return array( 'success' => true, 'remediation' => $result );
    }

    /**
     * Roll back a remediation.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_rollback_remediation( $input = array() ) {
        if ( ! $this->remediation_engine ) {
            return new WP_Error( 'aipatch_module_unavailable', 'Remediation engine not available.', array( 'status' => 400 ) );
        }
        $input = is_array( $input ) ? $input : array();

        $id = isset( $input['remediation_id'] ) ? absint( $input['remediation_id'] ) : 0;
        if ( 0 === $id ) {
            return new WP_Error( 'aipatch_missing_param', 'remediation_id is required.', array( 'status' => 400 ) );
        }

        $result = $this->remediation_engine->rollback( $id );
        if ( is_wp_error( $result ) ) {
            return $result;
        }

        return array( 'success' => true, 'remediation' => $result );
    }

    /**
     * List remediations.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_list_remediations( $input = array() ) {
        if ( ! $this->remediation_engine ) {
            return new WP_Error( 'aipatch_module_unavailable', 'Remediation engine not available.', array( 'status' => 400 ) );
        }
        $input = is_array( $input ) ? $input : array();

        $records = $this->remediation_engine->list_remediations( array(
            'finding_fingerprint' => isset( $input['finding_fingerprint'] ) ? $input['finding_fingerprint'] : '',
            'action_type'         => isset( $input['action_type'] ) ? $input['action_type'] : '',
            'status'              => isset( $input['status'] ) ? $input['status'] : '',
            'limit'               => isset( $input['limit'] ) ? absint( $input['limit'] ) : 50,
            'offset'              => isset( $input['offset'] ) ? absint( $input['offset'] ) : 0,
        ) );

        return array( 'success' => true, 'count' => count( $records ), 'remediations' => $records );
    }

    /* ---------------------------------------------------------------
     * Phase 8: New enriched MCP abilities
     * ------------------------------------------------------------- */

    /**
     * Verify WordPress core integrity against official checksums.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_verify_core_integrity( $input = array() ) {
        if ( ! $this->core_verifier ) {
            return new WP_Error( 'aipatch_module_unavailable', 'Core verifier not available.', array( 'status' => 400 ) );
        }

        $input         = is_array( $input ) ? $input : array();
        $force_refresh = isset( $input['force_refresh'] ) ? rest_sanitize_boolean( $input['force_refresh'] ) : false;

        $report = $this->core_verifier->verify_core( $force_refresh );

        $this->logger->info(
            'ability_verify_core',
            __( 'Core integrity verification ability executed.', 'aipatch-security-scanner' ),
            array(
                'verified'    => $report['verified'],
                'modified'    => count( $report['modified'] ),
                'missing'     => count( $report['missing'] ),
                'unexpected'  => count( $report['unexpected'] ),
            )
        );

        return array(
            'success'            => true,
            'generated_at_gmt'   => gmdate( 'c' ),
            'wp_version'         => $report['wp_version'],
            'checksums_available' => $report['checksums_available'],
            'verified'           => $report['verified'],
            'modified_count'     => count( $report['modified'] ),
            'missing_count'      => count( $report['missing'] ),
            'unexpected_count'   => count( $report['unexpected'] ),
            'modified'           => $report['modified'],
            'missing'            => $report['missing'],
            'unexpected'         => $report['unexpected'],
        );
    }

    /**
     * List suspicious files from the latest scan with enriched data.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_list_suspicious_files( $input = array() ) {
        $input = is_array( $input ) ? $input : array();

        $min_risk       = isset( $input['min_risk'] ) ? absint( $input['min_risk'] ) : 30;
        $classification = isset( $input['classification'] ) ? sanitize_key( $input['classification'] ) : '';
        $limit          = isset( $input['limit'] ) ? absint( $input['limit'] ) : 50;

        // Find the latest completed file_scan job.
        $job = $this->get_latest_file_scan_job();
        if ( ! $job ) {
            return new WP_Error( 'aipatch_no_scan', 'No completed file scan found. Run aipatch/start-file-scan first.', array( 'status' => 404 ) );
        }

        if ( ! $this->file_scanner ) {
            return new WP_Error( 'aipatch_module_unavailable', 'File scanner not available.', array( 'status' => 400 ) );
        }

        $raw = $this->file_scanner->get_results( $job->job_id, array(
            'min_risk'       => $min_risk,
            'classification' => $classification,
            'limit'          => $limit,
        ) );

        $enriched = $this->enrich_scan_results( isset( $raw['results'] ) ? $raw['results'] : array() );

        return array(
            'success'          => true,
            'generated_at_gmt' => gmdate( 'c' ),
            'job_id'           => $job->job_id,
            'scan_completed_at' => isset( $job->updated_at ) ? $job->updated_at : '',
            'filters'          => array(
                'min_risk'       => $min_risk,
                'classification' => $classification,
                'limit'          => $limit,
            ),
            'count'            => count( $enriched ),
            'files'            => $enriched,
            'stats'            => isset( $raw['stats'] ) ? $raw['stats'] : array(),
        );
    }

    /**
     * Get detailed information about a specific finding.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_get_file_finding_detail( $input = array() ) {
        if ( ! $this->findings_store ) {
            return new WP_Error( 'aipatch_module_unavailable', 'Findings store not available.', array( 'status' => 400 ) );
        }
        $input = is_array( $input ) ? $input : array();
        $fp    = isset( $input['fingerprint'] ) ? sanitize_text_field( $input['fingerprint'] ) : '';
        if ( empty( $fp ) ) {
            return new WP_Error( 'aipatch_missing_param', 'fingerprint is required.', array( 'status' => 400 ) );
        }

        $row = $this->findings_store->get_by_fingerprint( $fp );
        if ( ! $row ) {
            return new WP_Error( 'aipatch_finding_not_found', 'Finding not found.', array( 'status' => 404 ) );
        }

        $detail = (array) $row;

        // Decode meta_json into structured fields.
        $meta = array();
        if ( ! empty( $detail['meta_json'] ) ) {
            $decoded = json_decode( $detail['meta_json'], true );
            if ( is_array( $decoded ) ) {
                $meta = $decoded;
            }
        }

        $detail['meta'] = $meta;
        unset( $detail['meta_json'] );

        return array( 'success' => true, 'finding' => $detail );
    }

    /**
     * Get a comprehensive summary of the latest completed file scan.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_get_scan_summary( $input = array() ) {
        $job = $this->get_latest_file_scan_job();
        if ( ! $job ) {
            return new WP_Error( 'aipatch_no_scan', 'No completed file scan found. Run aipatch/start-file-scan first.', array( 'status' => 404 ) );
        }

        $summary = $this->job_manager ? $this->job_manager->summary( $job->job_id ) : null;
        $result  = isset( $job->result_json ) ? json_decode( $job->result_json, true ) : array();
        if ( ! is_array( $result ) ) {
            $result = array();
        }

        // Findings stats (overall + file_scanner source).
        $findings_stats = null;
        if ( $this->findings_store ) {
            $findings_stats = $this->findings_store->stats();
        }

        // Core integrity summary if available.
        $core_summary = null;
        if ( $this->core_verifier ) {
            $core = $this->core_verifier->verify_core();
            $core_summary = array(
                'verified'         => $core['verified'],
                'modified_count'   => count( $core['modified'] ),
                'missing_count'    => count( $core['missing'] ),
                'unexpected_count' => count( $core['unexpected'] ),
            );
        }

        return array(
            'success'          => true,
            'generated_at_gmt' => gmdate( 'c' ),
            'job_id'           => $job->job_id,
            'job_status'       => isset( $job->status ) ? $job->status : '',
            'started_at'       => isset( $job->created_at ) ? $job->created_at : '',
            'completed_at'     => isset( $job->updated_at ) ? $job->updated_at : '',
            'scan_stats'       => $result,
            'job_summary'      => $summary,
            'findings_stats'   => $findings_stats,
            'core_integrity'   => $core_summary,
        );
    }

    /**
     * Get combined baseline drift and core integrity report.
     *
     * @param array $input Input.
     * @return array|WP_Error
     */
    public function execute_get_baseline_drift( $input = array() ) {
        if ( ! $this->file_baseline ) {
            return new WP_Error( 'aipatch_module_unavailable', 'File baseline not available.', array( 'status' => 400 ) );
        }

        $input              = is_array( $input ) ? $input : array();
        $include_core_check = isset( $input['include_core_check'] ) ? rest_sanitize_boolean( $input['include_core_check'] ) : true;

        $diff   = $this->file_baseline->diff();
        $stats  = $this->file_baseline->stats();

        $response = array(
            'success'          => true,
            'generated_at_gmt' => gmdate( 'c' ),
            'baseline_stats'   => $stats,
            'drift'            => array(
                'modified_count' => count( $diff['modified'] ),
                'missing_count'  => count( $diff['missing'] ),
                'new_count'      => count( $diff['new'] ),
                'modified'       => array_slice( $diff['modified'], 0, 100 ),
                'missing'        => array_slice( $diff['missing'], 0, 100 ),
                'new'            => array_slice( $diff['new'], 0, 100 ),
            ),
        );

        if ( $include_core_check && $this->core_verifier ) {
            $core = $this->core_verifier->verify_core();
            $response['core_integrity'] = array(
                'wp_version'          => $core['wp_version'],
                'checksums_available' => $core['checksums_available'],
                'verified'            => $core['verified'],
                'modified_count'      => count( $core['modified'] ),
                'missing_count'       => count( $core['missing'] ),
                'unexpected_count'    => count( $core['unexpected'] ),
                'modified'            => $core['modified'],
                'missing'             => $core['missing'],
                'unexpected'          => $core['unexpected'],
            );
        }

        return $response;
    }

    /* ---------------------------------------------------------------
     * Phase 8 helpers
     * ------------------------------------------------------------- */

    /**
     * Find the latest completed file_scan job.
     *
     * @return object|null
     */
    private function get_latest_file_scan_job() {
        if ( ! $this->job_manager ) {
            return null;
        }

        $jobs = $this->job_manager->list_jobs( array(
            'job_type' => 'file_scan',
            'status'   => 'completed',
            'limit'    => 1,
        ) );

        return ! empty( $jobs ) ? $jobs[0] : null;
    }

    /**
     * Enrich raw DB result rows by decoding signals_json.
     *
     * @param array $rows Raw DB rows.
     * @return array Enriched items.
     */
    private function enrich_scan_results( $rows ) {
        $enriched = array();
        if ( ! is_array( $rows ) ) {
            return $enriched;
        }

        foreach ( $rows as $row ) {
            $item = array(
                'file_path'      => isset( $row->file_path ) ? $row->file_path : '',
                'risk_score'     => isset( $row->risk_score ) ? (int) $row->risk_score : 0,
                'classification' => isset( $row->classification ) ? $row->classification : '',
                'sha256'         => isset( $row->sha256 ) ? $row->sha256 : '',
                'file_size'      => isset( $row->file_size ) ? (int) $row->file_size : 0,
                'scanned_at'     => isset( $row->scanned_at ) ? $row->scanned_at : '',
            );

            $decoded = ! empty( $row->signals_json ) ? json_decode( $row->signals_json, true ) : array();
            if ( is_array( $decoded ) ) {
                $item['family']             = isset( $decoded['family'] ) ? $decoded['family'] : '';
                $item['family_label']       = isset( $decoded['family_label'] ) ? $decoded['family_label'] : '';
                $item['family_confidence']  = isset( $decoded['family_confidence'] ) ? $decoded['family_confidence'] : '';
                $item['risk_level']         = isset( $decoded['risk_level'] ) ? $decoded['risk_level'] : '';
                $item['reasons']            = isset( $decoded['reasons'] ) ? $decoded['reasons'] : array();
                $item['matched_rules']      = isset( $decoded['matched_rules'] ) ? $decoded['matched_rules'] : array();
                $item['context_flags']      = isset( $decoded['context_flags'] ) ? $decoded['context_flags'] : array();
                $item['integrity_flags']    = isset( $decoded['integrity_flags'] ) ? $decoded['integrity_flags'] : array();
                $item['layer_scores']       = isset( $decoded['layer_scores'] ) ? $decoded['layer_scores'] : array();
                $item['remediation_hint']   = isset( $decoded['remediation_hint'] ) ? $decoded['remediation_hint'] : '';
                $item['core_tampered']      = ! empty( $decoded['core_tampered'] );
                $item['unexpected_in_core'] = ! empty( $decoded['unexpected_in_core'] );
                $item['core_checksum']      = isset( $decoded['core_checksum'] ) ? $decoded['core_checksum'] : '';
                $item['is_new']             = ! empty( $decoded['is_new'] );
                $item['is_modified']        = ! empty( $decoded['is_modified'] );
            }

            $enriched[] = $item;
        }

        return $enriched;
    }
}
