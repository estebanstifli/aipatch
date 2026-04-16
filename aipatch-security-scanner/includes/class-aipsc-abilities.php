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

    /**
     * Constructor.
     *
     * @param AIPSC_Scanner|null         $scanner         Scanner module.
     * @param AIPSC_Vulnerabilities|null $vulnerabilities Vulnerabilities module.
     * @param AIPSC_Logger               $logger          Logger instance.
     */
    public function __construct( $scanner, $vulnerabilities, AIPSC_Logger $logger ) {
        $this->scanner         = $scanner;
        $this->vulnerabilities = $vulnerabilities;
        $this->logger          = $logger;
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

        $this->register_site_audit_ability( 'aipatch/audit-site', __( 'Audit Site', 'aipatch-security-scanner' ), __( 'Runs a full site security audit and returns a structured report for external AI agents.', 'aipatch-security-scanner' ) );
        $this->register_suspicious_audit_ability( 'aipatch/audit-suspicious', __( 'Audit Suspicious Files', 'aipatch-security-scanner' ), __( 'Scans for suspicious files and returns indicators for deep analysis by an external AI agent.', 'aipatch-security-scanner' ) );
        $this->register_async_status_ability();
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
}
