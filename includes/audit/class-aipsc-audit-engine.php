<?php
/**
 * Audit Engine.
 *
 * Orchestrates running all registered checks and collecting results.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Audit_Engine
 *
 * Runs registered audit checks and produces a unified result set.
 */
class AIPSC_Audit_Engine {

    /**
     * Registry instance.
     *
     * @var AIPSC_Audit_Check_Registry
     */
    private $registry;

    /**
     * Logger instance.
     *
     * @var AIPSC_Logger
     */
    private $logger;

    /**
     * Constructor.
     *
     * @param AIPSC_Audit_Check_Registry $registry Check registry.
     * @param AIPSC_Logger               $logger   Logger.
     */
    public function __construct( AIPSC_Audit_Check_Registry $registry, AIPSC_Logger $logger ) {
        $this->registry = $registry;
        $this->logger   = $logger;
    }

    /**
     * Register all built-in checks.
     *
     * Called once during plugin bootstrap. Third-party code should use the
     * `aipatch_register_audit_checks` action that fires after this.
     *
     * @return void
     */
    public function register_default_checks(): void {
        $checks = array(
            'AIPSC_Check_WP_Version',
            'AIPSC_Check_Plugins_Outdated',
            'AIPSC_Check_Themes_Outdated',
            'AIPSC_Check_Admin_Username',
            'AIPSC_Check_Too_Many_Admins',
            'AIPSC_Check_XMLRPC',
            'AIPSC_Check_File_Editor',
            'AIPSC_Check_Debug_Mode',
            'AIPSC_Check_PHP_Version',
            'AIPSC_Check_REST_Exposure',
            'AIPSC_Check_Directory_Listing',
            'AIPSC_Check_File_Permissions',
            'AIPSC_Check_SSL',
            'AIPSC_Check_Inactive_Plugins',
            'AIPSC_Check_Unused_Themes',
            'AIPSC_Check_Inactive_Admins',
            'AIPSC_Check_DB_Prefix',
            'AIPSC_Check_Sensitive_Files',
            'AIPSC_Check_PHP_In_Uploads',
            'AIPSC_Check_Security_Headers',
            'AIPSC_Check_User_Enumeration',
            'AIPSC_Check_Application_Passwords',
            'AIPSC_Check_Auto_Updates',
            'AIPSC_Check_Salt_Keys',
            'AIPSC_Check_Debug_Log',
            'AIPSC_Check_User_ID_One',
            'AIPSC_Check_Database_Debug',
            'AIPSC_Check_File_Install',
            'AIPSC_Check_Cron_Health',
            'AIPSC_Check_Cookie_Security',
            'AIPSC_Check_Backup_Files',
            'AIPSC_Check_Phpinfo',
            'AIPSC_Check_CORS',
            'AIPSC_Check_Uploads_Index',
            'AIPSC_Check_Login_URL',
            'AIPSC_Check_DB_Credentials',
        );

        foreach ( $checks as $class ) {
            if ( class_exists( $class ) ) {
                $this->registry->register( new $class() );
            }
        }

        /**
         * Fires after built-in checks are registered.
         *
         * Third parties can register additional checks here.
         *
         * @param AIPSC_Audit_Check_Registry $registry The check registry.
         */
        do_action( 'aipatch_register_audit_checks', $this->registry );
    }

    /**
     * Run all registered checks.
     *
     * @param array $options {
     *     Optional. Run options.
     *
     *     @type string[] $categories  Only run checks in these categories. Empty = all.
     *     @type string[] $check_ids   Only run these specific checks. Empty = all.
     * }
     * @return array {
     *     @type AIPSC_Audit_Check_Result[] $results    All findings.
     *     @type array                      $errors     Checks that threw exceptions: [ id => message ].
     *     @type int                        $checks_run Number of checks executed.
     *     @type float                      $duration   Duration in seconds.
     * }
     */
    public function run( array $options = array() ): array {
        $start           = microtime( true );
        $results         = array();
        $errors          = array();
        $checks_run      = 0;
        $categories      = $options['categories'] ?? array();
        $check_ids       = $options['check_ids'] ?? array();

        $checks = $this->registry->get_all();

        foreach ( $checks as $id => $check ) {
            // Filter by ID if specified.
            if ( ! empty( $check_ids ) && ! in_array( $id, $check_ids, true ) ) {
                continue;
            }

            // Filter by category if specified.
            if ( ! empty( $categories ) && ! in_array( $check->get_category(), $categories, true ) ) {
                continue;
            }

            try {
                $check_results = $check->run();
                $checks_run++;

                foreach ( $check_results as $result ) {
                    if ( $result instanceof AIPSC_Audit_Check_Result ) {
                        $results[] = $result;
                    }
                }
            } catch ( \Exception $e ) {
                $errors[ $id ] = $e->getMessage();
                $this->logger->error(
                    'audit_check_failed',
                    sprintf( 'Check "%s" failed: %s', $id, $e->getMessage() ),
                    array( 'check_id' => $id, 'exception' => $e->getMessage() )
                );
            }
        }

        $duration = microtime( true ) - $start;

        return array(
            'results'    => $results,
            'errors'     => $errors,
            'checks_run' => $checks_run,
            'duration'   => $duration,
        );
    }

    /**
     * Run all checks and return results in legacy format (compatible with AIPSC_Scanner output).
     *
     * @param string $scan_type Scan type identifier.
     * @return array{score: int, issues: array, timestamp: int, version: string}
     */
    public function run_legacy( string $scan_type = 'manual' ): array {
        $this->logger->info(
            'scan_started',
            sprintf(
                /* translators: %s: Scan type. */
                __( 'Security scan started (%s).', 'aipatch-security-scanner' ),
                $scan_type
            )
        );

        $run = $this->run();

        // Convert to legacy issue arrays.
        $issues = array();
        foreach ( $run['results'] as $result ) {
            $issues[] = $result->to_legacy_array();
        }

        // Calculate scores using the new weighted engine.
        $dismissed    = AIPSC_Utils::get_option( 'dismissed', array() );
        $score_data   = AIPSC_Score_Engine::compute( $run['results'], $dismissed );
        $score        = $score_data['overall_score'];

        $duration_ms = (int) round( $run['duration'] * 1000 );

        $this->logger->info(
            'scan_completed',
            sprintf(
                /* translators: 1: Score, 2: Issues count, 3: Duration. */
                __( 'Scan completed — Score: %1$d, Issues: %2$d, Duration: %3$dms.', 'aipatch-security-scanner' ),
                $score,
                count( $issues ),
                $duration_ms
            ),
            array(
                'score'       => $score,
                'issues'      => count( $issues ),
                'duration_ms' => $duration_ms,
                'scan_type'   => $scan_type,
                'checks_run'  => $run['checks_run'],
                'errors'      => count( $run['errors'] ),
            )
        );

        return array(
            'score'           => $score,
            'issues'          => $issues,
            'timestamp'       => time(),
            'version'         => defined( 'AIPATCH_VERSION' ) ? AIPATCH_VERSION : '0.0.0',
            'checks_run'      => $run['checks_run'],
            'duration_ms'     => $duration_ms,
            'score_breakdown' => $score_data,
            'raw_results'     => $run['results'],
        );
    }

    /**
     * Get the registry.
     *
     * @return AIPSC_Audit_Check_Registry
     */
    public function get_registry(): AIPSC_Audit_Check_Registry {
        return $this->registry;
    }
}
