<?php
/**
 * File Scanner.
 *
 * Orchestrates batch file scanning using the Job Manager, heuristics engine,
 * and file classifier. Designed for incremental execution via WP-Cron or
 * successive REST/MCP calls.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_File_Scanner
 */
class AIPSC_File_Scanner {

    const JOB_TYPE = 'file_scan';

    /**
     * Default extensions to scan.
     *
     * @var string[]
     */
    private static $default_extensions = array( 'php', 'phtml', 'php5', 'php7', 'pht', 'phps', 'shtml' );

    /**
     * Max file size to read (2 MB).
     */
    const MAX_FILE_SIZE = 2097152;

    /**
     * @var AIPSC_Job_Manager
     */
    private $job_manager;

    /**
     * @var AIPSC_Logger
     */
    private $logger;

    /**
     * Constructor.
     *
     * @param AIPSC_Job_Manager $job_manager Job manager instance.
     * @param AIPSC_Logger      $logger      Logger instance.
     */
    public function __construct( AIPSC_Job_Manager $job_manager, AIPSC_Logger $logger ) {
        $this->job_manager = $job_manager;
        $this->logger      = $logger;
    }

    /**
     * Start a new file scan job.
     *
     * Enumerates PHP files under the given root and creates a job with items.
     *
     * @param array $options {
     *     @type string   $root        Directory to scan (default ABSPATH).
     *     @type string[] $extensions  File extensions to include.
     *     @type string[] $exclude     Directory names to skip.
     *     @type int      $max_files   Cap on total files (0 = unlimited).
     * }
     * @return string|false Job ID or false on failure.
     */
    public function start( array $options = array() ) {
        $defaults = array(
            'root'       => ABSPATH,
            'extensions' => self::$default_extensions,
            'exclude'    => array( 'node_modules', '.git', 'vendor', 'cache' ),
            'max_files'  => 50000,
        );
        $options = wp_parse_args( $options, $defaults );

        $files = $this->enumerate_files(
            $options['root'],
            $options['extensions'],
            $options['exclude'],
            $options['max_files']
        );

        if ( empty( $files ) ) {
            $this->logger->warning( 'file_scan', 'No scannable files found.' );
            return false;
        }

        $job_id = $this->job_manager->create( self::JOB_TYPE, $options, count( $files ) );
        if ( ! $job_id ) {
            return false;
        }

        $this->job_manager->add_items( $job_id, $files );

        $this->logger->info(
            'file_scan',
            sprintf( 'File scan job created: %s (%d files).', $job_id, count( $files ) )
        );

        return $job_id;
    }

    /**
     * Process the next batch of files for a job.
     *
     * Returns the number of files processed. Call repeatedly until 0.
     *
     * @param string $job_id     Job UUID.
     * @param int    $batch_size Files per batch.
     * @return int               Number of files processed in this batch.
     */
    public function process_batch( $job_id, $batch_size = 50 ) {
        $job = $this->job_manager->get( $job_id );
        if ( ! $job || AIPSC_Job_Manager::STATUS_CANCELLED === $job->status ) {
            return 0;
        }

        // Start the job on first batch.
        if ( AIPSC_Job_Manager::STATUS_PENDING === $job->status ) {
            $this->job_manager->start( $job_id );
        }

        $items = $this->job_manager->claim_items( $job_id, $batch_size );
        if ( empty( $items ) ) {
            // No more items — complete the job.
            $this->finalise_job( $job_id );
            return 0;
        }

        global $wpdb;
        $results_table = $wpdb->prefix . 'aipsc_file_scan_results';
        $processed     = 0;

        foreach ( $items as $item ) {
            $file_path = $item->item_key;

            try {
                $scan_result = $this->scan_file( $file_path );

                // Store in file_scan_results table.
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
                $wpdb->insert(
                    $results_table,
                    array(
                        'job_id'         => $job_id,
                        'file_path'      => $file_path,
                        'risk_score'     => $scan_result['risk_score'],
                        'classification' => $scan_result['classification'],
                        'signals_json'   => wp_json_encode( $scan_result['signals'] ),
                        'sha256'         => $scan_result['sha256'],
                        'file_size'      => $scan_result['file_size'],
                        'scanned_at'     => current_time( 'mysql', true ),
                    ),
                    array( '%s', '%s', '%d', '%s', '%s', '%s', '%d', '%s' )
                );

                $this->job_manager->complete_item( $item->id, array(
                    'risk_score'     => $scan_result['risk_score'],
                    'classification' => $scan_result['classification'],
                ) );
            } catch ( \Exception $e ) {
                $this->job_manager->fail_item( $item->id, $e->getMessage() );
            }

            $processed++;
        }

        // Update progress.
        $counts    = $this->job_manager->count_items( $job_id );
        $completed = $counts['completed'] + $counts['failed'];
        $this->job_manager->progress( $job_id, $completed );

        return $processed;
    }

    /**
     * Run the full scan synchronously (for small sites or CLI).
     *
     * @param array $options Same as start().
     * @return array Summary with job_id and results.
     */
    public function run_full( array $options = array() ) {
        $job_id = $this->start( $options );
        if ( ! $job_id ) {
            return array( 'error' => 'Failed to create file scan job.' );
        }

        $batch_size = 100;
        while ( true ) {
            $processed = $this->process_batch( $job_id, $batch_size );
            if ( 0 === $processed ) {
                break;
            }
        }

        return $this->get_results( $job_id );
    }

    /**
     * Get results for a completed job.
     *
     * @param string $job_id     Job UUID.
     * @param array  $args {
     *     @type int    $min_risk   Minimum risk score to include.
     *     @type string $classification Filter by classification.
     *     @type int    $limit      Max results.
     *     @type int    $offset     Offset.
     * }
     * @return array
     */
    public function get_results( $job_id, array $args = array() ) {
        global $wpdb;

        $defaults = array(
            'min_risk'       => 0,
            'classification' => '',
            'limit'          => 200,
            'offset'         => 0,
        );
        $args = wp_parse_args( $args, $defaults );

        $where  = array( 'job_id = %s' );
        $values = array( $job_id );

        if ( $args['min_risk'] > 0 ) {
            $where[]  = 'risk_score >= %d';
            $values[] = absint( $args['min_risk'] );
        }

        if ( ! empty( $args['classification'] ) ) {
            $where[]  = 'classification = %s';
            $values[] = sanitize_key( $args['classification'] );
        }

        $where_clause = implode( ' AND ', $where );
        $values[]     = absint( $args['limit'] );
        $values[]     = absint( $args['offset'] );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}aipsc_file_scan_results WHERE {$where_clause} ORDER BY risk_score DESC LIMIT %d OFFSET %d",
                $values
            )
        );

        $summary = $this->job_manager->summary( $job_id );

        return array(
            'job'     => $summary,
            'results' => $rows,
            'stats'   => $this->compute_stats( $job_id ),
        );
    }

    /**
     * Scan a single file.
     *
     * @param string $file_path Absolute path to file.
     * @return array
     */
    public function scan_file( $file_path ) {
        if ( ! is_readable( $file_path ) ) {
            throw new \RuntimeException( sprintf( 'File not readable: %s', $file_path ) );
        }

        $file_size = filesize( $file_path );

        // Skip files that are too large.
        if ( $file_size > self::MAX_FILE_SIZE ) {
            return array(
                'risk_score'     => 0,
                'classification' => 'skipped',
                'signals'        => array(),
                'sha256'         => '',
                'file_size'      => $file_size,
            );
        }

        $content = file_get_contents( $file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
        $sha256  = hash( 'sha256', $content );

        $relative = $this->relative_path( $file_path );
        $signals  = AIPSC_File_Heuristics::analyse( $content, $relative );
        $result   = AIPSC_File_Classifier::classify( $signals, $relative );

        return array(
            'risk_score'     => $result['risk_score'],
            'classification' => $result['classification'],
            'signals'        => $signals,
            'sha256'         => $sha256,
            'file_size'      => $file_size,
        );
    }

    /* ---------------------------------------------------------------
     * Internal
     * ------------------------------------------------------------- */

    /**
     * Enumerate PHP-like files recursively.
     *
     * @param string   $root       Root directory.
     * @param string[] $extensions Allowed extensions.
     * @param string[] $exclude    Directory names to skip.
     * @param int      $max_files  Cap.
     * @return string[]
     */
    private function enumerate_files( $root, array $extensions, array $exclude, $max_files ) {
        $files     = array();
        $root      = rtrim( $root, '/\\' );
        $ext_map   = array_flip( array_map( 'strtolower', $extensions ) );
        $excl_map  = array_flip( array_map( 'strtolower', $exclude ) );

        $iterator = new \RecursiveDirectoryIterator(
            $root,
            \RecursiveDirectoryIterator::SKIP_DOTS | \RecursiveDirectoryIterator::FOLLOW_SYMLINKS
        );

        $filter = new \RecursiveCallbackFilterIterator(
            $iterator,
            function ( $current, $key, $iterator ) use ( $excl_map ) {
                if ( $current->isDir() ) {
                    return ! isset( $excl_map[ strtolower( $current->getFilename() ) ] );
                }
                return true;
            }
        );

        $flat = new \RecursiveIteratorIterator( $filter, \RecursiveIteratorIterator::LEAVES_ONLY );

        foreach ( $flat as $file ) {
            if ( ! $file->isFile() ) {
                continue;
            }

            $ext = strtolower( $file->getExtension() );
            if ( ! isset( $ext_map[ $ext ] ) ) {
                continue;
            }

            $files[] = $file->getPathname();

            if ( $max_files > 0 && count( $files ) >= $max_files ) {
                break;
            }
        }

        return $files;
    }

    /**
     * Convert absolute path to relative from ABSPATH.
     *
     * @param string $path Absolute path.
     * @return string
     */
    private function relative_path( $path ) {
        $abs = wp_normalize_path( ABSPATH );
        $path = wp_normalize_path( $path );

        if ( 0 === strpos( $path, $abs ) ) {
            return substr( $path, strlen( $abs ) );
        }

        return $path;
    }

    /**
     * Finalise a completed job with statistics.
     *
     * @param string $job_id Job UUID.
     */
    private function finalise_job( $job_id ) {
        $stats = $this->compute_stats( $job_id );

        $this->job_manager->complete( $job_id, $stats );

        $this->logger->info(
            'file_scan',
            sprintf(
                'File scan completed: %s — %d files, %d suspicious, %d risky, %d malicious.',
                $job_id,
                $stats['total_files'],
                $stats['by_classification']['suspicious'],
                $stats['by_classification']['risky'],
                $stats['by_classification']['malicious']
            )
        );
    }

    /**
     * Compute aggregate statistics for a job.
     *
     * @param string $job_id Job UUID.
     * @return array
     */
    private function compute_stats( $job_id ) {
        global $wpdb;

        $table = $wpdb->prefix . 'aipsc_file_scan_results';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $by_class = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT classification, COUNT(*) as cnt FROM {$table} WHERE job_id = %s GROUP BY classification",
                $job_id
            ),
            OBJECT_K
        );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $agg = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT COUNT(*) as total, MAX(risk_score) as max_risk, AVG(risk_score) as avg_risk FROM {$table} WHERE job_id = %s",
                $job_id
            )
        );

        return array(
            'total_files'       => $agg ? (int) $agg->total : 0,
            'max_risk_score'    => $agg ? (int) $agg->max_risk : 0,
            'avg_risk_score'    => $agg ? round( (float) $agg->avg_risk, 1 ) : 0,
            'by_classification' => array(
                'clean'      => isset( $by_class['clean'] ) ? (int) $by_class['clean']->cnt : 0,
                'suspicious' => isset( $by_class['suspicious'] ) ? (int) $by_class['suspicious']->cnt : 0,
                'risky'      => isset( $by_class['risky'] ) ? (int) $by_class['risky']->cnt : 0,
                'malicious'  => isset( $by_class['malicious'] ) ? (int) $by_class['malicious']->cnt : 0,
                'skipped'    => isset( $by_class['skipped'] ) ? (int) $by_class['skipped']->cnt : 0,
            ),
        );
    }
}
