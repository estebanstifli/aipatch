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
    private static $default_extensions = array( 'php', 'phtml', 'phar', 'php5', 'php7', 'pht', 'phps', 'shtml' );

    /**
     * Non-PHP extensions to also scan inside uploads (hidden PHP detection).
     *
     * @var string[]
     */
    private static $uploads_extra_extensions = array(
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'svg',
        'htm', 'html', 'css', 'js', 'txt', 'xml', 'json',
    );

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
     * @var AIPSC_File_Baseline|null
     */
    private $baseline;

    /**
     * @var AIPSC_Findings_Store|null
     */
    private $findings_store;

    /**
     * Baseline index cache (loaded once per batch).
     *
     * @var array<string, array>|null
     */
    private $baseline_index;

    /**
     * Constructor.
     *
     * @param AIPSC_Job_Manager        $job_manager     Job manager instance.
     * @param AIPSC_Logger             $logger          Logger instance.
     * @param AIPSC_File_Baseline|null $baseline        Optional baseline for integrity checks.
     * @param AIPSC_Findings_Store|null $findings_store Optional findings store for persistence.
     */
    public function __construct( AIPSC_Job_Manager $job_manager, AIPSC_Logger $logger, $baseline = null, $findings_store = null ) {
        $this->job_manager    = $job_manager;
        $this->logger         = $logger;
        $this->baseline       = $baseline;
        $this->findings_store = $findings_store;
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
            'root'          => ABSPATH,
            'extensions'    => self::$default_extensions,
            'exclude'       => array( 'node_modules', '.git', 'vendor', 'cache' ),
            'max_files'     => 50000,
            'scan_uploads'  => true,
        );
        $options = wp_parse_args( $options, $defaults );

        $files = $this->enumerate_files(
            $options['root'],
            $options['extensions'],
            $options['exclude'],
            $options['max_files']
        );

        // Also enumerate non-PHP files in uploads for hidden PHP detection.
        if ( $options['scan_uploads'] ) {
            $upload_info = wp_upload_dir();
            $uploads_dir = isset( $upload_info['basedir'] ) ? $upload_info['basedir'] : '';

            if ( '' !== $uploads_dir && is_dir( $uploads_dir ) ) {
                $remaining = $options['max_files'] > 0
                    ? max( 0, $options['max_files'] - count( $files ) )
                    : 0;

                if ( 0 === $options['max_files'] || $remaining > 0 ) {
                    $uploads_files = $this->enumerate_files(
                        $uploads_dir,
                        self::$uploads_extra_extensions,
                        $options['exclude'],
                        $remaining
                    );
                    $files = array_unique( array_merge( $files, $uploads_files ) );
                }
            }
        }

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

                // Build enriched JSON payload for storage.
                $enriched_json = wp_json_encode( array(
                    'signals'           => $scan_result['signals'],
                    'reasons'           => $scan_result['reasons'],
                    'matched_rules'     => $scan_result['matched_rules'],
                    'context_flags'     => $scan_result['context_flags'],
                    'integrity_flags'   => $scan_result['integrity_flags'],
                    'layer_scores'      => isset( $scan_result['layer_scores'] ) ? $scan_result['layer_scores'] : array(),
                    'family'            => $scan_result['family'],
                    'family_label'      => $scan_result['family_label'],
                    'family_confidence' => $scan_result['family_confidence'],
                    'remediation_hint'  => $scan_result['remediation_hint'],
                    'family_guess'      => $scan_result['family_guess'],
                    'risk_level'        => $scan_result['risk_level'],
                    'is_new'            => ! empty( $scan_result['is_new'] ),
                    'is_modified'       => ! empty( $scan_result['is_modified'] ),
                    'first_seen'        => isset( $scan_result['first_seen'] ) ? $scan_result['first_seen'] : '',
                    'last_seen'         => isset( $scan_result['last_seen'] ) ? $scan_result['last_seen'] : '',
                ) );

                // Store in file_scan_results table.
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
                $wpdb->insert(
                    $results_table,
                    array(
                        'job_id'         => $job_id,
                        'file_path'      => $file_path,
                        'risk_score'     => $scan_result['risk_score'],
                        'classification' => $scan_result['classification'],
                        'signals_json'   => $enriched_json,
                        'sha256'         => $scan_result['sha256'],
                        'file_size'      => $scan_result['file_size'],
                        'scanned_at'     => current_time( 'mysql', true ),
                    ),
                    array( '%s', '%s', '%d', '%s', '%s', '%s', '%d', '%s' )
                );

                $this->job_manager->complete_item( $item->id, array(
                    'risk_score'        => $scan_result['risk_score'],
                    'classification'    => $scan_result['classification'],
                    'family'            => $scan_result['family'],
                    'family_confidence' => $scan_result['family_confidence'],
                    'family_guess'      => $scan_result['family_guess'],
                    'risk_level'        => $scan_result['risk_level'],
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
     * @return array Enriched result with layered scoring.
     */
    public function scan_file( $file_path ) {
        if ( ! is_readable( $file_path ) ) {
            throw new \RuntimeException( sprintf( 'File not readable: %s', $file_path ) );
        }

        $file_size = filesize( $file_path );

        // Skip files that are too large.
        if ( $file_size > self::MAX_FILE_SIZE ) {
            return array(
                'risk_score'        => 0,
                'risk_level'        => 'clean',
                'classification'    => 'skipped',
                'family'            => '',
                'family_label'      => '',
                'family_confidence' => 'none',
                'remediation_hint'  => '',
                'family_guess'      => '',
                'signals'           => array(),
                'reasons'           => array(),
                'matched_rules'     => array(),
                'context_flags'     => array(),
                'integrity_flags'   => array(),
                'sha256'            => '',
                'file_size'         => $file_size,
            );
        }

        $content  = file_get_contents( $file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
        $sha256   = hash( 'sha256', $content );
        $relative = $this->relative_path( $file_path );

        // Determine analysis method based on file extension.
        $ext    = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );
        $is_php = in_array( $ext, self::$default_extensions, true );

        // Heuristic signals (full analysis for PHP, hidden-PHP check for other files).
        if ( $is_php ) {
            $signals = AIPSC_File_Heuristics::analyse( $content, $relative );
        } else {
            $signals = AIPSC_File_Heuristics::analyse_non_php( $content, $relative );
        }

        // Integrity info from baseline.
        $integrity_info = $this->get_integrity_info( $relative, $sha256 );

        // Layered classification.
        $result = AIPSC_File_Classifier::classify( $signals, $relative, $integrity_info, $sha256 );

        $integrity_status = isset( $integrity_info['status'] ) ? $integrity_info['status'] : 'unknown';

        return array(
            'risk_score'        => $result['risk_score'],
            'risk_level'        => $result['risk_level'],
            'classification'    => $result['classification'],
            'family'            => $result['family'],
            'family_label'      => $result['family_label'],
            'family_confidence' => $result['family_confidence'],
            'remediation_hint'  => $result['remediation_hint'],
            'family_guess'      => $result['family_guess'],
            'signals'           => $signals,
            'reasons'           => $result['reasons'],
            'matched_rules'     => $result['matched_rules'],
            'context_flags'     => $result['context_flags'],
            'integrity_flags'   => $result['integrity_flags'],
            'layer_scores'      => $result['layer_scores'],
            'sha256'            => $sha256,
            'file_size'         => $file_size,
            'is_new'            => 'new' === $integrity_status,
            'is_modified'       => 'modified' === $integrity_status,
            'first_seen'        => isset( $integrity_info['first_seen'] ) ? $integrity_info['first_seen'] : '',
            'last_seen'         => isset( $integrity_info['last_seen'] ) ? $integrity_info['last_seen'] : '',
        );
    }

    /**
     * Get integrity info for a file from the baseline index.
     *
     * @param string $relative Relative file path.
     * @param string $sha256   Current file SHA-256.
     * @return array Integrity status array.
     */
    private function get_integrity_info( $relative, $sha256 ) {
        if ( null === $this->baseline ) {
            return array( 'status' => 'unknown' );
        }

        // Lazy-load baseline index once per scanner lifetime.
        if ( null === $this->baseline_index ) {
            $this->baseline_index = $this->load_baseline_index();
        }

        if ( ! isset( $this->baseline_index[ $relative ] ) ) {
            return array(
                'status'      => 'new',
                'origin_type' => '',
                'first_seen'  => '',
                'last_seen'   => '',
            );
        }

        $entry = $this->baseline_index[ $relative ];

        $base = array(
            'origin_type' => $entry['origin_type'],
            'first_seen'  => $entry['first_seen'],
            'last_seen'   => $entry['last_seen'],
        );

        if ( $entry['sha256'] === $sha256 ) {
            return array_merge( array( 'status' => 'unchanged' ), $base );
        }

        return array_merge( array(
            'status'     => 'modified',
            'sha256_was' => $entry['sha256'],
        ), $base );
    }

    /**
     * Load baseline entries into a path-keyed index.
     *
     * @return array<string, array{sha256: string, origin_type: string, first_seen: string, last_seen: string}>
     */
    private function load_baseline_index() {
        global $wpdb;

        $table = $wpdb->prefix . 'aipsc_file_baseline';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results( "SELECT file_path, sha256, origin_type, first_seen, last_seen FROM {$table}" );

        $index = array();
        if ( $rows ) {
            foreach ( $rows as $row ) {
                $index[ $row->file_path ] = array(
                    'sha256'      => $row->sha256,
                    'origin_type' => $row->origin_type,
                    'first_seen'  => $row->first_seen,
                    'last_seen'   => $row->last_seen,
                );
            }
        }

        return $index;
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

        // Sync relevant file results into persistent findings store.
        $findings_sync = $this->sync_findings_for_job( $job_id );
        if ( ! empty( $findings_sync ) ) {
            $stats['findings_sync'] = $findings_sync;
        }

        $this->job_manager->complete( $job_id, $stats );

        $this->logger->info(
            'file_scan',
            sprintf(
                'File scan completed: %s — %d files, %d suspicious, %d risky, %d malicious. Findings: %d new, %d updated, %d resolved.',
                $job_id,
                $stats['total_files'],
                $stats['by_classification']['suspicious'],
                $stats['by_classification']['risky'],
                $stats['by_classification']['malicious'],
                isset( $findings_sync['inserted'] ) ? $findings_sync['inserted'] : 0,
                isset( $findings_sync['updated'] ) ? $findings_sync['updated'] : 0,
                isset( $findings_sync['resolved'] ) ? $findings_sync['resolved'] : 0
            )
        );
    }

    /**
     * Sync file scan results into the persistent findings store.
     *
     * Reads all results for the job with risk_score >= 15, decodes their
     * enriched data, and feeds them into the findings store for deduplication
     * and tracking.
     *
     * @param string $job_id Job UUID.
     * @return array Sync statistics or empty array if store unavailable.
     */
    private function sync_findings_for_job( $job_id ) {
        if ( null === $this->findings_store ) {
            return array();
        }

        global $wpdb;
        $table = $wpdb->prefix . 'aipsc_file_scan_results';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT file_path, risk_score, classification, signals_json, sha256, file_size FROM {$table} WHERE job_id = %s AND risk_score >= 15",
                $job_id
            )
        );

        if ( empty( $rows ) ) {
            // No findings — still call sync to auto-resolve previously open file_scanner findings.
            return $this->findings_store->sync_file_findings( array(), $job_id );
        }

        $file_results = array();
        foreach ( $rows as $row ) {
            $enriched = ! empty( $row->signals_json ) ? json_decode( $row->signals_json, true ) : array();
            if ( ! is_array( $enriched ) ) {
                $enriched = array();
            }

            // Merge DB-level fields with decoded enriched data.
            $file_results[] = array_merge( $enriched, array(
                'file_path'      => $row->file_path,
                'risk_score'     => (int) $row->risk_score,
                'classification' => $row->classification,
                'sha256'         => $row->sha256,
                'file_size'      => (int) $row->file_size,
            ) );
        }

        return $this->findings_store->sync_file_findings( $file_results, $job_id );
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
