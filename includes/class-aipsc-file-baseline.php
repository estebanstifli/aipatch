<?php
/**
 * File Baseline Manager.
 *
 * Maintains a database of known-good file states (sha256, size, mtime).
 * Provides methods to build, refresh, and diff the baseline against
 * the current filesystem to detect integrity drift.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_File_Baseline
 */
class AIPSC_File_Baseline {

    const ORIGIN_CORE    = 'core';
    const ORIGIN_PLUGIN  = 'plugin';
    const ORIGIN_THEME   = 'theme';
    const ORIGIN_UPLOAD  = 'upload';
    const ORIGIN_UNKNOWN = 'unknown';

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
     * @param AIPSC_Job_Manager $job_manager Job manager.
     * @param AIPSC_Logger      $logger      Logger.
     */
    public function __construct( AIPSC_Job_Manager $job_manager, AIPSC_Logger $logger ) {
        $this->job_manager = $job_manager;
        $this->logger      = $logger;
    }

    /**
     * Build or refresh the baseline for a set of files.
     *
     * @param string[] $file_paths Absolute paths. If empty, auto-discover.
     * @return array{ inserted: int, updated: int }
     */
    public function build( array $file_paths = array() ) {
        global $wpdb;

        if ( empty( $file_paths ) ) {
            $file_paths = $this->discover_files();
        }

        $table = $wpdb->prefix . 'aipsc_file_baseline';
        $now   = current_time( 'mysql', true );
        $stats = array( 'inserted' => 0, 'updated' => 0 );

        foreach ( $file_paths as $path ) {
            if ( ! is_readable( $path ) ) {
                continue;
            }

            $relative = $this->relative_path( $path );
            $sha256   = hash_file( 'sha256', $path );
            $size     = filesize( $path );
            $mtime    = filemtime( $path );
            $origin   = $this->detect_origin( $relative );

            $component = $this->detect_component( $relative );

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $existing = $wpdb->get_row(
                $wpdb->prepare(
                    "SELECT id FROM {$wpdb->prefix}aipsc_file_baseline WHERE file_path = %s LIMIT 1",
                    $relative
                )
            );

            if ( $existing ) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->update(
                    $table,
                    array(
                        'sha256'            => $sha256,
                        'file_size'         => $size,
                        'mtime'             => $mtime,
                        'origin_type'       => $origin,
                        'component_slug'    => $component['slug'],
                        'component_version' => $component['version'],
                        'last_seen'         => $now,
                    ),
                    array( 'id' => $existing->id )
                );
                $stats['updated']++;
            } else {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
                $wpdb->insert(
                    $table,
                    array(
                        'file_path'         => $relative,
                        'sha256'            => $sha256,
                        'file_size'         => $size,
                        'mtime'             => $mtime,
                        'origin_type'       => $origin,
                        'component_slug'    => $component['slug'],
                        'component_version' => $component['version'],
                        'first_seen'        => $now,
                        'last_seen'         => $now,
                    )
                );
                $stats['inserted']++;
            }
        }

        $this->logger->info(
            'baseline',
            sprintf( 'Baseline built: %d inserted, %d updated.', $stats['inserted'], $stats['updated'] )
        );

        return $stats;
    }

    /**
     * Check the current filesystem against the stored baseline.
     *
     * @return array{
     *     modified: array,
     *     missing: array,
     *     new: array,
     * }
     */
    public function diff() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $baseline_rows = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}aipsc_file_baseline" );

        $result = array(
            'modified' => array(),
            'missing'  => array(),
            'new'      => array(),
        );

        $known_paths = array();

        foreach ( $baseline_rows as $row ) {
            $known_paths[ $row->file_path ] = true;
            $abs_path = ABSPATH . $row->file_path;

            if ( ! file_exists( $abs_path ) ) {
                $result['missing'][] = array(
                    'file_path'    => $row->file_path,
                    'origin_type'  => $row->origin_type,
                    'sha256_was'   => $row->sha256,
                    'last_seen'    => $row->last_seen,
                );
                continue;
            }

            $current_sha = hash_file( 'sha256', $abs_path );
            if ( $current_sha !== $row->sha256 ) {
                $result['modified'][] = array(
                    'file_path'    => $row->file_path,
                    'origin_type'  => $row->origin_type,
                    'sha256_was'   => $row->sha256,
                    'sha256_now'   => $current_sha,
                    'size_was'     => (int) $row->file_size,
                    'size_now'     => filesize( $abs_path ),
                    'mtime_was'    => (int) $row->mtime,
                    'mtime_now'    => filemtime( $abs_path ),
                );
            }
        }

        // Detect new files not in the baseline.
        $current_files = $this->discover_files();
        foreach ( $current_files as $abs ) {
            $rel = $this->relative_path( $abs );
            if ( ! isset( $known_paths[ $rel ] ) ) {
                $result['new'][] = array(
                    'file_path'   => $rel,
                    'origin_type' => $this->detect_origin( $rel ),
                    'sha256'      => hash_file( 'sha256', $abs ),
                    'file_size'   => filesize( $abs ),
                );
            }
        }

        return $result;
    }

    /**
     * Get baseline statistics.
     *
     * @return array
     */
    public function stats() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $by_origin = $wpdb->get_results(
            "SELECT origin_type, COUNT(*) as cnt FROM {$wpdb->prefix}aipsc_file_baseline GROUP BY origin_type",
            OBJECT_K
        );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $total = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}aipsc_file_baseline" );

        $origins = array();
        foreach ( $by_origin as $key => $row ) {
            $origins[ $key ] = (int) $row->cnt;
        }

        return array(
            'total_files'  => (int) $total,
            'by_origin'    => $origins,
        );
    }

    /**
     * Remove entries for files that no longer exist.
     *
     * @return int Rows removed.
     */
    public function prune_missing() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rows = $wpdb->get_results( "SELECT id, file_path FROM {$wpdb->prefix}aipsc_file_baseline" );

        $to_delete = array();
        foreach ( $rows as $row ) {
            if ( ! file_exists( ABSPATH . $row->file_path ) ) {
                $to_delete[] = (int) $row->id;
            }
        }

        if ( empty( $to_delete ) ) {
            return 0;
        }

        $placeholders = implode( ',', array_fill( 0, count( $to_delete ), '%d' ) );

        // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter
        return (int) $wpdb->query(
            $wpdb->prepare( "DELETE FROM {$wpdb->prefix}aipsc_file_baseline WHERE id IN ({$placeholders})", ...$to_delete )
        );
        // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter
    }

    /* ---------------------------------------------------------------
     * Internal
     * ------------------------------------------------------------- */

    /**
     * Discover all PHP files under ABSPATH for baseline cataloging.
     *
     * @return string[] Absolute paths.
     */
    private function discover_files() {
        $extensions = array( 'php', 'phtml', 'php5', 'php7' );
        $exclude    = array( 'node_modules', '.git', 'vendor', 'cache' );
        $ext_map    = array_flip( $extensions );
        $excl_map   = array_flip( array_map( 'strtolower', $exclude ) );
        $files      = array();
        $root       = rtrim( ABSPATH, '/\\' );

        $iterator = new \RecursiveDirectoryIterator(
            $root,
            \RecursiveDirectoryIterator::SKIP_DOTS | \RecursiveDirectoryIterator::FOLLOW_SYMLINKS
        );

        $filter = new \RecursiveCallbackFilterIterator(
            $iterator,
            function ( $current ) use ( $excl_map ) {
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
            if ( isset( $ext_map[ $ext ] ) ) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    /**
     * Determine the origin type based on relative path.
     *
     * @param string $relative Relative path from ABSPATH.
     * @return string
     */
    private function detect_origin( $relative ) {
        $relative = wp_normalize_path( $relative );

        if ( preg_match( '#^wp-content/plugins/#', $relative ) ) {
            return self::ORIGIN_PLUGIN;
        }
        if ( preg_match( '#^wp-content/themes/#', $relative ) ) {
            return self::ORIGIN_THEME;
        }
        if ( preg_match( '#^wp-content/uploads/#', $relative ) ) {
            return self::ORIGIN_UPLOAD;
        }
        if ( preg_match( '#^wp-(admin|includes)/#', $relative ) || preg_match( '#^wp-[^/]+\.php$#', $relative ) ) {
            return self::ORIGIN_CORE;
        }

        return self::ORIGIN_UNKNOWN;
    }

    /**
     * Detect the plugin/theme slug and version from a relative path.
     *
     * @param string $relative Relative path.
     * @return array{ slug: string, version: string }
     */
    private function detect_component( $relative ) {
        $relative = wp_normalize_path( $relative );

        // Plugin: wp-content/plugins/{slug}/...
        if ( preg_match( '#^wp-content/plugins/([^/]+)/#', $relative, $m ) ) {
            $slug = $m[1];
            if ( ! function_exists( 'get_plugins' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $all = get_plugins();
            foreach ( $all as $file => $data ) {
                if ( 0 === strpos( $file, $slug . '/' ) ) {
                    return array( 'slug' => $slug, 'version' => $data['Version'] ?? '' );
                }
            }
            return array( 'slug' => $slug, 'version' => '' );
        }

        // Theme: wp-content/themes/{slug}/...
        if ( preg_match( '#^wp-content/themes/([^/]+)/#', $relative, $m ) ) {
            $slug  = $m[1];
            $theme = wp_get_theme( $slug );
            return array( 'slug' => $slug, 'version' => $theme->exists() ? $theme->get( 'Version' ) : '' );
        }

        // Core.
        if ( preg_match( '#^wp-(admin|includes)/#', $relative ) ) {
            global $wp_version;
            return array( 'slug' => 'wordpress', 'version' => $wp_version );
        }

        return array( 'slug' => '', 'version' => '' );
    }

    /**
     * Convert absolute path to relative from ABSPATH.
     *
     * @param string $path Absolute path.
     * @return string
     */
    private function relative_path( $path ) {
        $abs  = wp_normalize_path( ABSPATH );
        $path = wp_normalize_path( $path );

        if ( 0 === strpos( $path, $abs ) ) {
            return substr( $path, strlen( $abs ) );
        }

        return $path;
    }
}
