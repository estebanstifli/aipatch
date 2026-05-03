<?php
/**
 * Performance diagnostics module.
 *
 * Detects common reasons a WordPress site may be slow.
 * This is a diagnostic tool, not an optimizer.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Performance
 */
class AIPSC_Performance {

    /**
     * Cached loopback response to avoid duplicate requests.
     *
     * @var array|null
     */
    private $loopback = null;

    /**
     * Run all performance diagnostics.
     *
     * @return array
     */
    public function run_diagnostics() {
        $findings = array();

        $findings[] = $this->check_page_cache();
        $findings[] = $this->check_object_cache();
        $findings[] = $this->check_php_version();
        $findings[] = $this->check_autoloaded_options();
        $findings[] = $this->check_expired_transients();
        $findings[] = $this->check_active_plugins();
        $findings[] = $this->check_database_size();
        $findings[] = $this->check_response_time();

        $health = $this->calculate_health( $findings );

        $quick_wins   = array();
        $bottlenecks  = array();

        foreach ( $findings as $finding ) {
            if ( 'good' === $finding['status'] ) {
                continue;
            }
            if ( 'quick_win' === $finding['category'] ) {
                $quick_wins[] = $finding;
            } else {
                $bottlenecks[] = $finding;
            }
        }

        $results = array(
            'health'       => $health,
            'health_label' => $this->get_health_label( $health ),
            'health_class' => $this->get_health_class( $health ),
            'findings'     => $findings,
            'quick_wins'   => $quick_wins,
            'bottlenecks'  => $bottlenecks,
            'tools'        => $this->get_recommended_tools(),
            'timestamp'    => time(),
        );

        AIPSC_Utils::update_option( 'performance_results', $results );

        return $results;
    }

    /**
     * Get cached diagnostic results.
     *
     * @return array|false
     */
    public function get_last_results() {
        return AIPSC_Utils::get_option( 'performance_results', false );
    }

    /* ---------------------------------------------------------------
     * Individual Checks
     * ------------------------------------------------------------- */

    /**
     * Check for page cache presence.
     *
     * @return array
     */
    private function check_page_cache() {
        $detected   = false;
        $cache_name = '';

        // Check for advanced-cache.php drop-in.
        if ( defined( 'WP_CONTENT_DIR' ) && file_exists( WP_CONTENT_DIR . '/advanced-cache.php' ) ) {
            $detected   = true;
            $cache_name = 'advanced-cache.php drop-in';
        }

        // Check common page cache plugins.
        $cache_plugins = array(
            'wp-super-cache/wp-cache.php'           => 'WP Super Cache',
            'w3-total-cache/w3-total-cache.php'     => 'W3 Total Cache',
            'wp-fastest-cache/wpFastestCache.php'   => 'WP Fastest Cache',
            'litespeed-cache/litespeed-cache.php'   => 'LiteSpeed Cache',
            'wp-rocket/wp-rocket.php'               => 'WP Rocket',
            'cache-enabler/cache-enabler.php'       => 'Cache Enabler',
            'comet-cache/comet-cache.php'           => 'Comet Cache',
            'sg-cachepress/sg-cachepress.php'       => 'SG Optimizer',
            'breeze/breeze.php'                     => 'Breeze',
            'nitropack/main.php'                    => 'NitroPack',
            'powered-cache/powered-cache.php'       => 'Powered Cache',
            'swift-performance-lite/performance.php' => 'Swift Performance',
            'hummingbird-performance/wp-hummingbird.php' => 'Hummingbird',
        );

        $active_plugins = get_option( 'active_plugins', array() );
        foreach ( $cache_plugins as $plugin_file => $name ) {
            if ( in_array( $plugin_file, $active_plugins, true ) ) {
                $detected   = true;
                $cache_name = $name;
                break;
            }
        }

        // Check WP_CACHE constant.
        if ( ! $detected && defined( 'WP_CACHE' ) && WP_CACHE ) {
            $detected   = true;
            $cache_name = 'WP_CACHE';
        }

        return array(
            'id'             => 'page_cache',
            'title'          => __( 'Page Cache', 'aipatch-security-scanner' ),
            'status'         => $detected ? 'good' : 'poor',
            'value'          => $detected
                ? sprintf(
                    /* translators: %s: Cache plugin name. */
                    __( 'Detected (%s)', 'aipatch-security-scanner' ),
                    $cache_name
                )
                : __( 'Not detected', 'aipatch-security-scanner' ),
            'description'    => __( 'Page caching serves pre-built HTML to visitors, significantly reducing server load and improving response times.', 'aipatch-security-scanner' ),
            'recommendation' => $detected
                ? ''
                : __( 'Install and configure a page cache plugin such as WP Super Cache, LiteSpeed Cache, or WP Rocket.', 'aipatch-security-scanner' ),
            'category'       => 'quick_win',
            'details'        => array(),
        );
    }

    /**
     * Check for persistent object cache.
     *
     * @return array
     */
    private function check_object_cache() {
        $using_ext   = wp_using_ext_object_cache();
        $drop_in     = defined( 'WP_CONTENT_DIR' ) && file_exists( WP_CONTENT_DIR . '/object-cache.php' );

        if ( $using_ext ) {
            $status = 'good';
            $value  = __( 'Active', 'aipatch-security-scanner' );
        } elseif ( $drop_in ) {
            $status = 'warning';
            $value  = __( 'Drop-in present but inactive', 'aipatch-security-scanner' );
        } else {
            $status = 'warning';
            $value  = __( 'Not configured', 'aipatch-security-scanner' );
        }

        return array(
            'id'             => 'object_cache',
            'title'          => __( 'Persistent Object Cache', 'aipatch-security-scanner' ),
            'status'         => $status,
            'value'          => $value,
            'description'    => __( 'A persistent object cache (Redis, Memcached) reduces database queries by storing frequently used data in memory.', 'aipatch-security-scanner' ),
            'recommendation' => 'good' === $status
                ? ''
                : __( 'Consider configuring Redis or Memcached if your hosting supports it. Especially beneficial for dynamic or high-traffic sites.', 'aipatch-security-scanner' ),
            'category'       => 'quick_win',
            'details'        => array(),
        );
    }

    /**
     * Check PHP version.
     *
     * @return array
     */
    private function check_php_version() {
        $version     = PHP_VERSION;
        $recommended = '8.1';
        $minimum_ok  = '8.0';

        if ( version_compare( $version, $recommended, '>=' ) ) {
            $status = 'good';
        } elseif ( version_compare( $version, $minimum_ok, '>=' ) ) {
            $status = 'warning';
        } else {
            $status = 'poor';
        }

        return array(
            'id'             => 'php_version_perf',
            'title'          => __( 'PHP Version', 'aipatch-security-scanner' ),
            'status'         => $status,
            'value'          => $version,
            'description'    => sprintf(
                /* translators: %s: Recommended PHP version. */
                __( 'Newer PHP versions bring significant performance improvements. PHP %s or newer is recommended.', 'aipatch-security-scanner' ),
                $recommended
            ),
            'recommendation' => 'good' === $status
                ? ''
                : sprintf(
                    /* translators: %s: Recommended PHP version. */
                    __( 'Upgrade to PHP %s or newer. Each major PHP version typically brings 10–30%% faster execution.', 'aipatch-security-scanner' ),
                    $recommended
                ),
            'category'       => 'quick_win',
            'details'        => array(),
        );
    }

    /**
     * Check autoloaded options size and find the largest ones.
     *
     * @return array
     */
    private function check_autoloaded_options() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $total_size = $wpdb->get_var(
            "SELECT SUM(LENGTH(option_value)) FROM {$wpdb->options} WHERE autoload = 'yes'"
        );
        $total_bytes = (int) $total_size;
        $total_mb    = round( $total_bytes / 1048576, 2 );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $top_options = $wpdb->get_results(
            "SELECT option_name, LENGTH(option_value) AS size FROM {$wpdb->options} WHERE autoload = 'yes' ORDER BY size DESC LIMIT 10",
            ARRAY_A
        );

        if ( $total_mb > 2 ) {
            $status = 'poor';
        } elseif ( $total_mb > 0.8 ) {
            $status = 'warning';
        } else {
            $status = 'good';
        }

        $details = array();
        if ( $top_options ) {
            foreach ( $top_options as $opt ) {
                $details[] = array(
                    'name' => $opt['option_name'],
                    'size' => $this->format_bytes( (int) $opt['size'] ),
                );
            }
        }

        return array(
            'id'             => 'autoloaded_options',
            'title'          => __( 'Autoloaded Options', 'aipatch-security-scanner' ),
            'status'         => $status,
            'value'          => sprintf(
                /* translators: %s: Size in MB. */
                __( '%s MB total', 'aipatch-security-scanner' ),
                number_format_i18n( $total_mb, 2 )
            ),
            'description'    => __( 'WordPress loads all autoloaded options on every page request. Excessive autoloaded data increases memory usage and slows down Time to First Byte.', 'aipatch-security-scanner' ),
            'recommendation' => 'good' === $status
                ? ''
                : __( 'Review the largest autoloaded options below. Some may belong to deactivated plugins or store unnecessary data.', 'aipatch-security-scanner' ),
            'category'       => 'bottleneck',
            'details'        => $details,
        );
    }

    /**
     * Check expired transients count.
     *
     * @return array
     */
    private function check_expired_transients() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $count = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s AND option_value < %d",
                $wpdb->esc_like( '_transient_timeout_' ) . '%',
                time()
            )
        );

        if ( $count > 200 ) {
            $status = 'poor';
        } elseif ( $count > 50 ) {
            $status = 'warning';
        } else {
            $status = 'good';
        }

        return array(
            'id'             => 'expired_transients',
            'title'          => __( 'Expired Transients', 'aipatch-security-scanner' ),
            'status'         => $status,
            'value'          => sprintf(
                /* translators: %d: Number of expired transients. */
                _n( '%d expired transient', '%d expired transients', $count, 'aipatch-security-scanner' ),
                $count
            ),
            'description'    => __( 'Expired transients are temporary data that WordPress has not yet cleaned up. A large number can bloat the options table.', 'aipatch-security-scanner' ),
            'recommendation' => 'good' === $status
                ? ''
                : __( 'A large backlog of expired transients may indicate a cron problem. Consider running a database cleanup.', 'aipatch-security-scanner' ),
            'category'       => 'quick_win',
            'details'        => array(),
        );
    }

    /**
     * Check active plugins count.
     *
     * @return array
     */
    private function check_active_plugins() {
        $active = get_option( 'active_plugins', array() );
        $count  = count( $active );

        if ( $count > 30 ) {
            $status = 'poor';
        } elseif ( $count > 20 ) {
            $status = 'warning';
        } else {
            $status = 'good';
        }

        return array(
            'id'             => 'active_plugins_perf',
            'title'          => __( 'Active Plugins', 'aipatch-security-scanner' ),
            'status'         => $status,
            'value'          => sprintf(
                /* translators: %d: Number of active plugins. */
                _n( '%d active plugin', '%d active plugins', $count, 'aipatch-security-scanner' ),
                $count
            ),
            'description'    => __( 'Each active plugin adds PHP code, hooks, and potentially database queries to every page load. The impact depends on what each plugin does, not just the count.', 'aipatch-security-scanner' ),
            'recommendation' => 'good' === $status
                ? ''
                : __( 'Review active plugins and deactivate any that are not essential. Use Query Monitor to identify which plugins add the most overhead.', 'aipatch-security-scanner' ),
            'category'       => 'bottleneck',
            'details'        => array(),
        );
    }

    /**
     * Check database size and overhead.
     *
     * @return array
     */
    private function check_database_size() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $tables = $wpdb->get_results( 'SHOW TABLE STATUS', ARRAY_A );

        $total_data     = 0;
        $total_index    = 0;
        $total_overhead = 0;
        $large_tables   = array();

        if ( $tables ) {
            foreach ( $tables as $table ) {
                $data     = isset( $table['Data_length'] ) ? (int) $table['Data_length'] : 0;
                $index    = isset( $table['Index_length'] ) ? (int) $table['Index_length'] : 0;
                $overhead = isset( $table['Data_free'] ) ? (int) $table['Data_free'] : 0;

                $total_data     += $data;
                $total_index    += $index;
                $total_overhead += $overhead;

                $size = $data + $index;
                if ( $size > 50 * 1048576 ) { // > 50 MB.
                    $large_tables[] = array(
                        'name' => $table['Name'],
                        'size' => $this->format_bytes( $size ),
                        'rows' => isset( $table['Rows'] ) ? number_format_i18n( (int) $table['Rows'] ) : '?',
                    );
                }
            }
        }

        $total_size  = $total_data + $total_index;
        $total_mb    = round( $total_size / 1048576, 1 );
        $overhead_mb = round( $total_overhead / 1048576, 1 );

        if ( $overhead_mb > 100 ) {
            $status = 'poor';
        } elseif ( $overhead_mb > 50 || $total_mb > 1000 ) {
            $status = 'warning';
        } else {
            $status = 'good';
        }

        return array(
            'id'             => 'database_size',
            'title'          => __( 'Database', 'aipatch-security-scanner' ),
            'status'         => $status,
            'value'          => sprintf(
                /* translators: 1: Total size, 2: Overhead size. */
                __( '%1$s MB (%2$s MB overhead)', 'aipatch-security-scanner' ),
                number_format_i18n( $total_mb, 1 ),
                number_format_i18n( $overhead_mb, 1 )
            ),
            'description'    => __( 'Large databases with significant overhead can slow down queries. Regular optimization helps reclaim wasted space.', 'aipatch-security-scanner' ),
            'recommendation' => 'good' === $status
                ? ''
                : __( 'Consider optimizing your database tables. Use WP-CLI or a database optimization plugin to run OPTIMIZE TABLE.', 'aipatch-security-scanner' ),
            'category'       => 'bottleneck',
            'details'        => $large_tables,
        );
    }

    /**
     * Check homepage response time via loopback request.
     *
     * @return array
     */
    private function check_response_time() {
        $loopback = $this->do_loopback_request();

        if ( is_wp_error( $loopback['response'] ) ) {
            return array(
                'id'             => 'response_time',
                'title'          => __( 'Homepage Response Time', 'aipatch-security-scanner' ),
                'status'         => 'warning',
                'value'          => __( 'Could not measure', 'aipatch-security-scanner' ),
                'description'    => __( 'A loopback request to your homepage failed. This may indicate server configuration issues or blocked loopback requests.', 'aipatch-security-scanner' ),
                'recommendation' => __( 'Check that your site is accessible and that loopback requests are not blocked by firewall or hosting.', 'aipatch-security-scanner' ),
                'category'       => 'bottleneck',
                'details'        => array(),
            );
        }

        $elapsed_ms = $loopback['elapsed_ms'];

        if ( $elapsed_ms > 3000 ) {
            $status = 'poor';
        } elseif ( $elapsed_ms > 1000 ) {
            $status = 'warning';
        } else {
            $status = 'good';
        }

        return array(
            'id'             => 'response_time',
            'title'          => __( 'Homepage Response Time', 'aipatch-security-scanner' ),
            'status'         => $status,
            'value'          => sprintf(
                /* translators: %d: Milliseconds. */
                __( '%d ms', 'aipatch-security-scanner' ),
                $elapsed_ms
            ),
            'description'    => __( 'Server-side response time for your homepage (TTFB). Under 1 second is acceptable, under 500 ms is excellent.', 'aipatch-security-scanner' ),
            'recommendation' => 'good' === $status
                ? ''
                : __( 'High response times typically indicate server-side bottlenecks. Check page cache, database performance, and hosting resources.', 'aipatch-security-scanner' ),
            'category'       => 'bottleneck',
            'details'        => array(),
        );
    }

    /* ---------------------------------------------------------------
     * Helpers
     * ------------------------------------------------------------- */

    /**
     * Perform a loopback request to the homepage (cached per diagnostics run).
     *
     * @return array
     */
    private function do_loopback_request() {
        if ( null !== $this->loopback ) {
            return $this->loopback;
        }

        $start    = microtime( true );
        $response = wp_remote_get( home_url( '/' ), array(
            'timeout'     => 15,
            'sslverify'   => false,
            'redirection' => 0,
        ) );
        $elapsed_ms = (int) round( ( microtime( true ) - $start ) * 1000 );

        $this->loopback = array(
            'response'   => $response,
            'elapsed_ms' => $elapsed_ms,
        );

        return $this->loopback;
    }

    /**
     * Calculate overall health from findings.
     *
     * @param array $findings All diagnostic findings.
     * @return string 'good', 'needs_attention', or 'poor'.
     */
    private function calculate_health( $findings ) {
        $score = 0;
        foreach ( $findings as $f ) {
            if ( 'poor' === $f['status'] ) {
                $score += 2;
            } elseif ( 'warning' === $f['status'] ) {
                ++$score;
            }
        }

        if ( $score <= 1 ) {
            return 'good';
        }
        if ( $score <= 4 ) {
            return 'needs_attention';
        }
        return 'poor';
    }

    /**
     * Get human-readable health label.
     *
     * @param string $health Health key.
     * @return string
     */
    private function get_health_label( $health ) {
        $labels = array(
            'good'            => __( 'Good', 'aipatch-security-scanner' ),
            'needs_attention' => __( 'Needs Attention', 'aipatch-security-scanner' ),
            'poor'            => __( 'Poor', 'aipatch-security-scanner' ),
        );
        return isset( $labels[ $health ] ) ? $labels[ $health ] : $labels['good'];
    }

    /**
     * Get CSS class for health display.
     *
     * @param string $health Health key.
     * @return string
     */
    private function get_health_class( $health ) {
        $classes = array(
            'good'            => 'aipatch-health-good',
            'needs_attention' => 'aipatch-health-warning',
            'poor'            => 'aipatch-health-poor',
        );
        return isset( $classes[ $health ] ) ? $classes[ $health ] : $classes['good'];
    }

    /**
     * Get recommended external diagnostic tools.
     *
     * @return array
     */
    private function get_recommended_tools() {
        return array(
            array(
                'name'        => 'Query Monitor',
                'description' => __( 'Detailed breakdown of database queries, hooks, and HTTP requests per page.', 'aipatch-security-scanner' ),
                'url'         => 'https://wordpress.org/plugins/query-monitor/',
                'type'        => 'plugin',
            ),
            array(
                'name'        => 'PageSpeed Insights',
                'description' => __( 'Google\'s tool for measuring real-world Core Web Vitals and lab performance.', 'aipatch-security-scanner' ),
                'url'         => 'https://pagespeed.web.dev/',
                'type'        => 'external',
            ),
            array(
                'name'        => 'GTmetrix',
                'description' => __( 'Comprehensive page speed analysis with waterfall charts and optimization recommendations.', 'aipatch-security-scanner' ),
                'url'         => 'https://gtmetrix.com/',
                'type'        => 'external',
            ),
            array(
                'name'        => 'WebPageTest',
                'description' => __( 'Advanced performance testing from multiple locations with detailed network analysis.', 'aipatch-security-scanner' ),
                'url'         => 'https://www.webpagetest.org/',
                'type'        => 'external',
            ),
        );
    }

    /**
     * Format bytes into a human-readable string.
     *
     * @param int $bytes Byte count.
     * @return string
     */
    private function format_bytes( $bytes ) {
        if ( $bytes >= 1048576 ) {
            return number_format_i18n( round( $bytes / 1048576, 2 ), 2 ) . ' MB';
        }
        if ( $bytes >= 1024 ) {
            return number_format_i18n( round( $bytes / 1024, 1 ), 1 ) . ' KB';
        }
        return number_format_i18n( $bytes ) . ' B';
    }
}
