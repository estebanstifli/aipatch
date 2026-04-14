<?php
/**
 * Security scanner module.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Scanner
 *
 * Performs local security checks and generates a risk score.
 */
class AIPSC_Scanner {

    /**
     * @var AIPSC_Logger
     */
    private $logger;

    /**
     * Constructor.
     *
     * @param AIPSC_Logger $logger Logger instance.
     */
    public function __construct( AIPSC_Logger $logger ) {
        $this->logger = $logger;
    }

    /**
     * Run a full security scan.
     *
     * @return array Scan results with 'score', 'issues', 'timestamp'.
     */
    public function run_full_scan( $scan_type = 'manual' ) {
        $start_time = microtime( true );
        $issues = array();

        $this->logger->info(
            'scan_started',
            sprintf(
                /* translators: %s: Scan type. */
                __( 'Security scan started (%s).', 'aipatch-security-scanner' ),
                $scan_type
            )
        );

        $issues = array_merge( $issues, $this->check_wp_version() );
        $issues = array_merge( $issues, $this->check_plugins() );
        $issues = array_merge( $issues, $this->check_themes() );
        $issues = array_merge( $issues, $this->check_users() );
        $issues = array_merge( $issues, $this->check_xmlrpc() );
        $issues = array_merge( $issues, $this->check_file_editor() );
        $issues = array_merge( $issues, $this->check_debug_mode() );
        $issues = array_merge( $issues, $this->check_php_version() );
        $issues = array_merge( $issues, $this->check_rest_api_exposure() );
        $issues = array_merge( $issues, $this->check_directory_listing() );
        $issues = array_merge( $issues, $this->check_file_permissions() );
        $issues = array_merge( $issues, $this->check_ssl() );

        // Extended checks (v2).
        $issues = array_merge( $issues, $this->check_inactive_plugins() );
        $issues = array_merge( $issues, $this->check_unused_themes() );
        $issues = array_merge( $issues, $this->check_inactive_admins() );
        $issues = array_merge( $issues, $this->check_db_prefix() );
        $issues = array_merge( $issues, $this->check_sensitive_files() );
        $issues = array_merge( $issues, $this->check_php_in_uploads() );
        $issues = array_merge( $issues, $this->check_security_headers() );
        $issues = array_merge( $issues, $this->check_user_enumeration() );
        $issues = array_merge( $issues, $this->check_application_passwords() );
        $issues = array_merge( $issues, $this->check_auto_updates() );
        $issues = array_merge( $issues, $this->check_salt_keys() );
        $issues = array_merge( $issues, $this->check_debug_log_accessible() );
        $issues = array_merge( $issues, $this->check_user_id_one() );
        $issues = array_merge( $issues, $this->check_database_debug() );
        $issues = array_merge( $issues, $this->check_file_install() );
        $issues = array_merge( $issues, $this->check_cron_health() );

        // Calculate score.
        $score = $this->calculate_score( $issues );

        $duration_ms = (int) round( ( microtime( true ) - $start_time ) * 1000 );

        // Build results.
        $results = array(
            'score'     => $score,
            'issues'    => $issues,
            'timestamp' => time(),
            'version'   => AIPATCH_VERSION,
        );

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
            )
        );

        // Store results.
        AIPSC_Utils::update_option( 'scan_results', $results );
        AIPSC_Utils::update_option( 'last_scan', time() );
        AIPSC_Utils::update_option( 'security_score', $score );

        // Save to scan history table.
        $this->save_scan_history( $scan_type, $score, $issues, $duration_ms );

        /**
         * Fires after a security scan completes.
         *
         * @param array $results Scan results.
         */
        do_action( 'aipatch_scan_completed', $results );

        return $results;
    }

    /**
     * Save a scan record to the history table.
     *
     * @param string $scan_type   manual|cron.
     * @param int    $score       Security score.
     * @param array  $issues      Issue list.
     * @param int    $duration_ms Duration in milliseconds.
     */
    private function save_scan_history( $scan_type, $score, $issues, $duration_ms ) {
        global $wpdb;

        $table = $wpdb->prefix . 'aipsc_scan_history';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $table,
            array(
                'scan_type'    => sanitize_key( $scan_type ),
                'score'        => absint( $score ),
                'issues_count' => count( $issues ),
                'issues_json'  => wp_json_encode( $issues ),
                'duration_ms'  => absint( $duration_ms ),
                'created_at'   => current_time( 'mysql', true ),
            ),
            array( '%s', '%d', '%d', '%s', '%d', '%s' )
        );
    }

    /**
     * Get the last scan results (cached).
     *
     * @return array|false
     */
    public function get_last_results() {
        return AIPSC_Utils::get_option( 'scan_results', false );
    }

    /**
     * Calculate security score from issues.
     *
     * @param array $issues List of issues.
     * @return int Score 0-100.
     */
    private function calculate_score( array $issues ) {
        $score = 100;

        // Filter out dismissed issues.
        $dismissed = AIPSC_Utils::get_option( 'dismissed', array() );

        foreach ( $issues as $issue ) {
            if ( isset( $dismissed[ $issue['id'] ] ) ) {
                continue;
            }
            $score -= AIPSC_Utils::severity_weight( $issue['severity'] );
        }

        return max( 0, min( 100, $score ) );
    }

    /**
     * Check WordPress core version.
     *
     * @return array
     */
    private function check_wp_version() {
        $issues = array();
        global $wp_version;

        $update_data = get_site_transient( 'update_core' );
        $needs_update = false;

        if ( isset( $update_data->updates ) && is_array( $update_data->updates ) ) {
            foreach ( $update_data->updates as $update ) {
                if ( 'upgrade' === $update->response ) {
                    $needs_update = true;
                    break;
                }
            }
        }

        if ( $needs_update ) {
            $issues[] = array(
                'id'              => 'wp_outdated',
                'title'           => __( 'WordPress core is outdated', 'aipatch-security-scanner' ),
                'description'     => sprintf(
                    /* translators: %s: Current WP version. */
                    __( 'You are running WordPress %s. A newer version is available.', 'aipatch-security-scanner' ),
                    $wp_version
                ),
                'severity'        => 'high',
                'category'        => 'core',
                'why_it_matters'  => __( 'Outdated WordPress versions may contain known security vulnerabilities that attackers can exploit.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Update WordPress to the latest version from Dashboard → Updates.', 'aipatch-security-scanner' ),
                'dismissible'     => false,
                'evidence'        => sprintf( 'Installed: %s', $wp_version ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'wp_outdated' ),
            );
        }

        return $issues;
    }

    /**
     * Check plugins for updates and potential issues.
     *
     * @return array
     */
    private function check_plugins() {
        $issues = array();

        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins    = get_plugins();
        $active_plugins = get_option( 'active_plugins', array() );
        $update_data    = get_site_transient( 'update_plugins' );
        $outdated       = array();

        foreach ( $all_plugins as $file => $data ) {
            if ( ! in_array( $file, $active_plugins, true ) ) {
                continue;
            }

            if ( isset( $update_data->response[ $file ] ) ) {
                $outdated[] = $data['Name'];
            }
        }

        if ( ! empty( $outdated ) ) {
            $issues[] = array(
                'id'              => 'plugins_outdated',
                'title'           => sprintf(
                    /* translators: %d: Number of outdated plugins. */
                    _n( '%d plugin needs updating', '%d plugins need updating', count( $outdated ), 'aipatch-security-scanner' ),
                    count( $outdated )
                ),
                'description'     => sprintf(
                    /* translators: %s: Comma-separated plugin names. */
                    __( 'Outdated plugins: %s', 'aipatch-security-scanner' ),
                    implode( ', ', array_map( 'esc_html', array_slice( $outdated, 0, 10 ) ) )
                ),
                'severity'        => count( $outdated ) > 3 ? 'high' : 'medium',
                'category'        => 'plugins',
                'why_it_matters'  => __( 'Outdated plugins are one of the most common entry points for attackers. Updates often include security patches.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Update all plugins from Dashboard → Updates, or enable auto-updates for trusted plugins.', 'aipatch-security-scanner' ),
                'dismissible'     => false,
                'evidence'        => sprintf( 'Outdated: %s', implode( ', ', array_slice( $outdated, 0, 10 ) ) ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'plugins_outdated' ),
            );
        }

        return $issues;
    }

    /**
     * Check themes for updates.
     *
     * @return array
     */
    private function check_themes() {
        $issues      = array();
        $update_data = get_site_transient( 'update_themes' );
        $outdated    = array();

        if ( isset( $update_data->response ) && is_array( $update_data->response ) ) {
            foreach ( $update_data->response as $slug => $data ) {
                $theme = wp_get_theme( $slug );
                if ( $theme->exists() ) {
                    $outdated[] = $theme->get( 'Name' );
                }
            }
        }

        if ( ! empty( $outdated ) ) {
            $issues[] = array(
                'id'              => 'themes_outdated',
                'title'           => sprintf(
                    /* translators: %d: Number of outdated themes. */
                    _n( '%d theme needs updating', '%d themes need updating', count( $outdated ), 'aipatch-security-scanner' ),
                    count( $outdated )
                ),
                'description'     => sprintf(
                    /* translators: %s: Comma-separated theme names. */
                    __( 'Outdated themes: %s', 'aipatch-security-scanner' ),
                    implode( ', ', array_map( 'esc_html', $outdated ) )
                ),
                'severity'        => 'medium',
                'category'        => 'themes',
                'why_it_matters'  => __( 'Theme vulnerabilities can be exploited even if the theme is not active. Keep all installed themes updated.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Update themes from Dashboard → Updates. Remove unused themes.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Outdated: %s', implode( ', ', $outdated ) ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'themes_outdated' ),
            );
        }

        return $issues;
    }

    /**
     * Check user accounts for common issues.
     *
     * @return array
     */
    private function check_users() {
        $issues = array();

        // Check for "admin" username.
        $admin_user = get_user_by( 'login', 'admin' );
        if ( $admin_user ) {
            $issues[] = array(
                'id'              => 'admin_username',
                'title'           => __( 'Default "admin" username exists', 'aipatch-security-scanner' ),
                'description'     => __( 'A user account with the username "admin" was detected.', 'aipatch-security-scanner' ),
                'severity'        => 'medium',
                'category'        => 'users',
                'why_it_matters'  => __( 'The "admin" username is the first one attackers try in brute-force attacks. Using a unique username adds a layer of security.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Create a new administrator account with a unique username, transfer content, and delete the "admin" account.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'User "admin" exists (ID: %d)', $admin_user->ID ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'admin_username' ),
            );
        }

        // Count administrators.
        $admins = get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) );
        if ( count( $admins ) > 3 ) {
            $issues[] = array(
                'id'              => 'too_many_admins',
                'title'           => sprintf(
                    /* translators: %d: Number of admin users. */
                    __( '%d administrator accounts detected', 'aipatch-security-scanner' ),
                    count( $admins )
                ),
                'description'     => __( 'Having many administrator accounts increases the attack surface.', 'aipatch-security-scanner' ),
                'severity'        => 'low',
                'category'        => 'users',
                'why_it_matters'  => __( 'Each admin account is a potential target. If one is compromised, the attacker gains full control.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Review administrator accounts and downgrade roles where full admin access is not needed.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Found %d administrator accounts', count( $admins ) ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'too_many_admins' ),
            );
        }

        return $issues;
    }

    /**
     * Check if XML-RPC is enabled.
     *
     * @return array
     */
    private function check_xmlrpc() {
        $issues = array();

        $hardening = AIPSC_Utils::get_hardening();
        $xmlrpc_disabled = ! empty( $hardening['disable_xmlrpc'] );

        if ( ! $xmlrpc_disabled ) {
            $issues[] = array(
                'id'              => 'xmlrpc_enabled',
                'title'           => __( 'XML-RPC is enabled', 'aipatch-security-scanner' ),
                'description'     => __( 'The XML-RPC interface is currently accessible.', 'aipatch-security-scanner' ),
                'severity'        => 'medium',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'XML-RPC can be exploited for brute-force amplification attacks and DDoS. Most modern sites do not need it.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Disable XML-RPC from the Hardening page unless you use Jetpack, the WordPress mobile app, or XML-RPC clients.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'XML-RPC not disabled via hardening settings',
                'source'          => 'scanner',
                'fingerprint'     => md5( 'xmlrpc_enabled' ),
            );
        }

        return $issues;
    }

    /**
     * Check if the file editor is enabled.
     *
     * @return array
     */
    private function check_file_editor() {
        $issues = array();
        $file_editor_disabled = defined( 'DISALLOW_FILE_EDIT' ) ? (bool) constant( 'DISALLOW_FILE_EDIT' ) : false;

        if ( ! $file_editor_disabled ) {
            $issues[] = array(
                'id'              => 'file_editor_enabled',
                'title'           => __( 'WordPress file editor is enabled', 'aipatch-security-scanner' ),
                'description'     => __( 'The built-in plugin and theme editor is accessible from the admin panel.', 'aipatch-security-scanner' ),
                'severity'        => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'If an attacker gains admin access, they can inject malicious code directly through the file editor.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Add this line to your wp-config.php: define( \'DISALLOW_FILE_EDIT\', true );', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'DISALLOW_FILE_EDIT constant not defined or false',
                'source'          => 'scanner',
                'fingerprint'     => md5( 'file_editor_enabled' ),
            );
        }

        return $issues;
    }

    /**
     * Check if debug mode is active.
     *
     * @return array
     */
    private function check_debug_mode() {
        $issues = array();

        if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
            $severity = 'medium';
            if ( defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY ) {
                $severity = 'high';
            }

            $issues[] = array(
                'id'              => 'debug_enabled',
                'title'           => __( 'Debug mode is active', 'aipatch-security-scanner' ),
                'description'     => __( 'WP_DEBUG is enabled on this site.', 'aipatch-security-scanner' ),
                'severity'        => $severity,
                'category'        => 'configuration',
                'why_it_matters'  => __( 'Debug mode can expose sensitive information like file paths, database queries, and PHP errors to visitors.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Disable WP_DEBUG in wp-config.php for production sites. Use WP_DEBUG_LOG instead of WP_DEBUG_DISPLAY if you need logging.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'WP_DEBUG=%s, WP_DEBUG_DISPLAY=%s', WP_DEBUG ? 'true' : 'false', ( defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY ) ? 'true' : 'false' ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'debug_enabled' ),
            );
        }

        return $issues;
    }

    /**
     * Check PHP version.
     *
     * @return array
     */
    private function check_php_version() {
        $issues = array();

        if ( version_compare( PHP_VERSION, '8.0', '<' ) ) {
            $severity = version_compare( PHP_VERSION, '7.4', '<' ) ? 'high' : 'medium';

            $issues[] = array(
                'id'              => 'php_outdated',
                'title'           => sprintf(
                    /* translators: %s: PHP version. */
                    __( 'PHP %s is outdated', 'aipatch-security-scanner' ),
                    PHP_VERSION
                ),
                'description'     => __( 'Your PHP version is no longer receiving active security updates.', 'aipatch-security-scanner' ),
                'severity'        => $severity,
                'category'        => 'server',
                'why_it_matters'  => __( 'Outdated PHP versions may have unpatched security vulnerabilities and degrade performance.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Contact your hosting provider to upgrade PHP to version 8.1 or higher.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'PHP version: %s', PHP_VERSION ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'php_outdated' ),
            );
        }

        return $issues;
    }

    /**
     * Check REST API exposure.
     *
     * @return array
     */
    private function check_rest_api_exposure() {
        $issues = array();

        $hardening = AIPSC_Utils::get_hardening();
        if ( empty( $hardening['restrict_rest_api'] ) ) {
            $issues[] = array(
                'id'              => 'rest_api_exposed',
                'title'           => __( 'REST API is publicly accessible', 'aipatch-security-scanner' ),
                'description'     => __( 'The WordPress REST API exposes user enumeration and other data to unauthenticated requests.', 'aipatch-security-scanner' ),
                'severity'        => 'low',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'Attackers can enumerate usernames via /wp-json/wp/v2/users and gather information about your site structure.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Enable REST API restrictions from the Hardening page. Compatible mode keeps public endpoints working.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'REST API restrictions not enabled in hardening settings',
                'source'          => 'scanner',
                'fingerprint'     => md5( 'rest_api_exposed' ),
            );
        }

        return $issues;
    }

    /**
     * Check for potential directory listing.
     *
     * @return array
     */
    private function check_directory_listing() {
        $issues = array();

        $uploads_dir = wp_upload_dir();
        $uploads_path = $uploads_dir['basedir'];

        // Check if index file exists in uploads directory.
        $has_index = file_exists( $uploads_path . '/index.php' ) || file_exists( $uploads_path . '/index.html' );

        if ( ! $has_index ) {
            // Also check .htaccess for Options -Indexes.
            $htaccess = ABSPATH . '.htaccess';
            $protected = false;
            if ( file_exists( $htaccess ) ) {
                $content = @file_get_contents( $htaccess );
                if ( $content && stripos( $content, 'Options -Indexes' ) !== false ) {
                    $protected = true;
                }
            }

            if ( ! $protected ) {
                $issues[] = array(
                    'id'              => 'directory_listing',
                    'title'           => __( 'Directory listing may be enabled', 'aipatch-security-scanner' ),
                    'description'     => __( 'The uploads directory does not have an index file and no .htaccess protection was detected.', 'aipatch-security-scanner' ),
                    'severity'        => 'low',
                    'category'        => 'server',
                    'why_it_matters'  => __( 'Directory listing allows anyone to browse your files, which can expose sensitive information.', 'aipatch-security-scanner' ),
                    'recommendation'  => __( 'Add an empty index.php file to your uploads directory or add "Options -Indexes" to your .htaccess file.', 'aipatch-security-scanner' ),
                    'dismissible'     => true,
                    'evidence'        => 'No index.php in uploads directory, no Options -Indexes in .htaccess',
                    'source'          => 'scanner',
                    'fingerprint'     => md5( 'directory_listing' ),
                );
            }
        }

        return $issues;
    }

    /**
     * Check critical file permissions (Unix only).
     *
     * @return array
     */
    private function check_file_permissions() {
        $issues = array();

        // Skip on Windows.
        if ( strtoupper( substr( PHP_OS, 0, 3 ) ) === 'WIN' ) {
            return $issues;
        }

        $wp_config = ABSPATH . 'wp-config.php';
        if ( ! file_exists( $wp_config ) ) {
            $wp_config = dirname( ABSPATH ) . '/wp-config.php';
        }

        if ( file_exists( $wp_config ) ) {
            $perms = fileperms( $wp_config ) & 0777;
            if ( $perms > 0644 ) {
                $issues[] = array(
                    'id'              => 'wpconfig_permissions',
                    'title'           => __( 'wp-config.php has loose permissions', 'aipatch-security-scanner' ),
                    'description'     => sprintf(
                        /* translators: %s: File permissions in octal. */
                        __( 'Current permissions: %s. Recommended: 0644 or more restrictive.', 'aipatch-security-scanner' ),
                        decoct( $perms )
                    ),
                    'severity'        => 'high',
                    'category'        => 'server',
                    'why_it_matters'  => __( 'wp-config.php contains database credentials and secret keys. Loose permissions may allow other users on the server to read it.', 'aipatch-security-scanner' ),
                    'recommendation'  => __( 'Set wp-config.php permissions to 0644 or 0640 via your hosting file manager or SSH.', 'aipatch-security-scanner' ),
                    'dismissible'     => false,
                    'evidence'        => sprintf( 'wp-config.php permissions: 0%s', decoct( $perms ) ),
                    'source'          => 'scanner',
                    'fingerprint'     => md5( 'wpconfig_permissions' ),
                );
            }
        }

        return $issues;
    }

    /**
     * Check if the site uses SSL.
     *
     * @return array
     */
    private function check_ssl() {
        $issues = array();

        if ( ! is_ssl() ) {
            $issues[] = array(
                'id'              => 'no_ssl',
                'title'           => __( 'Site is not using HTTPS', 'aipatch-security-scanner' ),
                'description'     => __( 'This site is accessible over an unencrypted HTTP connection.', 'aipatch-security-scanner' ),
                'severity'        => 'high',
                'category'        => 'server',
                'why_it_matters'  => __( 'Without HTTPS, data between your visitors and the server (including passwords) is sent in plain text and can be intercepted.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Install an SSL certificate (many hosts offer free Let\'s Encrypt certificates) and force HTTPS.', 'aipatch-security-scanner' ),
                'dismissible'     => false,
                'evidence'        => sprintf( 'Site URL: %s', home_url() ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'no_ssl' ),
            );
        }

        return $issues;
    }

    /* ------------------------------------------------------------------ */
    /*  Extended checks (v2)                                              */
    /* ------------------------------------------------------------------ */

    /**
     * Check for inactive plugins that are outdated or may be vulnerable.
     *
     * @return array
     */
    private function check_inactive_plugins() {
        $issues = array();

        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins    = get_plugins();
        $active_plugins = get_option( 'active_plugins', array() );
        $update_data    = get_site_transient( 'update_plugins' );
        $inactive_outdated = array();

        foreach ( $all_plugins as $file => $data ) {
            if ( in_array( $file, $active_plugins, true ) ) {
                continue;
            }

            if ( isset( $update_data->response[ $file ] ) ) {
                $inactive_outdated[] = $data['Name'];
            }
        }

        if ( ! empty( $inactive_outdated ) ) {
            $issues[] = array(
                'id'              => 'inactive_plugins_outdated',
                'title'           => sprintf(
                    /* translators: %d: Number of inactive outdated plugins. */
                    _n( '%d inactive plugin is outdated', '%d inactive plugins are outdated', count( $inactive_outdated ), 'aipatch-security-scanner' ),
                    count( $inactive_outdated )
                ),
                'description'     => sprintf(
                    /* translators: %s: Comma-separated plugin names. */
                    __( 'Inactive outdated plugins: %s', 'aipatch-security-scanner' ),
                    implode( ', ', array_map( 'esc_html', array_slice( $inactive_outdated, 0, 10 ) ) )
                ),
                'severity'        => count( $inactive_outdated ) > 2 ? 'high' : 'medium',
                'category'        => 'plugins',
                'why_it_matters'  => __( 'Inactive plugins can still be exploited if they contain vulnerabilities. Their code is still on the server and accessible.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Delete inactive plugins you no longer need. If you plan to reactivate them, update them first.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Inactive outdated: %s', implode( ', ', array_slice( $inactive_outdated, 0, 10 ) ) ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'inactive_plugins_outdated' ),
            );
        }

        // Check for inactive plugins that haven't been updated in a long time.
        $inactive_count = 0;
        foreach ( $all_plugins as $file => $data ) {
            if ( ! in_array( $file, $active_plugins, true ) ) {
                $inactive_count++;
            }
        }

        if ( $inactive_count > 3 ) {
            $issues[] = array(
                'id'              => 'too_many_inactive_plugins',
                'title'           => sprintf(
                    /* translators: %d: Number of inactive plugins. */
                    __( '%d inactive plugins installed', 'aipatch-security-scanner' ),
                    $inactive_count
                ),
                'description'     => __( 'Having many inactive plugins increases the attack surface even though they are deactivated.', 'aipatch-security-scanner' ),
                'severity'        => 'low',
                'category'        => 'plugins',
                'why_it_matters'  => __( 'Inactive plugin files remain on the server and can be targeted. Each unused plugin is unnecessary risk.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Delete plugins you are not using. Keep only the ones you plan to reactivate soon.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Found %d inactive plugins', $inactive_count ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'too_many_inactive_plugins' ),
            );
        }

        return $issues;
    }

    /**
     * Check for unused themes (not active, not parent of active).
     *
     * @return array
     */
    private function check_unused_themes() {
        $issues = array();

        $active_theme  = get_stylesheet();
        $parent_theme  = get_template();
        $all_themes    = wp_get_themes();
        $update_data   = get_site_transient( 'update_themes' );
        $unused        = array();
        $unused_outdated = array();

        foreach ( $all_themes as $slug => $theme ) {
            if ( $slug === $active_theme || $slug === $parent_theme ) {
                continue;
            }
            $unused[] = $theme->get( 'Name' );

            if ( isset( $update_data->response[ $slug ] ) ) {
                $unused_outdated[] = $theme->get( 'Name' );
            }
        }

        if ( ! empty( $unused_outdated ) ) {
            $issues[] = array(
                'id'              => 'unused_themes_outdated',
                'title'           => sprintf(
                    /* translators: %d: Number of unused outdated themes. */
                    _n( '%d unused theme is outdated', '%d unused themes are outdated', count( $unused_outdated ), 'aipatch-security-scanner' ),
                    count( $unused_outdated )
                ),
                'description'     => sprintf(
                    /* translators: %s: Comma-separated theme names. */
                    __( 'Unused outdated themes: %s', 'aipatch-security-scanner' ),
                    implode( ', ', array_map( 'esc_html', $unused_outdated ) )
                ),
                'severity'        => 'medium',
                'category'        => 'themes',
                'why_it_matters'  => __( 'Unused themes with known vulnerabilities can be exploited even though they are not active. Their PHP files are still accessible on the server.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Delete unused themes. WordPress recommends keeping only the active theme and one default fallback theme.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Unused outdated themes: %s', implode( ', ', $unused_outdated ) ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'unused_themes_outdated' ),
            );
        }

        if ( count( $unused ) > 2 ) {
            $issues[] = array(
                'id'              => 'too_many_unused_themes',
                'title'           => sprintf(
                    /* translators: %d: Number of unused themes. */
                    __( '%d unused themes installed', 'aipatch-security-scanner' ),
                    count( $unused )
                ),
                'description'     => __( 'Multiple inactive themes are installed. Each adds potential attack vectors.', 'aipatch-security-scanner' ),
                'severity'        => 'low',
                'category'        => 'themes',
                'why_it_matters'  => __( 'Extra themes increase your attack surface. Their files can be exploited regardless of activation status.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Remove unused themes, keeping only the active theme and one default theme as fallback.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Found %d unused themes: %s', count( $unused ), implode( ', ', array_slice( $unused, 0, 10 ) ) ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'too_many_unused_themes' ),
            );
        }

        return $issues;
    }

    /**
     * Check for admin users that haven't logged in for a long time.
     *
     * @return array
     */
    private function check_inactive_admins() {
        $issues = array();

        $admins = get_users( array( 'role' => 'administrator', 'fields' => array( 'ID', 'user_login' ) ) );
        $inactive_threshold = strtotime( '-6 months' );
        $inactive_admins = array();

        foreach ( $admins as $admin ) {
            $last_login = get_user_meta( $admin->ID, 'last_login', true );

            // Fallback: check WP session tokens.
            if ( empty( $last_login ) ) {
                $sessions = get_user_meta( $admin->ID, 'session_tokens', true );
                if ( is_array( $sessions ) && ! empty( $sessions ) ) {
                    $latest = 0;
                    foreach ( $sessions as $session ) {
                        if ( isset( $session['login'] ) && $session['login'] > $latest ) {
                            $latest = $session['login'];
                        }
                    }
                    $last_login = $latest > 0 ? $latest : '';
                }
            }

            // If no login recorded at all, flag it.
            if ( empty( $last_login ) ) {
                $inactive_admins[] = $admin->user_login;
            } elseif ( (int) $last_login < $inactive_threshold ) {
                $inactive_admins[] = $admin->user_login;
            }
        }

        if ( ! empty( $inactive_admins ) ) {
            $issues[] = array(
                'id'              => 'inactive_admins',
                'title'           => sprintf(
                    /* translators: %d: Number of inactive admin accounts. */
                    _n( '%d admin account appears inactive', '%d admin accounts appear inactive', count( $inactive_admins ), 'aipatch-security-scanner' ),
                    count( $inactive_admins )
                ),
                'description'     => sprintf(
                    /* translators: %s: Comma-separated usernames. */
                    __( 'Admin accounts with no recent login: %s', 'aipatch-security-scanner' ),
                    implode( ', ', array_map( 'esc_html', $inactive_admins ) )
                ),
                'severity'        => 'medium',
                'category'        => 'users',
                'why_it_matters'  => __( 'Dormant admin accounts are prime targets for attackers. If compromised, they provide full access and may go unnoticed.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Downgrade inactive admin accounts to a lower role, or delete them if they are no longer needed.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Inactive admins (>6 months): %s', implode( ', ', $inactive_admins ) ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'inactive_admins' ),
            );
        }

        return $issues;
    }

    /**
     * Check if the database uses the default wp_ prefix.
     *
     * @return array
     */
    private function check_db_prefix() {
        $issues = array();
        global $wpdb;

        if ( 'wp_' === $wpdb->prefix ) {
            $issues[] = array(
                'id'              => 'default_db_prefix',
                'title'           => __( 'Default database prefix (wp_) in use', 'aipatch-security-scanner' ),
                'description'     => __( 'Your database tables use the default wp_ prefix, which is well-known to attackers.', 'aipatch-security-scanner' ),
                'severity'        => 'low',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'A custom table prefix adds a small layer of defense against automated SQL injection attacks that target the default prefix.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'For new installations, use a custom prefix. For existing sites, changing the prefix requires careful database migration—consider using a security plugin to assist.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Current DB prefix: %s', $wpdb->prefix ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'default_db_prefix' ),
            );
        }

        return $issues;
    }

    /**
     * Check for sensitive files accessible from the web.
     *
     * @return array
     */
    private function check_sensitive_files() {
        $issues = array();

        $sensitive_files = array(
            'readme.html'          => __( 'WordPress readme (exposes version)', 'aipatch-security-scanner' ),
            'license.txt'          => __( 'License file (confirms WordPress)', 'aipatch-security-scanner' ),
            'wp-config-sample.php' => __( 'Sample config (may leak server paths)', 'aipatch-security-scanner' ),
            'xmlrpc.php'           => null, // Already handled in check_xmlrpc.
            'wp-admin/install.php' => __( 'Install script (should not be accessible)', 'aipatch-security-scanner' ),
        );

        $found_files = array();

        foreach ( $sensitive_files as $file => $desc ) {
            if ( null === $desc ) {
                continue;
            }
            if ( file_exists( ABSPATH . $file ) ) {
                $found_files[ $file ] = $desc;
            }
        }

        if ( ! empty( $found_files ) ) {
            $file_list = array();
            foreach ( $found_files as $file => $desc ) {
                $file_list[] = $file;
            }

            $issues[] = array(
                'id'              => 'sensitive_files_exposed',
                'title'           => sprintf(
                    /* translators: %d: Number of sensitive files. */
                    _n( '%d sensitive file is publicly accessible', '%d sensitive files are publicly accessible', count( $found_files ), 'aipatch-security-scanner' ),
                    count( $found_files )
                ),
                'description'     => sprintf(
                    /* translators: %s: Comma-separated file names. */
                    __( 'These files exist and may be accessible: %s', 'aipatch-security-scanner' ),
                    implode( ', ', array_map( 'esc_html', $file_list ) )
                ),
                'severity'        => 'low',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'These files can reveal your WordPress version, server configuration, or confirm that WordPress is installed, making targeted attacks easier.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Delete readme.html, license.txt, and wp-config-sample.php. Block access to wp-admin/install.php via .htaccess or your server config.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Found: %s', implode( ', ', $file_list ) ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'sensitive_files_exposed' ),
            );
        }

        return $issues;
    }

    /**
     * Check if PHP execution is possible in the uploads directory.
     *
     * @return array
     */
    private function check_php_in_uploads() {
        $issues = array();

        $uploads_dir = wp_upload_dir();
        $uploads_path = $uploads_dir['basedir'];

        $php_blocked = false;

        // Check .htaccess in uploads.
        $htaccess = $uploads_path . '/.htaccess';
        if ( file_exists( $htaccess ) ) {
            $content = @file_get_contents( $htaccess );
            if ( $content && preg_match( '/php_flag\s+engine\s+off|<FilesMatch.*\.php.*>.*Deny|RemoveHandler\s+\.php|SetHandler\s+none/si', $content ) ) {
                $php_blocked = true;
            }
        }

        // Check web.config (IIS).
        if ( ! $php_blocked ) {
            $web_config = $uploads_path . '/web.config';
            if ( file_exists( $web_config ) ) {
                $content = @file_get_contents( $web_config );
                if ( $content && stripos( $content, '.php' ) !== false && stripos( $content, 'RequestFiltering' ) !== false ) {
                    $php_blocked = true;
                }
            }
        }

        if ( ! $php_blocked ) {
            $issues[] = array(
                'id'              => 'php_in_uploads',
                'title'           => __( 'PHP execution not blocked in uploads', 'aipatch-security-scanner' ),
                'description'     => __( 'The uploads directory does not have rules preventing PHP file execution.', 'aipatch-security-scanner' ),
                'severity'        => 'high',
                'category'        => 'server',
                'why_it_matters'  => __( 'If an attacker manages to upload a PHP file (via a vulnerability), it could be executed directly, giving them full control of your server.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Add a .htaccess file in your uploads directory with: php_flag engine off. For Nginx, add a location block to deny PHP execution.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'No PHP execution restriction found in uploads directory',
                'source'          => 'scanner',
                'fingerprint'     => md5( 'php_in_uploads' ),
            );
        }

        return $issues;
    }

    /**
     * Check for basic security headers.
     *
     * @return array
     */
    private function check_security_headers() {
        $issues = array();
        $missing_headers = array();

        // Perform a local request to check headers.
        $response = wp_remote_get( home_url( '/' ), array(
            'timeout'     => 10,
            'sslverify'   => false,
            'redirection' => 0,
        ) );

        if ( is_wp_error( $response ) ) {
            return $issues; // Can't check headers, skip silently.
        }

        $headers = wp_remote_retrieve_headers( $response );

        $security_headers = array(
            'x-content-type-options' => 'X-Content-Type-Options',
            'x-frame-options'        => 'X-Frame-Options',
            'x-xss-protection'       => 'X-XSS-Protection',
            'referrer-policy'        => 'Referrer-Policy',
            'permissions-policy'     => 'Permissions-Policy',
        );

        foreach ( $security_headers as $key => $label ) {
            if ( empty( $headers[ $key ] ) ) {
                $missing_headers[] = $label;
            }
        }

        if ( ! empty( $missing_headers ) ) {
            $severity = count( $missing_headers ) >= 4 ? 'medium' : 'low';

            $issues[] = array(
                'id'              => 'missing_security_headers',
                'title'           => sprintf(
                    /* translators: %d: Number of missing headers. */
                    _n( '%d security header missing', '%d security headers missing', count( $missing_headers ), 'aipatch-security-scanner' ),
                    count( $missing_headers )
                ),
                'description'     => sprintf(
                    /* translators: %s: Comma-separated header names. */
                    __( 'Missing headers: %s', 'aipatch-security-scanner' ),
                    implode( ', ', $missing_headers )
                ),
                'severity'        => $severity,
                'category'        => 'server',
                'why_it_matters'  => __( 'Security headers protect against common attacks like clickjacking, MIME-sniffing, and cross-site scripting. Their absence leaves visitors more vulnerable.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Add security headers via your server configuration, .htaccess, or a security plugin. At minimum, add X-Content-Type-Options: nosniff and X-Frame-Options: SAMEORIGIN.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Missing: %s', implode( ', ', $missing_headers ) ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'missing_security_headers' ),
            );
        }

        // Check for Content-Security-Policy separately (important).
        if ( empty( $headers['content-security-policy'] ) ) {
            $issues[] = array(
                'id'              => 'no_csp_header',
                'title'           => __( 'Content-Security-Policy header not set', 'aipatch-security-scanner' ),
                'description'     => __( 'No Content-Security-Policy header was detected on the homepage.', 'aipatch-security-scanner' ),
                'severity'        => 'low',
                'category'        => 'server',
                'why_it_matters'  => __( 'CSP is one of the most effective defenses against XSS attacks. Without it, injected scripts can execute freely.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Implement a Content-Security-Policy header. Start with a report-only policy to test before enforcing.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'Content-Security-Policy header not present',
                'source'          => 'scanner',
                'fingerprint'     => md5( 'no_csp_header' ),
            );
        }

        return $issues;
    }

    /**
     * Check for user enumeration exposure.
     *
     * @return array
     */
    private function check_user_enumeration() {
        $issues = array();

        $hardening = AIPSC_Utils::get_hardening();

        // Check if author archives or ?author= parameter is accessible.
        $author_enum_blocked = ! empty( $hardening['block_author_scanning'] );

        if ( ! $author_enum_blocked ) {
            // Test if ?author=1 redirects to an author archive (reveals usernames).
            $response = wp_remote_get( add_query_arg( 'author', '1', home_url( '/' ) ), array(
                'timeout'     => 10,
                'sslverify'   => false,
                'redirection' => 0,
            ) );

            $enum_possible = false;
            if ( ! is_wp_error( $response ) ) {
                $status = wp_remote_retrieve_response_code( $response );
                $location = wp_remote_retrieve_header( $response, 'location' );
                // A 301 redirect to /author/username/ confirms enumeration works.
                if ( 301 === $status && ! empty( $location ) && strpos( $location, '/author/' ) !== false ) {
                    $enum_possible = true;
                }
                // A 200 on the author page also means enumeration is possible.
                if ( 200 === $status ) {
                    $enum_possible = true;
                }
            }

            if ( $enum_possible ) {
                $issues[] = array(
                    'id'              => 'user_enumeration',
                    'title'           => __( 'User enumeration is possible', 'aipatch-security-scanner' ),
                    'description'     => __( 'Usernames can be discovered via the ?author= parameter or author archive URLs.', 'aipatch-security-scanner' ),
                    'severity'        => 'medium',
                    'category'        => 'users',
                    'why_it_matters'  => __( 'Knowing valid usernames makes brute-force attacks much more effective. Attackers only need to guess the password.', 'aipatch-security-scanner' ),
                    'recommendation'  => __( 'Block author scanning from the Hardening page, or redirect/block ?author= requests in your .htaccess or server config.', 'aipatch-security-scanner' ),
                    'dismissible'     => true,
                    'evidence'        => 'GET /?author=1 reveals user information',
                    'source'          => 'scanner',
                    'fingerprint'     => md5( 'user_enumeration' ),
                );
            }
        }

        return $issues;
    }

    /**
     * Check if Application Passwords feature is enabled.
     *
     * @return array
     */
    private function check_application_passwords() {
        $issues = array();

        // Application Passwords were added in WP 5.6.
        if ( version_compare( get_bloginfo( 'version' ), '5.6', '<' ) ) {
            return $issues;
        }

        // Check if Application Passwords is enabled (default is true in WP 5.6+).
        $app_passwords_enabled = apply_filters( 'wp_is_application_passwords_available', true );

        if ( $app_passwords_enabled ) {
            // Check if any users actually have application passwords set.
            $admins = get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) );
            $users_with_app_passwords = 0;

            foreach ( $admins as $admin_id ) {
                $app_passwords = get_user_meta( $admin_id, '_application_passwords', true );
                if ( ! empty( $app_passwords ) ) {
                    $users_with_app_passwords++;
                }
            }

            if ( $users_with_app_passwords > 0 ) {
                $issues[] = array(
                    'id'              => 'app_passwords_in_use',
                    'title'           => sprintf(
                        /* translators: %d: Number of admin users with app passwords. */
                        _n( '%d admin has application passwords', '%d admins have application passwords', $users_with_app_passwords, 'aipatch-security-scanner' ),
                        $users_with_app_passwords
                    ),
                    'description'     => __( 'Application Passwords provide API access that bypasses two-factor authentication if configured.', 'aipatch-security-scanner' ),
                    'severity'        => 'medium',
                    'category'        => 'users',
                    'why_it_matters'  => __( 'Application Passwords bypass normal login protections including 2FA. If one leaks, an attacker gets full API access.', 'aipatch-security-scanner' ),
                    'recommendation'  => __( 'Review active application passwords in each admin user\'s profile. Remove any that are not actively used by trusted applications.', 'aipatch-security-scanner' ),
                    'dismissible'     => true,
                    'evidence'        => sprintf( '%d admin account(s) with application passwords', $users_with_app_passwords ),
                    'source'          => 'scanner',
                    'fingerprint'     => md5( 'app_passwords_in_use' ),
                );
            } else {
                // Just flag that the feature is enabled.
                $issues[] = array(
                    'id'              => 'app_passwords_enabled',
                    'title'           => __( 'Application Passwords feature is enabled', 'aipatch-security-scanner' ),
                    'description'     => __( 'The Application Passwords feature is active. Any user can generate API credentials.', 'aipatch-security-scanner' ),
                    'severity'        => 'info',
                    'category'        => 'configuration',
                    'why_it_matters'  => __( 'While not a vulnerability itself, Application Passwords provide another authentication vector that should be monitored.', 'aipatch-security-scanner' ),
                    'recommendation'  => __( 'If no integrations need Application Passwords, disable the feature by adding: add_filter( \'wp_is_application_passwords_available\', \'__return_false\' );', 'aipatch-security-scanner' ),
                    'dismissible'     => true,
                    'evidence'        => 'Application Passwords feature active, no admin app passwords found',
                    'source'          => 'scanner',
                    'fingerprint'     => md5( 'app_passwords_enabled' ),
                );
            }
        }

        return $issues;
    }

    /**
     * Check if auto-updates are enabled for core and plugins.
     *
     * @return array
     */
    private function check_auto_updates() {
        $issues = array();

        // Check core auto-updates.
        $core_auto_update = false;
        if ( defined( 'WP_AUTO_UPDATE_CORE' ) ) {
            $core_auto_update = WP_AUTO_UPDATE_CORE;
        } else {
            // Default in modern WP is 'minor'.
            $core_auto_update = 'minor';
        }

        if ( false === $core_auto_update || 'false' === $core_auto_update ) {
            $issues[] = array(
                'id'              => 'core_auto_updates_off',
                'title'           => __( 'Core auto-updates are disabled', 'aipatch-security-scanner' ),
                'description'     => __( 'Automatic updates for WordPress core are completely disabled.', 'aipatch-security-scanner' ),
                'severity'        => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'Security patches are often released urgently. Without auto-updates, your site remains vulnerable until you manually update.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'At minimum, enable minor/security auto-updates by setting WP_AUTO_UPDATE_CORE to "minor" in wp-config.php.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'WP_AUTO_UPDATE_CORE = %s', var_export( $core_auto_update, true ) ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'core_auto_updates_off' ),
            );
        }

        // Check plugin auto-updates.
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $active_plugins = get_option( 'active_plugins', array() );
        $auto_update_plugins = get_site_option( 'auto_update_plugins', array() );

        if ( ! is_array( $auto_update_plugins ) ) {
            $auto_update_plugins = array();
        }

        $no_auto_update = array();
        $all_plugins = get_plugins();

        foreach ( $active_plugins as $plugin_file ) {
            if ( ! in_array( $plugin_file, $auto_update_plugins, true ) ) {
                if ( isset( $all_plugins[ $plugin_file ] ) ) {
                    $no_auto_update[] = $all_plugins[ $plugin_file ]['Name'];
                }
            }
        }

        if ( count( $no_auto_update ) > 0 && count( $active_plugins ) > 0 ) {
            $pct = round( ( count( $no_auto_update ) / count( $active_plugins ) ) * 100 );
            if ( $pct > 50 ) {
                $issues[] = array(
                    'id'              => 'plugins_auto_updates_off',
                    'title'           => sprintf(
                        /* translators: %d: Percentage of plugins without auto-updates. */
                        __( '%d%% of active plugins lack auto-updates', 'aipatch-security-scanner' ),
                        $pct
                    ),
                    'description'     => sprintf(
                        /* translators: %1$d: Plugins without auto-update, %2$d: Total active plugins. */
                        __( '%1$d of %2$d active plugins do not have auto-updates enabled.', 'aipatch-security-scanner' ),
                        count( $no_auto_update ),
                        count( $active_plugins )
                    ),
                    'severity'        => 'medium',
                    'category'        => 'plugins',
                    'why_it_matters'  => __( 'Plugins without auto-updates won\'t receive security patches automatically, leaving your site exposed between your manual checks.', 'aipatch-security-scanner' ),
                    'recommendation'  => __( 'Enable auto-updates for trusted plugins from the Plugins page, or at least for plugins that handle user input, authentication, or payments.', 'aipatch-security-scanner' ),
                    'dismissible'     => true,
                    'evidence'        => sprintf( '%d of %d plugins without auto-updates', count( $no_auto_update ), count( $active_plugins ) ),
                    'source'          => 'scanner',
                    'fingerprint'     => md5( 'plugins_auto_updates_off' ),
                );
            }
        }

        return $issues;
    }

    /**
     * Check SALT keys quality in wp-config.php.
     *
     * @return array
     */
    private function check_salt_keys() {
        $issues = array();

        $salt_constants = array(
            'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
            'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT',
        );

        $weak_salts = array();
        $default_phrase = 'put your unique phrase here';

        foreach ( $salt_constants as $constant ) {
            if ( ! defined( $constant ) ) {
                $weak_salts[] = $constant;
            } else {
                $value = constant( $constant );
                if ( empty( $value ) || $value === $default_phrase || strlen( $value ) < 32 ) {
                    $weak_salts[] = $constant;
                }
            }
        }

        if ( ! empty( $weak_salts ) ) {
            $issues[] = array(
                'id'              => 'weak_salt_keys',
                'title'           => sprintf(
                    /* translators: %d: Number of weak salt keys. */
                    _n( '%d security salt key is weak or missing', '%d security salt keys are weak or missing', count( $weak_salts ), 'aipatch-security-scanner' ),
                    count( $weak_salts )
                ),
                'description'     => sprintf(
                    /* translators: %s: Comma-separated key names. */
                    __( 'Weak keys: %s', 'aipatch-security-scanner' ),
                    implode( ', ', $weak_salts )
                ),
                'severity'        => count( $weak_salts ) > 4 ? 'high' : 'medium',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'Salt keys protect cookies and passwords. Weak or default keys make it easier for attackers to forge session cookies and hijack accounts.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Generate new salt keys at https://api.wordpress.org/secret-key/1.1/salt/ and replace them in your wp-config.php.', 'aipatch-security-scanner' ),
                'dismissible'     => false,
                'evidence'        => sprintf( 'Weak/missing: %s', implode( ', ', $weak_salts ) ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'weak_salt_keys' ),
            );
        }

        return $issues;
    }

    /**
     * Check if the debug log file is publicly accessible.
     *
     * @return array
     */
    private function check_debug_log_accessible() {
        $issues = array();

        $debug_log = WP_CONTENT_DIR . '/debug.log';

        if ( file_exists( $debug_log ) ) {
            $size = filesize( $debug_log );

            $issues[] = array(
                'id'              => 'debug_log_exists',
                'title'           => __( 'Debug log file exists in wp-content', 'aipatch-security-scanner' ),
                'description'     => sprintf(
                    /* translators: %s: File size. */
                    __( 'A debug.log file (%s) was found. This file might be accessible publicly.', 'aipatch-security-scanner' ),
                    size_format( $size )
                ),
                'severity'        => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'The debug log can contain sensitive information like file paths, database queries, plugin errors, and user data that help attackers plan an attack.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Delete the debug.log file and block access to it via .htaccess. If debugging is needed, use a custom log path outside the web root.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'debug.log found at %s (%s)', $debug_log, size_format( $size ) ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'debug_log_exists' ),
            );
        }

        return $issues;
    }

    /**
     * Check if user ID 1 is an active administrator (predictable target).
     *
     * @return array
     */
    private function check_user_id_one() {
        $issues = array();

        $user = get_user_by( 'ID', 1 );
        if ( $user && in_array( 'administrator', $user->roles, true ) ) {
            $issues[] = array(
                'id'              => 'admin_user_id_one',
                'title'           => __( 'User ID 1 is an administrator', 'aipatch-security-scanner' ),
                'description'     => sprintf(
                    /* translators: %s: Username. */
                    __( 'The user "%s" (ID 1) has administrator privileges. This is the first target in enumeration attacks.', 'aipatch-security-scanner' ),
                    $user->user_login
                ),
                'severity'        => 'low',
                'category'        => 'users',
                'why_it_matters'  => __( 'User ID 1 is the default first account. Attackers specifically target it for brute-force and privilege escalation attacks.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Create a new admin account, transfer ownership of posts, and change user ID 1 to a subscriber or editor role.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'User ID 1 (%s) is administrator', $user->user_login ),
                'source'          => 'scanner',
                'fingerprint'     => md5( 'admin_user_id_one' ),
            );
        }

        return $issues;
    }

    /**
     * Check if database error reporting is exposed.
     *
     * @return array
     */
    private function check_database_debug() {
        $issues = array();
        global $wpdb;

        if ( defined( 'SAVEQUERIES' ) && SAVEQUERIES ) {
            $issues[] = array(
                'id'              => 'savequeries_enabled',
                'title'           => __( 'SAVEQUERIES is enabled', 'aipatch-security-scanner' ),
                'description'     => __( 'WordPress is logging all database queries. This impacts performance and may expose sensitive data.', 'aipatch-security-scanner' ),
                'severity'        => 'medium',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'SAVEQUERIES stores every SQL query in memory, reducing performance and potentially exposing database structure if debug information leaks.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Remove or set SAVEQUERIES to false in wp-config.php. Use it only during active debugging sessions.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'SAVEQUERIES constant is true',
                'source'          => 'scanner',
                'fingerprint'     => md5( 'savequeries_enabled' ),
            );
        }

        if ( property_exists( $wpdb, 'show_errors' ) && $wpdb->show_errors ) {
            $issues[] = array(
                'id'              => 'db_errors_shown',
                'title'           => __( 'Database errors are displayed', 'aipatch-security-scanner' ),
                'description'     => __( 'Database error messages are being shown, potentially exposing table names and query structure.', 'aipatch-security-scanner' ),
                'severity'        => 'medium',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'Visible database errors help attackers understand your database structure and craft SQL injection attacks.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Ensure $wpdb->show_errors is not enabled on production. This is typically controlled by WP_DEBUG.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'wpdb show_errors is enabled',
                'source'          => 'scanner',
                'fingerprint'     => md5( 'db_errors_shown' ),
            );
        }

        return $issues;
    }

    /**
     * Check if DISALLOW_FILE_MODS is properly set.
     *
     * @return array
     */
    private function check_file_install() {
        $issues = array();

        // Check if file modifications are allowed (plugin/theme installs from admin).
        $file_mods_allowed = ! defined( 'DISALLOW_FILE_MODS' ) || ! DISALLOW_FILE_MODS;

        // Only flag this on sites that should be locked down.
        if ( $file_mods_allowed && defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) {
            $issues[] = array(
                'id'              => 'file_mods_allowed',
                'title'           => __( 'Plugin/theme installation from admin is allowed', 'aipatch-security-scanner' ),
                'description'     => __( 'File editing is disabled but file installations are still possible from the admin panel.', 'aipatch-security-scanner' ),
                'severity'        => 'low',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'If an attacker gains admin access, they could install a malicious plugin or theme, even though the file editor is disabled.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'For maximum security, add define( \'DISALLOW_FILE_MODS\', true ); to wp-config.php. This disables all file changes from the admin panel.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'DISALLOW_FILE_EDIT is true but DISALLOW_FILE_MODS is not set',
                'source'          => 'scanner',
                'fingerprint'     => md5( 'file_mods_allowed' ),
            );
        }

        return $issues;
    }

    /**
     * Check WordPress cron system health.
     *
     * @return array
     */
    private function check_cron_health() {
        $issues = array();

        // Check if WP Cron is disabled.
        if ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) {
            // Cron is disabled—check when last ran by looking at the cron array.
            $crons = _get_cron_array();
            if ( ! empty( $crons ) ) {
                $next = min( array_keys( $crons ) );
                $overdue = $next < ( time() - HOUR_IN_SECONDS );

                if ( $overdue ) {
                    $issues[] = array(
                        'id'              => 'cron_overdue',
                        'title'           => __( 'WP-Cron is disabled and tasks are overdue', 'aipatch-security-scanner' ),
                        'description'     => __( 'DISABLE_WP_CRON is true and scheduled tasks appear overdue.', 'aipatch-security-scanner' ),
                        'severity'        => 'medium',
                        'category'        => 'configuration',
                        'why_it_matters'  => __( 'If cron isn\'t running, scheduled security scans, plugin updates, and other maintenance tasks won\'t execute.', 'aipatch-security-scanner' ),
                        'recommendation'  => __( 'Ensure a real system cron job calls wp-cron.php regularly (e.g. every 5 minutes) or remove DISABLE_WP_CRON.', 'aipatch-security-scanner' ),
                        'dismissible'     => true,
                        'evidence'        => sprintf( 'DISABLE_WP_CRON=true, next task due: %s', wp_date( 'Y-m-d H:i:s', $next ) ),
                        'source'          => 'scanner',
                        'fingerprint'     => md5( 'cron_overdue' ),
                    );
                }
            }
        }

        return $issues;
    }

    /**
     * Get quick summary data for dashboard cards.
     *
     * @return array
     */
    public function get_summary() {
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        global $wp_version, $wpdb;

        $all_plugins    = get_plugins();
        $active_plugins = get_option( 'active_plugins', array() );
        $update_plugins = get_site_transient( 'update_plugins' );
        $update_themes  = get_site_transient( 'update_themes' );
        $admins         = get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) );
        $hardening      = AIPSC_Utils::get_hardening();
        $file_editor_off = defined( 'DISALLOW_FILE_EDIT' ) ? (bool) constant( 'DISALLOW_FILE_EDIT' ) : false;

        $outdated_plugins = 0;
        if ( isset( $update_plugins->response ) ) {
            foreach ( $update_plugins->response as $file => $data ) {
                if ( in_array( $file, $active_plugins, true ) ) {
                    $outdated_plugins++;
                }
            }
        }

        $outdated_themes = 0;
        if ( isset( $update_themes->response ) ) {
            $outdated_themes = count( $update_themes->response );
        }

        return array(
            'wp_version'         => $wp_version,
            'php_version'        => PHP_VERSION,
            'active_plugins'     => count( $active_plugins ),
            'total_plugins'      => count( $all_plugins ),
            'outdated_plugins'   => $outdated_plugins,
            'inactive_plugins'   => count( $all_plugins ) - count( $active_plugins ),
            'outdated_themes'    => $outdated_themes,
            'unused_themes'      => max( 0, count( wp_get_themes() ) - 2 ),
            'admin_count'        => count( $admins ),
            'admin_user_exists'  => (bool) get_user_by( 'login', 'admin' ),
            'db_prefix_default'  => 'wp_' === $wpdb->prefix,
            'xmlrpc_disabled'    => ! empty( $hardening['disable_xmlrpc'] ),
            'rest_restricted'    => ! empty( $hardening['restrict_rest_api'] ),
            'file_editor_off'    => $file_editor_off,
            'debug_active'       => defined( 'WP_DEBUG' ) && WP_DEBUG,
            'ssl_active'         => is_ssl(),
            'login_protected'    => ! empty( $hardening['login_protection'] ),
            'wp_version_hidden'  => ! empty( $hardening['hide_wp_version'] ),
            'auto_updates_core'  => ( ! defined( 'WP_AUTO_UPDATE_CORE' ) || false !== WP_AUTO_UPDATE_CORE ),
            'total_checks'       => 28,
        );
    }
}
