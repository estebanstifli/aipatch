<?php
/**
 * Security scanner module.
 *
 * @package PatchWatch
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class PWW_Scanner
 *
 * Performs local security checks and generates a risk score.
 */
class PWW_Scanner {

    /**
     * @var PWW_Logger
     */
    private $logger;

    /**
     * Constructor.
     *
     * @param PWW_Logger $logger Logger instance.
     */
    public function __construct( PWW_Logger $logger ) {
        $this->logger = $logger;
    }

    /**
     * Run a full security scan.
     *
     * @return array Scan results with 'score', 'issues', 'timestamp'.
     */
    public function run_full_scan() {
        $issues = array();

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

        // Calculate score.
        $score = $this->calculate_score( $issues );

        // Build results.
        $results = array(
            'score'     => $score,
            'issues'    => $issues,
            'timestamp' => time(),
            'version'   => AIPATCH_VERSION,
        );

        // Store results.
        PWW_Utils::update_option( 'scan_results', $results );
        PWW_Utils::update_option( 'last_scan', time() );
        PWW_Utils::update_option( 'security_score', $score );

        /**
         * Fires after a security scan completes.
         *
         * @param array $results Scan results.
         */
        do_action( 'aipatch_scan_completed', $results );

        return $results;
    }

    /**
     * Get the last scan results (cached).
     *
     * @return array|false
     */
    public function get_last_results() {
        return PWW_Utils::get_option( 'scan_results', false );
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
        $dismissed = PWW_Utils::get_option( 'dismissed', array() );

        foreach ( $issues as $issue ) {
            if ( isset( $dismissed[ $issue['id'] ] ) ) {
                continue;
            }
            $score -= PWW_Utils::severity_weight( $issue['severity'] );
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
                'title'           => __( 'WordPress core is outdated', 'patchwatch-wp' ),
                'description'     => sprintf(
                    /* translators: %s: Current WP version. */
                    __( 'You are running WordPress %s. A newer version is available.', 'patchwatch-wp' ),
                    $wp_version
                ),
                'severity'        => 'high',
                'category'        => 'core',
                'why_it_matters'  => __( 'Outdated WordPress versions may contain known security vulnerabilities that attackers can exploit.', 'patchwatch-wp' ),
                'recommendation'  => __( 'Update WordPress to the latest version from Dashboard → Updates.', 'patchwatch-wp' ),
                'dismissible'     => false,
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
                    _n( '%d plugin needs updating', '%d plugins need updating', count( $outdated ), 'patchwatch-wp' ),
                    count( $outdated )
                ),
                'description'     => sprintf(
                    /* translators: %s: Comma-separated plugin names. */
                    __( 'Outdated plugins: %s', 'patchwatch-wp' ),
                    implode( ', ', array_map( 'esc_html', array_slice( $outdated, 0, 10 ) ) )
                ),
                'severity'        => count( $outdated ) > 3 ? 'high' : 'medium',
                'category'        => 'plugins',
                'why_it_matters'  => __( 'Outdated plugins are one of the most common entry points for attackers. Updates often include security patches.', 'patchwatch-wp' ),
                'recommendation'  => __( 'Update all plugins from Dashboard → Updates, or enable auto-updates for trusted plugins.', 'patchwatch-wp' ),
                'dismissible'     => false,
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
                    _n( '%d theme needs updating', '%d themes need updating', count( $outdated ), 'patchwatch-wp' ),
                    count( $outdated )
                ),
                'description'     => sprintf(
                    /* translators: %s: Comma-separated theme names. */
                    __( 'Outdated themes: %s', 'patchwatch-wp' ),
                    implode( ', ', array_map( 'esc_html', $outdated ) )
                ),
                'severity'        => 'medium',
                'category'        => 'themes',
                'why_it_matters'  => __( 'Theme vulnerabilities can be exploited even if the theme is not active. Keep all installed themes updated.', 'patchwatch-wp' ),
                'recommendation'  => __( 'Update themes from Dashboard → Updates. Remove unused themes.', 'patchwatch-wp' ),
                'dismissible'     => true,
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
                'title'           => __( 'Default "admin" username exists', 'patchwatch-wp' ),
                'description'     => __( 'A user account with the username "admin" was detected.', 'patchwatch-wp' ),
                'severity'        => 'medium',
                'category'        => 'users',
                'why_it_matters'  => __( 'The "admin" username is the first one attackers try in brute-force attacks. Using a unique username adds a layer of security.', 'patchwatch-wp' ),
                'recommendation'  => __( 'Create a new administrator account with a unique username, transfer content, and delete the "admin" account.', 'patchwatch-wp' ),
                'dismissible'     => true,
            );
        }

        // Count administrators.
        $admins = get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) );
        if ( count( $admins ) > 3 ) {
            $issues[] = array(
                'id'              => 'too_many_admins',
                'title'           => sprintf(
                    /* translators: %d: Number of admin users. */
                    __( '%d administrator accounts detected', 'patchwatch-wp' ),
                    count( $admins )
                ),
                'description'     => __( 'Having many administrator accounts increases the attack surface.', 'patchwatch-wp' ),
                'severity'        => 'low',
                'category'        => 'users',
                'why_it_matters'  => __( 'Each admin account is a potential target. If one is compromised, the attacker gains full control.', 'patchwatch-wp' ),
                'recommendation'  => __( 'Review administrator accounts and downgrade roles where full admin access is not needed.', 'patchwatch-wp' ),
                'dismissible'     => true,
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

        $hardening = PWW_Utils::get_hardening();
        $xmlrpc_disabled = ! empty( $hardening['disable_xmlrpc'] );

        if ( ! $xmlrpc_disabled ) {
            $issues[] = array(
                'id'              => 'xmlrpc_enabled',
                'title'           => __( 'XML-RPC is enabled', 'patchwatch-wp' ),
                'description'     => __( 'The XML-RPC interface is currently accessible.', 'patchwatch-wp' ),
                'severity'        => 'medium',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'XML-RPC can be exploited for brute-force amplification attacks and DDoS. Most modern sites do not need it.', 'patchwatch-wp' ),
                'recommendation'  => __( 'Disable XML-RPC from the Hardening page unless you use Jetpack, the WordPress mobile app, or XML-RPC clients.', 'patchwatch-wp' ),
                'dismissible'     => true,
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

        if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
            $issues[] = array(
                'id'              => 'file_editor_enabled',
                'title'           => __( 'WordPress file editor is enabled', 'patchwatch-wp' ),
                'description'     => __( 'The built-in plugin and theme editor is accessible from the admin panel.', 'patchwatch-wp' ),
                'severity'        => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'If an attacker gains admin access, they can inject malicious code directly through the file editor.', 'patchwatch-wp' ),
                'recommendation'  => __( 'Add this line to your wp-config.php: define( \'DISALLOW_FILE_EDIT\', true );', 'patchwatch-wp' ),
                'dismissible'     => true,
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
                'title'           => __( 'Debug mode is active', 'patchwatch-wp' ),
                'description'     => __( 'WP_DEBUG is enabled on this site.', 'patchwatch-wp' ),
                'severity'        => $severity,
                'category'        => 'configuration',
                'why_it_matters'  => __( 'Debug mode can expose sensitive information like file paths, database queries, and PHP errors to visitors.', 'patchwatch-wp' ),
                'recommendation'  => __( 'Disable WP_DEBUG in wp-config.php for production sites. Use WP_DEBUG_LOG instead of WP_DEBUG_DISPLAY if you need logging.', 'patchwatch-wp' ),
                'dismissible'     => true,
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
                    __( 'PHP %s is outdated', 'patchwatch-wp' ),
                    PHP_VERSION
                ),
                'description'     => __( 'Your PHP version is no longer receiving active security updates.', 'patchwatch-wp' ),
                'severity'        => $severity,
                'category'        => 'server',
                'why_it_matters'  => __( 'Outdated PHP versions may have unpatched security vulnerabilities and degrade performance.', 'patchwatch-wp' ),
                'recommendation'  => __( 'Contact your hosting provider to upgrade PHP to version 8.1 or higher.', 'patchwatch-wp' ),
                'dismissible'     => true,
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

        $hardening = PWW_Utils::get_hardening();
        if ( empty( $hardening['restrict_rest_api'] ) ) {
            $issues[] = array(
                'id'              => 'rest_api_exposed',
                'title'           => __( 'REST API is publicly accessible', 'patchwatch-wp' ),
                'description'     => __( 'The WordPress REST API exposes user enumeration and other data to unauthenticated requests.', 'patchwatch-wp' ),
                'severity'        => 'low',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'Attackers can enumerate usernames via /wp-json/wp/v2/users and gather information about your site structure.', 'patchwatch-wp' ),
                'recommendation'  => __( 'Enable REST API restrictions from the Hardening page. Compatible mode keeps public endpoints working.', 'patchwatch-wp' ),
                'dismissible'     => true,
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
                    'title'           => __( 'Directory listing may be enabled', 'patchwatch-wp' ),
                    'description'     => __( 'The uploads directory does not have an index file and no .htaccess protection was detected.', 'patchwatch-wp' ),
                    'severity'        => 'low',
                    'category'        => 'server',
                    'why_it_matters'  => __( 'Directory listing allows anyone to browse your files, which can expose sensitive information.', 'patchwatch-wp' ),
                    'recommendation'  => __( 'Add an empty index.php file to your uploads directory or add "Options -Indexes" to your .htaccess file.', 'patchwatch-wp' ),
                    'dismissible'     => true,
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
                    'title'           => __( 'wp-config.php has loose permissions', 'patchwatch-wp' ),
                    'description'     => sprintf(
                        /* translators: %s: File permissions in octal. */
                        __( 'Current permissions: %s. Recommended: 0644 or more restrictive.', 'patchwatch-wp' ),
                        decoct( $perms )
                    ),
                    'severity'        => 'high',
                    'category'        => 'server',
                    'why_it_matters'  => __( 'wp-config.php contains database credentials and secret keys. Loose permissions may allow other users on the server to read it.', 'patchwatch-wp' ),
                    'recommendation'  => __( 'Set wp-config.php permissions to 0644 or 0640 via your hosting file manager or SSH.', 'patchwatch-wp' ),
                    'dismissible'     => false,
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
                'title'           => __( 'Site is not using HTTPS', 'patchwatch-wp' ),
                'description'     => __( 'This site is accessible over an unencrypted HTTP connection.', 'patchwatch-wp' ),
                'severity'        => 'high',
                'category'        => 'server',
                'why_it_matters'  => __( 'Without HTTPS, data between your visitors and the server (including passwords) is sent in plain text and can be intercepted.', 'patchwatch-wp' ),
                'recommendation'  => __( 'Install an SSL certificate (many hosts offer free Let\'s Encrypt certificates) and force HTTPS.', 'patchwatch-wp' ),
                'dismissible'     => false,
            );
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

        global $wp_version;

        $all_plugins    = get_plugins();
        $active_plugins = get_option( 'active_plugins', array() );
        $update_plugins = get_site_transient( 'update_plugins' );
        $update_themes  = get_site_transient( 'update_themes' );
        $admins         = get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) );
        $hardening      = PWW_Utils::get_hardening();

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
            'outdated_themes'    => $outdated_themes,
            'admin_count'        => count( $admins ),
            'admin_user_exists'  => (bool) get_user_by( 'login', 'admin' ),
            'xmlrpc_disabled'    => ! empty( $hardening['disable_xmlrpc'] ),
            'rest_restricted'    => ! empty( $hardening['restrict_rest_api'] ),
            'file_editor_off'    => defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT,
            'debug_active'       => defined( 'WP_DEBUG' ) && WP_DEBUG,
            'ssl_active'         => is_ssl(),
            'login_protected'    => ! empty( $hardening['login_protection'] ),
            'wp_version_hidden'  => ! empty( $hardening['hide_wp_version'] ),
        );
    }
}
