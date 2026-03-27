<?php
/**
 * Hardening module – applies security rules via WordPress filters.
 *
 * @package PatchWatch
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class PWW_Hardening
 */
class PWW_Hardening {

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
     * Apply all active hardening rules.
     * Called early during plugin bootstrap.
     */
    public function apply_active_rules() {
        $options = PWW_Utils::get_hardening();

        if ( ! empty( $options['disable_xmlrpc'] ) ) {
            $this->apply_disable_xmlrpc();
        }

        if ( ! empty( $options['hide_wp_version'] ) ) {
            $this->apply_hide_wp_version();
        }

        if ( ! empty( $options['restrict_rest_api'] ) ) {
            $this->apply_restrict_rest_api();
        }

        if ( ! empty( $options['login_protection'] ) ) {
            $this->apply_login_protection( $options );
        }
    }

    /**
     * Toggle a hardening option.
     *
     * @param string $key   Hardening option key.
     * @param bool   $value Enable or disable.
     * @return bool
     */
    public function toggle( $key, $value ) {
        $defaults = PWW_Utils::get_default_hardening();
        if ( ! array_key_exists( $key, $defaults ) ) {
            return false;
        }

        $options = PWW_Utils::get_hardening();
        $options[ $key ] = (bool) $value;
        $result = PWW_Utils::update_option( 'hardening', $options );

        if ( $result ) {
            $action = $value ? 'enabled' : 'disabled';
            $this->logger->info(
                'hardening_toggle',
                sprintf(
                    /* translators: 1: Option key, 2: Action. */
                    __( 'Hardening option "%1$s" %2$s.', 'patchwatch-wp' ),
                    $key,
                    $action
                )
            );
        }

        return $result;
    }

    /**
     * Update a numeric hardening setting.
     *
     * @param string $key   Setting key.
     * @param int    $value Value.
     * @return bool
     */
    public function update_setting( $key, $value ) {
        $allowed = array( 'login_max_attempts', 'login_lockout_duration' );
        if ( ! in_array( $key, $allowed, true ) ) {
            return false;
        }

        $options = PWW_Utils::get_hardening();
        $options[ $key ] = absint( $value );
        return PWW_Utils::update_option( 'hardening', $options );
    }

    /**
     * Get current hardening status for UI.
     *
     * @return array
     */
    public function get_status() {
        $options = PWW_Utils::get_hardening();

        return array(
            array(
                'key'           => 'disable_xmlrpc',
                'title'         => __( 'Disable XML-RPC', 'patchwatch-wp' ),
                'description'   => __( 'Blocks external XML-RPC requests. Disable if you use the WordPress mobile app, Jetpack, or remote publishing tools.', 'patchwatch-wp' ),
                'enabled'       => ! empty( $options['disable_xmlrpc'] ),
                'warning'       => __( 'May break Jetpack and WordPress mobile app connectivity.', 'patchwatch-wp' ),
                'severity'      => 'medium',
            ),
            array(
                'key'           => 'hide_wp_version',
                'title'         => __( 'Hide WordPress Version', 'patchwatch-wp' ),
                'description'   => __( 'Removes the WordPress version number from the page source, RSS feeds, and scripts.', 'patchwatch-wp' ),
                'enabled'       => ! empty( $options['hide_wp_version'] ),
                'warning'       => '',
                'severity'      => 'low',
            ),
            array(
                'key'           => 'restrict_rest_api',
                'title'         => __( 'Restrict REST API', 'patchwatch-wp' ),
                'description'   => __( 'Limits sensitive REST API endpoints (like user enumeration) to authenticated users only. Public endpoints for themes and plugins remain accessible.', 'patchwatch-wp' ),
                'enabled'       => ! empty( $options['restrict_rest_api'] ),
                'warning'       => __( 'May affect headless/decoupled setups or plugins that rely on public REST access.', 'patchwatch-wp' ),
                'severity'      => 'low',
            ),
            array(
                'key'           => 'login_protection',
                'title'         => __( 'Login Brute-Force Protection', 'patchwatch-wp' ),
                'description'   => sprintf(
                    /* translators: 1: Max attempts, 2: Lockout duration in minutes. */
                    __( 'Limits login attempts to %1$d tries per IP, with a %2$d-minute lockout after exceeding the limit.', 'patchwatch-wp' ),
                    $options['login_max_attempts'],
                    $options['login_lockout_duration']
                ),
                'enabled'       => ! empty( $options['login_protection'] ),
                'warning'       => __( 'Legitimate users may be locked out temporarily if they forget their password.', 'patchwatch-wp' ),
                'severity'      => 'high',
                'settings'      => array(
                    'login_max_attempts'    => $options['login_max_attempts'],
                    'login_lockout_duration' => $options['login_lockout_duration'],
                ),
            ),
        );
    }

    /* ---------------------------------------------------------------
     * Hardening implementations
     * ------------------------------------------------------------- */

    /**
     * Disable XML-RPC via filters.
     */
    private function apply_disable_xmlrpc() {
        add_filter( 'xmlrpc_enabled', '__return_false' );
        add_filter( 'xmlrpc_methods', function () {
            return array();
        } );

        // Remove the X-Pingback header.
        add_filter( 'wp_headers', function ( $headers ) {
            unset( $headers['X-Pingback'] );
            return $headers;
        } );
    }

    /**
     * Hide WordPress version from frontend.
     */
    private function apply_hide_wp_version() {
        // Remove generator meta tag.
        remove_action( 'wp_head', 'wp_generator' );

        // Remove version from feeds.
        add_filter( 'the_generator', '__return_empty_string' );

        // Remove version from scripts and styles.
        add_filter( 'style_loader_src', array( $this, 'remove_version_query' ), 10, 2 );
        add_filter( 'script_loader_src', array( $this, 'remove_version_query' ), 10, 2 );
    }

    /**
     * Remove version query string from enqueued assets.
     *
     * @param string $src    Source URL.
     * @param string $handle Handle name.
     * @return string
     */
    public function remove_version_query( $src, $handle = '' ) {
        if ( strpos( $src, 'ver=' ) ) {
            $src = remove_query_arg( 'ver', $src );
        }
        return $src;
    }

    /**
     * Restrict REST API for unauthenticated users on sensitive endpoints.
     */
    private function apply_restrict_rest_api() {
        add_filter( 'rest_authentication_errors', function ( $result ) {
            // Don't override existing auth errors.
            if ( true === $result || is_wp_error( $result ) ) {
                return $result;
            }

            // Allow authenticated users.
            if ( is_user_logged_in() ) {
                return $result;
            }

            // Check compat mode.
            $settings = PWW_Utils::get_settings();
            if ( ! empty( $settings['rest_compat_mode'] ) ) {
                return $result;
            }

            // Block sensitive endpoints for unauthenticated users.
            $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

            // Sensitive patterns: user enumeration, settings.
            $blocked_patterns = array(
                '/wp/v2/users',
                '/wp/v2/settings',
            );

            foreach ( $blocked_patterns as $pattern ) {
                if ( strpos( $request_uri, $pattern ) !== false ) {
                    return new WP_Error(
                        'rest_forbidden',
                        __( 'Authentication is required to access this endpoint.', 'patchwatch-wp' ),
                        array( 'status' => 401 )
                    );
                }
            }

            return $result;
        } );
    }

    /**
     * Apply login brute-force protection.
     *
     * @param array $options Hardening options.
     */
    private function apply_login_protection( $options ) {
        $max_attempts    = isset( $options['login_max_attempts'] ) ? absint( $options['login_max_attempts'] ) : 5;
        $lockout_minutes = isset( $options['login_lockout_duration'] ) ? absint( $options['login_lockout_duration'] ) : 15;

        // Check lockout on authentication.
        add_filter( 'authenticate', function ( $user, $username ) use ( $max_attempts, $lockout_minutes ) {
            if ( empty( $username ) ) {
                return $user;
            }

            $ip      = PWW_Utils::get_client_ip();
            $ip_hash = PWW_Utils::hash_ip( $ip );

            // Check if currently locked out.
            $lockout = get_transient( 'aipatch_lockout_' . $ip_hash );
            if ( $lockout ) {
                return new WP_Error(
                    'aipatch_locked_out',
                    sprintf(
                        /* translators: %d: Lockout duration in minutes. */
                        __( 'Too many failed login attempts. Please try again in %d minutes.', 'patchwatch-wp' ),
                        $lockout_minutes
                    )
                );
            }

            return $user;
        }, 30, 2 );

        // Record failed login.
        add_action( 'wp_login_failed', function ( $username ) use ( $max_attempts, $lockout_minutes ) {
            $ip      = PWW_Utils::get_client_ip();
            $ip_hash = PWW_Utils::hash_ip( $ip );
            $key     = 'aipatch_fails_' . $ip_hash;

            $attempts = (int) get_transient( $key );
            $attempts++;

            if ( $attempts >= $max_attempts ) {
                set_transient( 'aipatch_lockout_' . $ip_hash, 1, $lockout_minutes * MINUTE_IN_SECONDS );
                delete_transient( $key );

                // Log the lockout (avoid storing IP directly).
                $logger = new PWW_Logger();
                $logger->warning(
                    'login_lockout',
                    sprintf(
                        /* translators: %d: Max attempts. */
                        __( 'IP locked out after %d failed login attempts.', 'patchwatch-wp' ),
                        $max_attempts
                    ),
                    array( 'ip_hash' => $ip_hash )
                );
            } else {
                set_transient( $key, $attempts, HOUR_IN_SECONDS );
            }
        } );

        // Clear failed attempts on successful login.
        add_action( 'wp_login', function () {
            $ip      = PWW_Utils::get_client_ip();
            $ip_hash = PWW_Utils::hash_ip( $ip );
            delete_transient( 'aipatch_fails_' . $ip_hash );
            delete_transient( 'aipatch_lockout_' . $ip_hash );
        } );
    }
}
