<?php
/**
 * Site Health integration – adds custom tests to WordPress Site Health.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Site_Health
 */
class AIPSC_Site_Health {

    /** @var AIPSC_Scanner */
    private $scanner;

    /**
     * Constructor.
     *
     * @param AIPSC_Scanner $scanner Scanner instance.
     */
    public function __construct( AIPSC_Scanner $scanner ) {
        $this->scanner = $scanner;
    }

    /**
     * Register Site Health hooks.
     */
    public function init() {
        add_filter( 'site_status_tests', array( $this, 'register_tests' ) );
    }

    /**
     * Register custom Site Health tests.
     *
     * @param array $tests Existing tests.
     * @return array
     */
    public function register_tests( $tests ) {
        $tests['direct']['aipatch_file_editor'] = array(
            'label' => __( 'File Editor Status', 'aipatch-security-scanner' ),
            'test'  => array( $this, 'test_file_editor' ),
        );

        $tests['direct']['aipatch_debug_mode'] = array(
            'label' => __( 'Debug Mode Status', 'aipatch-security-scanner' ),
            'test'  => array( $this, 'test_debug_mode' ),
        );

        $tests['direct']['aipatch_xmlrpc'] = array(
            'label' => __( 'XML-RPC Status', 'aipatch-security-scanner' ),
            'test'  => array( $this, 'test_xmlrpc' ),
        );

        $tests['direct']['aipatch_admin_username'] = array(
            'label' => __( 'Default Admin Username', 'aipatch-security-scanner' ),
            'test'  => array( $this, 'test_admin_username' ),
        );

        $tests['direct']['aipatch_ssl'] = array(
            'label' => __( 'SSL/HTTPS Status', 'aipatch-security-scanner' ),
            'test'  => array( $this, 'test_ssl' ),
        );

        $tests['direct']['aipatch_security_score'] = array(
            'label' => __( 'Aipatch Security Scanner Security Score', 'aipatch-security-scanner' ),
            'test'  => array( $this, 'test_security_score' ),
        );

        return $tests;
    }

    /**
     * Test: File Editor enabled.
     *
     * @return array
     */
    public function test_file_editor() {
        $result = array(
            'label'       => __( 'WordPress file editor is disabled', 'aipatch-security-scanner' ),
            'status'      => 'good',
            'badge'       => array(
                'label' => __( 'Security', 'aipatch-security-scanner' ),
                'color' => 'blue',
            ),
            'description' => sprintf(
                '<p>%s</p>',
                esc_html__( 'The built-in file editor is disabled, preventing direct code modifications from the admin panel.', 'aipatch-security-scanner' )
            ),
            'test'        => 'aipatch_file_editor',
        );

        if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
            $result['label']       = __( 'WordPress file editor is enabled', 'aipatch-security-scanner' );
            $result['status']      = 'recommended';
            $result['description'] = sprintf(
                '<p>%s</p>',
                esc_html__( 'The file editor allows editing plugin and theme code from the admin panel. If an attacker gains admin access, they could inject malicious code. Add define( \'DISALLOW_FILE_EDIT\', true ); to wp-config.php.', 'aipatch-security-scanner' )
            );
            $result['actions'] = sprintf(
                '<p><a href="%s">%s</a></p>',
                esc_url( admin_url( 'admin.php?page=aipatch-security-scanner-hardening' ) ),
                esc_html__( 'View Hardening Options', 'aipatch-security-scanner' )
            );
        }

        return $result;
    }

    /**
     * Test: Debug mode active.
     *
     * @return array
     */
    public function test_debug_mode() {
        $result = array(
            'label'       => __( 'Debug mode is off', 'aipatch-security-scanner' ),
            'status'      => 'good',
            'badge'       => array(
                'label' => __( 'Security', 'aipatch-security-scanner' ),
                'color' => 'blue',
            ),
            'description' => sprintf(
                '<p>%s</p>',
                esc_html__( 'Debug mode is correctly disabled for this site.', 'aipatch-security-scanner' )
            ),
            'test'        => 'aipatch_debug_mode',
        );

        if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
            $result['label']  = __( 'Debug mode is active', 'aipatch-security-scanner' );
            $result['status'] = 'recommended';
            if ( defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY ) {
                $result['status'] = 'critical';
                $result['description'] = sprintf(
                    '<p>%s</p>',
                    esc_html__( 'Debug mode is active AND errors are displayed publicly. This can expose file paths, database details, and PHP errors to visitors. Disable WP_DEBUG and WP_DEBUG_DISPLAY in wp-config.php immediately.', 'aipatch-security-scanner' )
                );
            } else {
                $result['description'] = sprintf(
                    '<p>%s</p>',
                    esc_html__( 'Debug mode is active but errors are not displayed. While less risky, debug mode should be disabled on production sites.', 'aipatch-security-scanner' )
                );
            }
        }

        return $result;
    }

    /**
     * Test: XML-RPC enabled.
     *
     * @return array
     */
    public function test_xmlrpc() {
        $hardening = AIPSC_Utils::get_hardening();

        $result = array(
            'label'       => __( 'XML-RPC is disabled', 'aipatch-security-scanner' ),
            'status'      => 'good',
            'badge'       => array(
                'label' => __( 'Security', 'aipatch-security-scanner' ),
                'color' => 'blue',
            ),
            'description' => sprintf(
                '<p>%s</p>',
                esc_html__( 'XML-RPC has been disabled, reducing the attack surface.', 'aipatch-security-scanner' )
            ),
            'test'        => 'aipatch_xmlrpc',
        );

        if ( empty( $hardening['disable_xmlrpc'] ) ) {
            $result['label']       = __( 'XML-RPC is enabled', 'aipatch-security-scanner' );
            $result['status']      = 'recommended';
            $result['description'] = sprintf(
                '<p>%s</p>',
                esc_html__( 'XML-RPC is enabled and can be used for brute-force amplification attacks. Disable it unless you need it for Jetpack or the WordPress mobile app.', 'aipatch-security-scanner' )
            );
            $result['actions'] = sprintf(
                '<p><a href="%s">%s</a></p>',
                esc_url( admin_url( 'admin.php?page=aipatch-security-scanner-hardening' ) ),
                esc_html__( 'Disable XML-RPC', 'aipatch-security-scanner' )
            );
        }

        return $result;
    }

    /**
     * Test: "admin" username exists.
     *
     * @return array
     */
    public function test_admin_username() {
        $result = array(
            'label'       => __( 'No default "admin" username found', 'aipatch-security-scanner' ),
            'status'      => 'good',
            'badge'       => array(
                'label' => __( 'Security', 'aipatch-security-scanner' ),
                'color' => 'blue',
            ),
            'description' => sprintf(
                '<p>%s</p>',
                esc_html__( 'No user with the "admin" username exists on this site.', 'aipatch-security-scanner' )
            ),
            'test'        => 'aipatch_admin_username',
        );

        if ( get_user_by( 'login', 'admin' ) ) {
            $result['label']       = __( 'Default "admin" username exists', 'aipatch-security-scanner' );
            $result['status']      = 'recommended';
            $result['description'] = sprintf(
                '<p>%s</p>',
                esc_html__( 'The "admin" username is the most common target for brute-force attacks. Consider creating a new admin account with a unique username and removing the "admin" account.', 'aipatch-security-scanner' )
            );
        }

        return $result;
    }

    /**
     * Test: SSL/HTTPS.
     *
     * @return array
     */
    public function test_ssl() {
        $result = array(
            'label'       => __( 'Site uses HTTPS', 'aipatch-security-scanner' ),
            'status'      => 'good',
            'badge'       => array(
                'label' => __( 'Security', 'aipatch-security-scanner' ),
                'color' => 'blue',
            ),
            'description' => sprintf(
                '<p>%s</p>',
                esc_html__( 'Your site uses HTTPS encryption for all connections.', 'aipatch-security-scanner' )
            ),
            'test'        => 'aipatch_ssl',
        );

        if ( ! is_ssl() ) {
            $result['label']       = __( 'Site is not using HTTPS', 'aipatch-security-scanner' );
            $result['status']      = 'critical';
            $result['description'] = sprintf(
                '<p>%s</p>',
                esc_html__( 'Your site is not using HTTPS. All data including passwords is transmitted in plain text. Install an SSL certificate and force HTTPS.', 'aipatch-security-scanner' )
            );
        }

        return $result;
    }

    /**
     * Test: Overall security score.
     *
     * @return array
     */
    public function test_security_score() {
        $score = (int) AIPSC_Utils::get_option( 'security_score', 0 );
        $last_scan = AIPSC_Utils::get_option( 'last_scan', 0 );

        if ( empty( $last_scan ) ) {
            return array(
                'label'       => __( 'Aipatch Security Scanner: No scan has been run yet', 'aipatch-security-scanner' ),
                'status'      => 'recommended',
                'badge'       => array(
                    'label' => __( 'Security', 'aipatch-security-scanner' ),
                    'color' => 'blue',
                ),
                'description' => sprintf(
                    '<p>%s</p>',
                    esc_html__( 'Run your first security scan from the Aipatch Security Scanner dashboard to assess your site\'s security posture.', 'aipatch-security-scanner' )
                ),
                'actions'     => sprintf(
                    '<p><a href="%s">%s</a></p>',
                    esc_url( admin_url( 'admin.php?page=aipatch-security-scanner-dashboard' ) ),
                    esc_html__( 'Go to Aipatch Security Scanner Dashboard', 'aipatch-security-scanner' )
                ),
                'test'        => 'aipatch_security_score',
            );
        }

        $status = 'good';
        if ( $score < 50 ) {
            $status = 'critical';
        } elseif ( $score < 70 ) {
            $status = 'recommended';
        }

        return array(
            'label'       => sprintf(
                /* translators: %d: Security score. */
                __( 'Aipatch Security Scanner Security Score: %d/100', 'aipatch-security-scanner' ),
                $score
            ),
            'status'      => $status,
            'badge'       => array(
                'label' => __( 'Security', 'aipatch-security-scanner' ),
                'color' => 'blue',
            ),
            'description' => sprintf(
                '<p>%s</p>',
                esc_html(
                    sprintf(
                        /* translators: 1: Score, 2: Last scan date. */
                        __( 'Your site scored %1$d out of 100 on the last security scan (%2$s). Visit the Aipatch Security Scanner dashboard for details and recommendations.', 'aipatch-security-scanner' ),
                        $score,
                        AIPSC_Utils::format_time( $last_scan )
                    )
                )
            ),
            'actions'     => sprintf(
                '<p><a href="%s">%s</a></p>',
                esc_url( admin_url( 'admin.php?page=aipatch-security-scanner-dashboard' ) ),
                esc_html__( 'View Full Report', 'aipatch-security-scanner' )
            ),
            'test'        => 'aipatch_security_score',
        );
    }
}
