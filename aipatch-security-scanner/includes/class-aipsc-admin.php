<?php
/**
 * Admin module – registers menus, enqueues assets, renders pages.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Admin
 */
class AIPSC_Admin {

    /** @var AIPSC_Dashboard */
    private $dashboard;

    /** @var AIPSC_Scanner|null */
    private $scanner;

    /** @var AIPSC_Hardening|null */
    private $hardening;

    /** @var AIPSC_Vulnerabilities|null */
    private $vulnerabilities;

    /** @var AIPSC_Settings */
    private $settings;

    /** @var AIPSC_Logger */
    private $logger;

    /** @var AIPSC_Performance|null */
    private $performance;

    /**
     * Constructor.
     */
    public function __construct(
        AIPSC_Dashboard $dashboard,
        $scanner,
        $hardening,
        $vulnerabilities,
        AIPSC_Settings $settings,
        AIPSC_Logger $logger,
        $performance = null
    ) {
        $this->dashboard       = $dashboard;
        $this->scanner         = $scanner;
        $this->hardening       = $hardening;
        $this->vulnerabilities = $vulnerabilities;
        $this->settings        = $settings;
        $this->logger          = $logger;
        $this->performance     = $performance;
    }

    /**
     * Register admin hooks.
     */
    public function init() {
        add_action( 'admin_menu', array( $this, 'register_menus' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
        add_action( 'admin_init', array( $this, 'register_settings' ) );
        add_action( 'admin_init', array( $this, 'handle_admin_actions' ) );
    }

    /**
     * Register admin menu pages.
     */
    public function register_menus() {
        // Main menu.
        add_menu_page(
            __( 'Aipatch Security Scanner', 'aipatch-security-scanner' ),
            __( 'Aipatch Security Scanner', 'aipatch-security-scanner' ),
            'manage_options',
            'aipatch-security-scanner-dashboard',
            array( $this, 'render_dashboard' ),
            'dashicons-shield',
            80
        );

        // Submenu: Dashboard.
        add_submenu_page(
            'aipatch-security-scanner-dashboard',
            __( 'Security Dashboard', 'aipatch-security-scanner' ),
            __( 'Dashboard', 'aipatch-security-scanner' ),
            'manage_options',
            'aipatch-security-scanner-dashboard',
            array( $this, 'render_dashboard' )
        );

        // Submenu: Vulnerabilities.
        add_submenu_page(
            'aipatch-security-scanner-dashboard',
            __( 'Known Vulnerabilities', 'aipatch-security-scanner' ),
            __( 'Vulnerabilities', 'aipatch-security-scanner' ),
            'manage_options',
            'aipatch-security-scanner-vulnerabilities',
            array( $this, 'render_vulnerabilities' )
        );

        // Submenu: Hardening.
        add_submenu_page(
            'aipatch-security-scanner-dashboard',
            __( 'Hardening', 'aipatch-security-scanner' ),
            __( 'Hardening', 'aipatch-security-scanner' ),
            'manage_options',
            'aipatch-security-scanner-hardening',
            array( $this, 'render_hardening' )
        );

        // Submenu: Performance.
        add_submenu_page(
            'aipatch-security-scanner-dashboard',
            __( 'Performance Diagnostics', 'aipatch-security-scanner' ),
            __( 'Performance', 'aipatch-security-scanner' ),
            'manage_options',
            'aipatch-security-scanner-performance',
            array( $this, 'render_performance' )
        );

        // Submenu: Logs.
        add_submenu_page(
            'aipatch-security-scanner-dashboard',
            __( 'Security Logs', 'aipatch-security-scanner' ),
            __( 'Logs', 'aipatch-security-scanner' ),
            'manage_options',
            'aipatch-security-scanner-logs',
            array( $this, 'render_logs' )
        );

        // Submenu: Settings.
        add_submenu_page(
            'aipatch-security-scanner-dashboard',
            __( 'Settings', 'aipatch-security-scanner' ),
            __( 'Settings', 'aipatch-security-scanner' ),
            'manage_options',
            'aipatch-security-scanner-settings',
            array( $this, 'render_settings' )
        );
    }

    /**
     * Enqueue admin CSS and JS on plugin pages only.
     *
     * @param string $hook Current admin page hook.
     */
    public function enqueue_assets( $hook ) {
        $plugin_pages = array(
            'toplevel_page_aipatch-security-scanner-dashboard',
            'aipatch-security-scanner_page_aipatch-security-scanner-vulnerabilities',
            'aipatch-security-scanner_page_aipatch-security-scanner-hardening',
            'aipatch-security-scanner_page_aipatch-security-scanner-performance',
            'aipatch-security-scanner_page_aipatch-security-scanner-logs',
            'aipatch-security-scanner_page_aipatch-security-scanner-settings',
        );

        if ( ! in_array( $hook, $plugin_pages, true ) ) {
            return;
        }

        wp_enqueue_style(
            'aipatch-admin',
            AIPATCH_PLUGIN_URL . 'assets/css/admin.css',
            array(),
            AIPATCH_VERSION
        );

        wp_enqueue_script(
            'aipatch-admin',
            AIPATCH_PLUGIN_URL . 'assets/js/admin.js',
            array(),
            AIPATCH_VERSION,
            true
        );

        wp_localize_script( 'aipatch-admin', 'aipatchAdmin', array(
            'restUrl'   => esc_url_raw( rest_url( AIPATCH_REST_NAMESPACE ) ),
            'nonce'     => wp_create_nonce( 'wp_rest' ),
            'adminUrl'  => admin_url(),
            'i18n'      => array(
                'scanning'        => __( 'Scanning...', 'aipatch-security-scanner' ),
                'scanComplete'    => __( 'Scan complete. Reloading...', 'aipatch-security-scanner' ),
                'error'           => __( 'An error occurred. Please try again.', 'aipatch-security-scanner' ),
                'confirmClear'    => __( 'Are you sure you want to clear all logs?', 'aipatch-security-scanner' ),
                'saving'          => __( 'Saving...', 'aipatch-security-scanner' ),
                'saved'           => __( 'Saved!', 'aipatch-security-scanner' ),
            ),
        ) );
    }

    /**
     * Register settings.
     */
    public function register_settings() {
        $this->settings->register();
    }

    /**
     * Handle admin form actions (nonce-protected).
     */
    public function handle_admin_actions() {
        if ( ! AIPSC_Utils::current_user_can_manage() ) {
            return;
        }

        // Run scan now.
        if ( isset( $_POST['aipatch_run_scan'] ) && $this->scanner ) {
            check_admin_referer( 'aipatch_run_scan', 'aipatch_scan_nonce' );
            $this->scanner->run_full_scan();
            $this->logger->info( 'manual_scan', __( 'Manual security scan executed.', 'aipatch-security-scanner' ) );
            wp_safe_redirect( admin_url( 'admin.php?page=aipatch-security-scanner-dashboard&scan=complete' ) );
            exit;
        }

        // Dismiss issue.
        if ( isset( $_POST['aipatch_dismiss_issue'] ) && isset( $_POST['issue_id'] ) ) {
            check_admin_referer( 'aipatch_dismiss_issue', 'aipatch_dismiss_nonce' );
            $issue_id = sanitize_key( wp_unslash( $_POST['issue_id'] ) );
            $this->dashboard->dismiss_issue( $issue_id );
            wp_safe_redirect( wp_get_referer() );
            exit;
        }

        // Restore dismissed issue.
        if ( isset( $_POST['aipatch_restore_issue'] ) && isset( $_POST['issue_id'] ) ) {
            check_admin_referer( 'aipatch_restore_issue', 'aipatch_restore_nonce' );
            $issue_id = sanitize_key( wp_unslash( $_POST['issue_id'] ) );
            $this->dashboard->restore_issue( $issue_id );
            wp_safe_redirect( wp_get_referer() );
            exit;
        }

        // Toggle hardening.
        if ( isset( $_POST['aipatch_toggle_hardening'] ) && isset( $_POST['hardening_key'] ) && $this->hardening ) {
            check_admin_referer( 'aipatch_toggle_hardening', 'aipatch_hardening_nonce' );
            $key   = sanitize_key( wp_unslash( $_POST['hardening_key'] ) );
            $value = ! empty( $_POST['hardening_value'] );
            $this->hardening->toggle( $key, $value );
            wp_safe_redirect( admin_url( 'admin.php?page=aipatch-security-scanner-hardening&updated=1' ) );
            exit;
        }

        // Run performance diagnostics.
        if ( isset( $_POST['aipatch_run_performance'] ) && $this->performance ) {
            check_admin_referer( 'aipatch_run_performance', 'aipatch_perf_nonce' );
            $this->performance->run_diagnostics();
            $this->logger->info( 'performance_scan', __( 'Performance diagnostics executed.', 'aipatch-security-scanner' ) );
            wp_safe_redirect( admin_url( 'admin.php?page=aipatch-security-scanner-performance&scan=complete' ) );
            exit;
        }

        // Clear logs.
        if ( isset( $_POST['aipatch_clear_logs'] ) ) {
            check_admin_referer( 'aipatch_clear_logs', 'aipatch_clear_nonce' );
            $this->logger->clear_all();
            $this->logger->info( 'logs_cleared', __( 'All logs were cleared manually.', 'aipatch-security-scanner' ) );
            wp_safe_redirect( admin_url( 'admin.php?page=aipatch-security-scanner-logs&cleared=1' ) );
            exit;
        }
    }

    /* ---------------------------------------------------------------
     * Page renderers
     * ------------------------------------------------------------- */

    /**
     * Render the dashboard page.
     */
    public function render_dashboard() {
        if ( ! AIPSC_Utils::current_user_can_manage() ) {
            return;
        }
        $data = $this->dashboard->get_dashboard_data();
        include AIPATCH_PLUGIN_DIR . 'admin/partials/dashboard.php';
    }

    /**
     * Render the vulnerabilities page.
     */
    public function render_vulnerabilities() {
        if ( ! AIPSC_Utils::current_user_can_manage() ) {
            return;
        }
        $vulns         = $this->vulnerabilities ? $this->vulnerabilities->get_all_vulnerabilities() : array();
        $has_external  = $this->vulnerabilities ? $this->vulnerabilities->has_external_provider() : false;
        $providers     = $this->vulnerabilities ? $this->vulnerabilities->get_provider_status() : array();
        include AIPATCH_PLUGIN_DIR . 'admin/partials/vulnerabilities.php';
    }

    /**
     * Render the hardening page.
     */
    public function render_hardening() {
        if ( ! AIPSC_Utils::current_user_can_manage() ) {
            return;
        }
        $rules = $this->hardening ? $this->hardening->get_status() : array();
        include AIPATCH_PLUGIN_DIR . 'admin/partials/hardening.php';
    }

    /**
     * Render the logs page.
     */
    public function render_logs() {
        if ( ! AIPSC_Utils::current_user_can_manage() ) {
            return;
        }

        $per_page = 20;
        $page     = isset( $_GET['paged'] ) ? absint( $_GET['paged'] ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $severity = isset( $_GET['severity'] ) ? sanitize_key( $_GET['severity'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

        $log_data = $this->logger->get_logs( array(
            'per_page' => $per_page,
            'page'     => $page,
            'severity' => $severity,
        ) );

        $logs       = $log_data['items'];
        $total      = $log_data['total'];
        $total_pages = ceil( $total / $per_page );
        $counts     = $this->logger->get_counts();

        include AIPATCH_PLUGIN_DIR . 'admin/partials/logs.php';
    }

    /**
     * Render the performance page.
     */
    public function render_performance() {
        if ( ! AIPSC_Utils::current_user_can_manage() ) {
            return;
        }
        $perf_data = $this->performance ? $this->performance->get_last_results() : false;
        include AIPATCH_PLUGIN_DIR . 'admin/partials/performance.php';
    }

    /**
     * Render the settings page.
     */
    public function render_settings() {
        if ( ! AIPSC_Utils::current_user_can_manage() ) {
            return;
        }
        $settings = AIPSC_Utils::get_settings();
        include AIPATCH_PLUGIN_DIR . 'admin/partials/settings.php';
    }
}
