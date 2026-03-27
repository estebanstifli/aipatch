<?php
/**
 * Admin module – registers menus, enqueues assets, renders pages.
 *
 * @package PatchWatch
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class PWW_Admin
 */
class PWW_Admin {

    /** @var PWW_Dashboard */
    private $dashboard;

    /** @var PWW_Scanner */
    private $scanner;

    /** @var PWW_Hardening */
    private $hardening;

    /** @var PWW_Vulnerabilities */
    private $vulnerabilities;

    /** @var PWW_Settings */
    private $settings;

    /** @var PWW_Logger */
    private $logger;

    /**
     * Constructor.
     */
    public function __construct(
        PWW_Dashboard $dashboard,
        PWW_Scanner $scanner,
        PWW_Hardening $hardening,
        PWW_Vulnerabilities $vulnerabilities,
        PWW_Settings $settings,
        PWW_Logger $logger
    ) {
        $this->dashboard       = $dashboard;
        $this->scanner         = $scanner;
        $this->hardening       = $hardening;
        $this->vulnerabilities = $vulnerabilities;
        $this->settings        = $settings;
        $this->logger          = $logger;
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
            __( 'AI PatchWatch', 'patchwatch-wp' ),
            __( 'AI PatchWatch', 'patchwatch-wp' ),
            'manage_options',
            'patchwatch-dashboard',
            array( $this, 'render_dashboard' ),
            'dashicons-shield',
            80
        );

        // Submenu: Dashboard.
        add_submenu_page(
            'patchwatch-dashboard',
            __( 'Security Dashboard', 'patchwatch-wp' ),
            __( 'Dashboard', 'patchwatch-wp' ),
            'manage_options',
            'patchwatch-dashboard',
            array( $this, 'render_dashboard' )
        );

        // Submenu: Vulnerabilities.
        add_submenu_page(
            'patchwatch-dashboard',
            __( 'Vulnerabilities', 'patchwatch-wp' ),
            __( 'Vulnerabilities', 'patchwatch-wp' ),
            'manage_options',
            'patchwatch-vulnerabilities',
            array( $this, 'render_vulnerabilities' )
        );

        // Submenu: Hardening.
        add_submenu_page(
            'patchwatch-dashboard',
            __( 'Hardening', 'patchwatch-wp' ),
            __( 'Hardening', 'patchwatch-wp' ),
            'manage_options',
            'patchwatch-hardening',
            array( $this, 'render_hardening' )
        );

        // Submenu: Logs.
        add_submenu_page(
            'patchwatch-dashboard',
            __( 'Security Logs', 'patchwatch-wp' ),
            __( 'Logs', 'patchwatch-wp' ),
            'manage_options',
            'patchwatch-logs',
            array( $this, 'render_logs' )
        );

        // Submenu: Settings.
        add_submenu_page(
            'patchwatch-dashboard',
            __( 'Settings', 'patchwatch-wp' ),
            __( 'Settings', 'patchwatch-wp' ),
            'manage_options',
            'patchwatch-settings',
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
            'toplevel_page_patchwatch-dashboard',
            'patchwatch_page_patchwatch-vulnerabilities',
            'patchwatch_page_patchwatch-hardening',
            'patchwatch_page_patchwatch-logs',
            'patchwatch_page_patchwatch-settings',
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
                'scanning'        => __( 'Scanning...', 'patchwatch-wp' ),
                'scanComplete'    => __( 'Scan complete. Reloading...', 'patchwatch-wp' ),
                'error'           => __( 'An error occurred. Please try again.', 'patchwatch-wp' ),
                'confirmClear'    => __( 'Are you sure you want to clear all logs?', 'patchwatch-wp' ),
                'saving'          => __( 'Saving...', 'patchwatch-wp' ),
                'saved'           => __( 'Saved!', 'patchwatch-wp' ),
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
        if ( ! PWW_Utils::current_user_can_manage() ) {
            return;
        }

        // Run scan now.
        if ( isset( $_POST['aipatch_run_scan'] ) ) {
            check_admin_referer( 'aipatch_run_scan', 'aipatch_scan_nonce' );
            $this->scanner->run_full_scan();
            $this->logger->info( 'manual_scan', __( 'Manual security scan executed.', 'patchwatch-wp' ) );
            wp_safe_redirect( admin_url( 'admin.php?page=patchwatch-dashboard&scan=complete' ) );
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
        if ( isset( $_POST['aipatch_toggle_hardening'] ) && isset( $_POST['hardening_key'] ) ) {
            check_admin_referer( 'aipatch_toggle_hardening', 'aipatch_hardening_nonce' );
            $key   = sanitize_key( wp_unslash( $_POST['hardening_key'] ) );
            $value = ! empty( $_POST['hardening_value'] );
            $this->hardening->toggle( $key, $value );
            wp_safe_redirect( admin_url( 'admin.php?page=patchwatch-hardening&updated=1' ) );
            exit;
        }

        // Clear logs.
        if ( isset( $_POST['aipatch_clear_logs'] ) ) {
            check_admin_referer( 'aipatch_clear_logs', 'aipatch_clear_nonce' );
            $this->logger->clear_all();
            $this->logger->info( 'logs_cleared', __( 'All logs were cleared manually.', 'patchwatch-wp' ) );
            wp_safe_redirect( admin_url( 'admin.php?page=patchwatch-logs&cleared=1' ) );
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
        if ( ! PWW_Utils::current_user_can_manage() ) {
            return;
        }
        $data = $this->dashboard->get_dashboard_data();
        include AIPATCH_PLUGIN_DIR . 'admin/partials/dashboard.php';
    }

    /**
     * Render the vulnerabilities page.
     */
    public function render_vulnerabilities() {
        if ( ! PWW_Utils::current_user_can_manage() ) {
            return;
        }
        $vulns         = $this->vulnerabilities->get_all_vulnerabilities();
        $has_external  = $this->vulnerabilities->has_external_provider();
        $providers     = $this->vulnerabilities->get_provider_status();
        include AIPATCH_PLUGIN_DIR . 'admin/partials/vulnerabilities.php';
    }

    /**
     * Render the hardening page.
     */
    public function render_hardening() {
        if ( ! PWW_Utils::current_user_can_manage() ) {
            return;
        }
        $rules = $this->hardening->get_status();
        include AIPATCH_PLUGIN_DIR . 'admin/partials/hardening.php';
    }

    /**
     * Render the logs page.
     */
    public function render_logs() {
        if ( ! PWW_Utils::current_user_can_manage() ) {
            return;
        }

        $per_page = 20;
        $page     = isset( $_GET['paged'] ) ? absint( $_GET['paged'] ) : 1;
        $severity = isset( $_GET['severity'] ) ? sanitize_key( $_GET['severity'] ) : '';

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
     * Render the settings page.
     */
    public function render_settings() {
        if ( ! PWW_Utils::current_user_can_manage() ) {
            return;
        }
        $settings = PWW_Utils::get_settings();
        include AIPATCH_PLUGIN_DIR . 'admin/partials/settings.php';
    }
}
