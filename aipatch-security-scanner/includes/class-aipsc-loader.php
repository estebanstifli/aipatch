<?php
/**
 * Main plugin loader and orchestrator.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Loader
 *
 * Loads all plugin components and wires hooks.
 */
class AIPSC_Loader {

    /**
     * Registered actions.
     *
     * @var array
     */
    private $actions = array();

    /**
     * Registered filters.
     *
     * @var array
     */
    private $filters = array();

    /**
     * Module instances.
     *
     * @var array
     */
    private $modules = array();

    /**
     * Constructor. Include dependencies.
     */
    public function __construct() {
        $this->load_dependencies();
    }

    /**
     * Include all required files.
     */
    private function load_dependencies() {
        $includes = AIPATCH_PLUGIN_DIR . 'includes/';

        require_once $includes . 'class-aipsc-utils.php';
        require_once $includes . 'class-aipsc-i18n.php';
        require_once $includes . 'class-aipsc-installer.php';
        require_once $includes . 'class-aipsc-logger.php';
        require_once $includes . 'class-aipsc-settings.php';
        require_once $includes . 'class-aipsc-scanner.php';
        require_once $includes . 'class-aipsc-hardening.php';
        require_once $includes . 'class-aipsc-vulnerabilities.php';
        require_once $includes . 'class-aipsc-dashboard.php';
        require_once $includes . 'class-aipsc-admin.php';
        require_once $includes . 'class-aipsc-rest.php';
        require_once $includes . 'class-aipsc-cron.php';
        require_once $includes . 'class-aipsc-site-health.php';
    }

    /**
     * Register an action hook.
     *
     * @param string $hook       Hook name.
     * @param object $component  Component instance.
     * @param string $callback   Method name.
     * @param int    $priority   Priority.
     * @param int    $args       Accepted args.
     */
    public function add_action( $hook, $component, $callback, $priority = 10, $args = 1 ) {
        $this->actions[] = compact( 'hook', 'component', 'callback', 'priority', 'args' );
    }

    /**
     * Register a filter hook.
     *
     * @param string $hook       Hook name.
     * @param object $component  Component instance.
     * @param string $callback   Method name.
     * @param int    $priority   Priority.
     * @param int    $args       Accepted args.
     */
    public function add_filter( $hook, $component, $callback, $priority = 10, $args = 1 ) {
        $this->filters[] = compact( 'hook', 'component', 'callback', 'priority', 'args' );
    }

    /**
     * Initialize all modules and register hooks.
     */
    public function run() {
        // i18n.
        $i18n = new AIPSC_I18n();
        $this->add_action( 'init', $i18n, 'load_textdomain' );

        // Run any pending DB upgrades.
        AIPSC_Installer::maybe_upgrade();

        // Logger (must be early, other modules may log).
        $this->modules['logger'] = new AIPSC_Logger();

        // Settings (always loaded — needed for module checks and admin).
        $this->modules['settings'] = new AIPSC_Settings();

        // Scanner (respects module toggle).
        if ( AIPSC_Settings::is_module_enabled( 'scanner' ) ) {
            $this->modules['scanner'] = new AIPSC_Scanner( $this->modules['logger'] );
        }

        // Hardening (respects module toggle).
        if ( AIPSC_Settings::is_module_enabled( 'hardening' ) ) {
            $this->modules['hardening'] = new AIPSC_Hardening( $this->modules['logger'] );
            $this->modules['hardening']->apply_active_rules();
        }

        // Vulnerabilities (respects module toggle).
        if ( AIPSC_Settings::is_module_enabled( 'vulnerabilities' ) ) {
            $this->modules['vulnerabilities'] = new AIPSC_Vulnerabilities();
        }

        // Dashboard (uses scanner + vulnerabilities if available).
        $this->modules['dashboard'] = new AIPSC_Dashboard(
            isset( $this->modules['scanner'] ) ? $this->modules['scanner'] : null,
            isset( $this->modules['vulnerabilities'] ) ? $this->modules['vulnerabilities'] : null
        );

        // Admin (only in admin context).
        if ( is_admin() ) {
            $this->modules['admin'] = new AIPSC_Admin(
                $this->modules['dashboard'],
                isset( $this->modules['scanner'] ) ? $this->modules['scanner'] : null,
                isset( $this->modules['hardening'] ) ? $this->modules['hardening'] : null,
                isset( $this->modules['vulnerabilities'] ) ? $this->modules['vulnerabilities'] : null,
                $this->modules['settings'],
                $this->modules['logger']
            );
            $this->modules['admin']->init();
        }

        // REST API (uses available modules).
        $this->modules['rest'] = new AIPSC_Rest(
            isset( $this->modules['scanner'] ) ? $this->modules['scanner'] : null,
            $this->modules['dashboard'],
            isset( $this->modules['vulnerabilities'] ) ? $this->modules['vulnerabilities'] : null,
            isset( $this->modules['hardening'] ) ? $this->modules['hardening'] : null,
            $this->modules['logger']
        );
        $this->add_action( 'rest_api_init', $this->modules['rest'], 'register_routes' );

        // Cron (only if scanner is enabled).
        if ( isset( $this->modules['scanner'] ) ) {
            $this->modules['cron'] = new AIPSC_Cron( $this->modules['scanner'], $this->modules['logger'] );
            $this->modules['cron']->init();
        }

        // Site Health (only if scanner is enabled).
        if ( isset( $this->modules['scanner'] ) ) {
            $this->modules['site_health'] = new AIPSC_Site_Health( $this->modules['scanner'] );
            $this->modules['site_health']->init();
        }

        // Fire all registered hooks.
        $this->register_hooks();

        /**
         * Fires after Aipatch Security Scanner is fully loaded.
         *
         * @param AIPSC_Loader $loader The loader instance.
         */
        do_action( 'aipatch_loaded', $this );
    }

    /**
     * Register all collected actions and filters with WordPress.
     */
    private function register_hooks() {
        foreach ( $this->actions as $hook ) {
            add_action(
                $hook['hook'],
                array( $hook['component'], $hook['callback'] ),
                $hook['priority'],
                $hook['args']
            );
        }

        foreach ( $this->filters as $hook ) {
            add_filter(
                $hook['hook'],
                array( $hook['component'], $hook['callback'] ),
                $hook['priority'],
                $hook['args']
            );
        }
    }

    /**
     * Get a module instance.
     *
     * @param string $name Module name.
     * @return object|null
     */
    public function get_module( $name ) {
        return isset( $this->modules[ $name ] ) ? $this->modules[ $name ] : null;
    }
}
