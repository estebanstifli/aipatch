<?php
/**
 * Main plugin loader and orchestrator.
 *
 * @package PatchWatch
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class PWW_Loader
 *
 * Loads all plugin components and wires hooks.
 */
class PWW_Loader {

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

        require_once $includes . 'class-pww-utils.php';
        require_once $includes . 'class-pww-i18n.php';
        require_once $includes . 'class-pww-installer.php';
        require_once $includes . 'class-pww-logger.php';
        require_once $includes . 'class-pww-settings.php';
        require_once $includes . 'class-pww-scanner.php';
        require_once $includes . 'class-pww-hardening.php';
        require_once $includes . 'class-pww-vulnerabilities.php';
        require_once $includes . 'class-pww-dashboard.php';
        require_once $includes . 'class-pww-admin.php';
        require_once $includes . 'class-pww-rest.php';
        require_once $includes . 'class-pww-cron.php';
        require_once $includes . 'class-pww-site-health.php';
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
        $i18n = new PWW_I18n();
        $this->add_action( 'init', $i18n, 'load_textdomain' );

        // Logger (must be early, other modules may log).
        $this->modules['logger'] = new PWW_Logger();

        // Settings.
        $this->modules['settings'] = new PWW_Settings();

        // Scanner.
        $this->modules['scanner'] = new PWW_Scanner( $this->modules['logger'] );

        // Hardening.
        $this->modules['hardening'] = new PWW_Hardening( $this->modules['logger'] );
        $this->modules['hardening']->apply_active_rules();

        // Vulnerabilities.
        $this->modules['vulnerabilities'] = new PWW_Vulnerabilities();

        // Dashboard.
        $this->modules['dashboard'] = new PWW_Dashboard(
            $this->modules['scanner'],
            $this->modules['vulnerabilities']
        );

        // Admin (only in admin context).
        if ( is_admin() ) {
            $this->modules['admin'] = new PWW_Admin(
                $this->modules['dashboard'],
                $this->modules['scanner'],
                $this->modules['hardening'],
                $this->modules['vulnerabilities'],
                $this->modules['settings'],
                $this->modules['logger']
            );
            $this->modules['admin']->init();
        }

        // REST API.
        $this->modules['rest'] = new PWW_Rest(
            $this->modules['scanner'],
            $this->modules['dashboard'],
            $this->modules['vulnerabilities'],
            $this->modules['hardening']
        );
        $this->add_action( 'rest_api_init', $this->modules['rest'], 'register_routes' );

        // Cron.
        $this->modules['cron'] = new PWW_Cron( $this->modules['scanner'], $this->modules['logger'] );
        $this->modules['cron']->init();

        // Site Health.
        $this->modules['site_health'] = new PWW_Site_Health( $this->modules['scanner'] );
        $this->modules['site_health']->init();

        // Fire all registered hooks.
        $this->register_hooks();

        /**
         * Fires after AI PatchWatch is fully loaded.
         *
         * @param PWW_Loader $loader The loader instance.
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
