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

        // Audit engine framework.
        $audit = $includes . 'audit/';
        require_once $audit . 'class-aipsc-audit-check-interface.php';
        require_once $audit . 'class-aipsc-audit-check-result.php';
        require_once $audit . 'class-aipsc-audit-check-registry.php';
        require_once $audit . 'class-aipsc-audit-engine.php';
        require_once $audit . 'class-aipsc-score-engine.php';

        // Base class for checks.
        require_once $audit . 'checks/class-aipsc-audit-check-base.php';

        // Individual checks.
        $checks = $audit . 'checks/';
        require_once $checks . 'class-check-wp-version.php';
        require_once $checks . 'class-check-plugins-outdated.php';
        require_once $checks . 'class-check-themes-outdated.php';
        require_once $checks . 'class-check-admin-username.php';
        require_once $checks . 'class-check-too-many-admins.php';
        require_once $checks . 'class-check-xmlrpc.php';
        require_once $checks . 'class-check-file-editor.php';
        require_once $checks . 'class-check-debug-mode.php';
        require_once $checks . 'class-check-php-version.php';
        require_once $checks . 'class-check-rest-exposure.php';
        require_once $checks . 'class-check-directory-listing.php';
        require_once $checks . 'class-check-file-permissions.php';
        require_once $checks . 'class-check-ssl.php';
        require_once $checks . 'class-check-inactive-plugins.php';
        require_once $checks . 'class-check-unused-themes.php';
        require_once $checks . 'class-check-inactive-admins.php';
        require_once $checks . 'class-check-db-prefix.php';
        require_once $checks . 'class-check-sensitive-files.php';
        require_once $checks . 'class-check-php-in-uploads.php';
        require_once $checks . 'class-check-security-headers.php';
        require_once $checks . 'class-check-user-enumeration.php';
        require_once $checks . 'class-check-application-passwords.php';
        require_once $checks . 'class-check-auto-updates.php';
        require_once $checks . 'class-check-salt-keys.php';
        require_once $checks . 'class-check-debug-log.php';
        require_once $checks . 'class-check-user-id-one.php';
        require_once $checks . 'class-check-database-debug.php';
        require_once $checks . 'class-check-file-install.php';
        require_once $checks . 'class-check-cron-health.php';
        require_once $checks . 'class-check-cookie-security.php';
        require_once $checks . 'class-check-backup-files.php';
        require_once $checks . 'class-check-phpinfo.php';
        require_once $checks . 'class-check-cors.php';
        require_once $checks . 'class-check-uploads-index.php';
        require_once $checks . 'class-check-login-url.php';
        require_once $checks . 'class-check-db-credentials.php';

        require_once $includes . 'class-aipsc-scanner.php';
        require_once $includes . 'class-aipsc-job-manager.php';
        require_once $includes . 'class-aipsc-findings-store.php';
        require_once $includes . 'class-aipsc-file-heuristics.php';
        require_once $includes . 'class-aipsc-file-classifier.php';
        require_once $includes . 'class-aipsc-file-scanner.php';
        require_once $includes . 'class-aipsc-file-baseline.php';
        require_once $includes . 'class-aipsc-remediation-engine.php';
        require_once $includes . 'class-aipsc-vulnerability-cache.php';
        require_once $includes . 'class-aipsc-vulnerabilities.php';
        require_once $includes . 'class-aipsc-cached-vulnerability-provider.php';
        require_once $includes . 'class-aipsc-hardening.php';
        require_once $includes . 'class-aipsc-dashboard.php';
        require_once $includes . 'class-aipsc-performance.php';
        require_once $includes . 'class-aipsc-abilities.php';
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

        // Audit engine (core of the new modular architecture).
        $registry = AIPSC_Audit_Check_Registry::instance();
        $this->modules['audit_engine'] = new AIPSC_Audit_Engine( $registry, $this->modules['logger'] );
        $this->modules['audit_engine']->register_default_checks();

        // Persistent job manager.
        $this->modules['job_manager'] = new AIPSC_Job_Manager();

        // Findings persistence store.
        $this->modules['findings_store'] = new AIPSC_Findings_Store();

        // File baseline (integrity monitoring) — created before file scanner.
        $this->modules['file_baseline'] = new AIPSC_File_Baseline(
            $this->modules['job_manager'],
            $this->modules['logger']
        );

        // File scanner (uses job manager for batch processing + baseline for integrity).
        $this->modules['file_scanner'] = new AIPSC_File_Scanner(
            $this->modules['job_manager'],
            $this->modules['logger'],
            $this->modules['file_baseline']
        );

        // Scanner (bridges the audit engine for backward compatibility).
        if ( AIPSC_Settings::is_module_enabled( 'scanner' ) ) {
            $this->modules['scanner'] = new AIPSC_Scanner(
                $this->modules['logger'],
                $this->modules['audit_engine'],
                $this->modules['findings_store']
            );
        }

        // Hardening (respects module toggle).
        if ( AIPSC_Settings::is_module_enabled( 'hardening' ) ) {
            $this->modules['hardening'] = new AIPSC_Hardening( $this->modules['logger'] );
            $this->modules['hardening']->apply_active_rules();
        }

        // Vulnerabilities (respects module toggle).
        if ( AIPSC_Settings::is_module_enabled( 'vulnerabilities' ) ) {
            $this->modules['vulnerability_cache'] = new AIPSC_Vulnerability_Cache();
            $this->modules['vulnerabilities']     = new AIPSC_Vulnerabilities( $this->modules['vulnerability_cache'] );
        }

        // Dashboard (uses scanner + vulnerabilities if available).
        $this->modules['dashboard'] = new AIPSC_Dashboard(
            isset( $this->modules['scanner'] ) ? $this->modules['scanner'] : null,
            isset( $this->modules['vulnerabilities'] ) ? $this->modules['vulnerabilities'] : null,
            $this->modules['logger']
        );

        // Performance diagnostics.
        $this->modules['performance'] = new AIPSC_Performance();

        // Remediation engine.
        $this->modules['remediation'] = new AIPSC_Remediation_Engine(
            $this->modules['findings_store'],
            $this->modules['logger']
        );

        // Abilities API integration (read-only MCP/AI tooling).
        $this->modules['abilities'] = new AIPSC_Abilities(
            isset( $this->modules['scanner'] ) ? $this->modules['scanner'] : null,
            isset( $this->modules['vulnerabilities'] ) ? $this->modules['vulnerabilities'] : null,
            $this->modules['logger'],
            array(
                'file_scanner'       => $this->modules['file_scanner'],
                'findings_store'     => $this->modules['findings_store'],
                'file_baseline'      => $this->modules['file_baseline'],
                'job_manager'        => $this->modules['job_manager'],
                'remediation_engine' => $this->modules['remediation'],
            )
        );
        $this->modules['abilities']->init();

        // Admin (only in admin context).
        if ( is_admin() ) {
            $this->modules['admin'] = new AIPSC_Admin(
                $this->modules['dashboard'],
                isset( $this->modules['scanner'] ) ? $this->modules['scanner'] : null,
                isset( $this->modules['hardening'] ) ? $this->modules['hardening'] : null,
                isset( $this->modules['vulnerabilities'] ) ? $this->modules['vulnerabilities'] : null,
                $this->modules['settings'],
                $this->modules['logger'],
                $this->modules['performance']
            );
            $this->modules['admin']->init();
        }

        // REST API (uses available modules).
        $this->modules['rest'] = new AIPSC_Rest(
            isset( $this->modules['scanner'] ) ? $this->modules['scanner'] : null,
            $this->modules['dashboard'],
            isset( $this->modules['vulnerabilities'] ) ? $this->modules['vulnerabilities'] : null,
            isset( $this->modules['hardening'] ) ? $this->modules['hardening'] : null,
            $this->modules['logger'],
            $this->modules['performance']
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
