<?php
/**
 * Plugin installer: activation, deactivation, and upgrade routines.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Installer
 */
class AIPSC_Installer {

    /**
     * Run on plugin activation.
     */
    public static function activate() {
        self::create_tables();
        self::set_default_options();
        self::schedule_cron();

        // Store installed version.
        update_option( 'aipatch_db_version', AIPATCH_DB_VERSION, false );

        // Flush rewrite rules on next load.
        set_transient( 'aipatch_flush_rewrite', 1, 60 );
    }

    /**
     * Run on plugin deactivation.
     */
    public static function deactivate() {
        wp_clear_scheduled_hook( 'aipatch_daily_scan' );
        wp_clear_scheduled_hook( 'aipatch_log_cleanup' );
    }

    /**
     * Create custom database tables.
     */
    private static function create_tables() {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();

        // Logs table.
        $logs_table = $wpdb->prefix . 'aipsc_logs';
        $sql_logs = "CREATE TABLE {$logs_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            event_type VARCHAR(50) NOT NULL DEFAULT '',
            severity VARCHAR(20) NOT NULL DEFAULT 'info',
            message TEXT NOT NULL,
            context_json LONGTEXT DEFAULT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY event_type (event_type),
            KEY severity (severity),
            KEY created_at (created_at)
        ) {$charset_collate};";

        // Scan history table.
        $scans_table = $wpdb->prefix . 'aipsc_scan_history';
        $sql_scans = "CREATE TABLE {$scans_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            scan_type VARCHAR(20) NOT NULL DEFAULT 'manual',
            score INT NOT NULL DEFAULT 0,
            issues_count INT NOT NULL DEFAULT 0,
            issues_json LONGTEXT DEFAULT NULL,
            duration_ms INT NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY scan_type (scan_type),
            KEY created_at (created_at)
        ) {$charset_collate};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql_logs );
        dbDelta( $sql_scans );
    }

    /**
     * Set default options if they don't exist.
     */
    private static function set_default_options() {
        if ( false === get_option( 'aipatch_settings' ) ) {
            update_option( 'aipatch_settings', AIPSC_Utils::get_default_settings(), false );
        }

        if ( false === get_option( 'aipatch_hardening' ) ) {
            update_option( 'aipatch_hardening', AIPSC_Utils::get_default_hardening(), false );
        }

        if ( false === get_option( 'aipatch_dismissed' ) ) {
            update_option( 'aipatch_dismissed', array(), false );
        }
    }

    /**
     * Schedule cron events.
     */
    private static function schedule_cron() {
        if ( ! wp_next_scheduled( 'aipatch_daily_scan' ) ) {
            wp_schedule_event( time(), 'daily', 'aipatch_daily_scan' );
        }

        if ( ! wp_next_scheduled( 'aipatch_log_cleanup' ) ) {
            wp_schedule_event( time(), 'daily', 'aipatch_log_cleanup' );
        }
    }

    /**
     * Check if DB needs upgrade and run if necessary.
     */
    public static function maybe_upgrade() {
        $installed_version = get_option( 'aipatch_db_version', '0' );

        if ( version_compare( $installed_version, AIPATCH_DB_VERSION, '<' ) ) {
            self::create_tables();
            update_option( 'aipatch_db_version', AIPATCH_DB_VERSION, false );
        }
    }
}
