<?php
/**
 * Plugin installer: activation, deactivation, and upgrade routines.
 *
 * @package PatchWatch
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class PWW_Installer
 */
class PWW_Installer {

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

        $table_name      = $wpdb->prefix . 'pww_logs';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table_name} (
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

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );
    }

    /**
     * Set default options if they don't exist.
     */
    private static function set_default_options() {
        if ( false === get_option( 'aipatch_settings' ) ) {
            update_option( 'aipatch_settings', PWW_Utils::get_default_settings(), false );
        }

        if ( false === get_option( 'aipatch_hardening' ) ) {
            update_option( 'aipatch_hardening', PWW_Utils::get_default_hardening(), false );
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
