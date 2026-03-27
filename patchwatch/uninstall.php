<?php
/**
 * Uninstall handler.
 *
 * Removes all plugin data when the plugin is deleted through WordPress admin.
 * This file is called by WordPress when the plugin is uninstalled.
 *
 * @package PatchWatch
 */

// Prevent direct access or execution outside of uninstall context.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

// Remove all plugin options.
$aipatch_options = array(
    'aipatch_settings',
    'aipatch_hardening',
    'aipatch_scan_results',
    'aipatch_last_scan',
    'aipatch_security_score',
    'aipatch_dismissed',
    'aipatch_db_version',
);

foreach ( $aipatch_options as $option ) {
    delete_option( $option );
}

// Remove the custom log table.
global $wpdb;
$table_name = esc_sql( $wpdb->prefix . 'pww_logs' );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared
$wpdb->query( 'DROP TABLE IF EXISTS `' . $table_name . '`' );

// Clear scheduled cron events.
wp_clear_scheduled_hook( 'aipatch_daily_scan' );
wp_clear_scheduled_hook( 'aipatch_log_cleanup' );

// Clean up transients (login protection).
// Note: We cannot enumerate all transients, but the main ones expire naturally.
// We clean known patterns if possible.
$options_table = esc_sql( $wpdb->options );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
$wpdb->query(
    'DELETE FROM `' . $options_table . "` WHERE option_name LIKE '_transient_aipatch_%' OR option_name LIKE '_transient_timeout_aipatch_%'"
);
