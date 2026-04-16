<?php
/**
 * Uninstall handler.
 *
 * Removes all plugin data when the plugin is deleted through WordPress admin.
 * This file is called by WordPress when the plugin is uninstalled.
 *
 * @package AipatchSecurityScanner
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
    'aipatch_performance_results',
    'aipatch_db_version',
);

foreach ( $aipatch_options as $aipsc_option ) {
    delete_option( $aipsc_option );
}

// Remove the custom tables.
global $wpdb;
$aipsc_tables = array(
    $wpdb->prefix . 'aipsc_remediations',
    $wpdb->prefix . 'aipsc_file_scan_results',
    $wpdb->prefix . 'aipsc_file_baseline',
    $wpdb->prefix . 'aipsc_vulnerability_cache',
    $wpdb->prefix . 'aipsc_findings',
    $wpdb->prefix . 'aipsc_job_items',
    $wpdb->prefix . 'aipsc_jobs',
    $wpdb->prefix . 'aipsc_scan_history',
    $wpdb->prefix . 'aipsc_logs',
);

foreach ( $aipsc_tables as $aipsc_table ) {
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
    $wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $aipsc_table ) );
}

// Clear scheduled cron events.
wp_clear_scheduled_hook( 'aipatch_daily_scan' );
wp_clear_scheduled_hook( 'aipatch_log_cleanup' );

// Clean up transients (login protection).
// Note: We cannot enumerate all transients, but the main ones expire naturally.
// We clean known patterns if possible.
$aipsc_options_table = $wpdb->options;
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query(
    $wpdb->prepare(
        'DELETE FROM %i WHERE option_name LIKE %s OR option_name LIKE %s',
        $aipsc_options_table,
        '_transient_aipatch_%',
        '_transient_timeout_aipatch_%'
    )
);
