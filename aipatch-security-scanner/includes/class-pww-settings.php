<?php
/**
 * Settings module.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class PWW_Settings
 */
class PWW_Settings {

    /**
     * Register settings with WordPress Settings API.
     */
    public function register() {
        register_setting(
            'aipatch_settings_group',
            'aipatch_settings',
            array(
                'type'              => 'array',
                'sanitize_callback' => array( $this, 'sanitize_settings' ),
                'default'           => PWW_Utils::get_default_settings(),
            )
        );
    }

    /**
     * Sanitize settings on save.
     *
     * @param array $input Raw input.
     * @return array Sanitized settings.
     */
    public function sanitize_settings( $input ) {
        $clean    = array();
        $defaults = PWW_Utils::get_default_settings();

        // Scan frequency.
        $valid_frequencies = array( 'daily', 'twicedaily', 'weekly' );
        $clean['scan_frequency'] = isset( $input['scan_frequency'] ) && in_array( $input['scan_frequency'], $valid_frequencies, true )
            ? $input['scan_frequency']
            : $defaults['scan_frequency'];

        // Log retention.
        $valid_retention = array( 7, 14, 30, 60, 90 );
        $clean['log_retention_days'] = isset( $input['log_retention_days'] ) && in_array( (int) $input['log_retention_days'], $valid_retention, true )
            ? (int) $input['log_retention_days']
            : $defaults['log_retention_days'];

        // REST compat mode.
        $clean['rest_compat_mode'] = ! empty( $input['rest_compat_mode'] );

        // Modules enabled.
        $module_keys = array( 'scanner', 'hardening', 'vulnerabilities', 'login_protection' );
        $clean['modules_enabled'] = array();
        foreach ( $module_keys as $key ) {
            $clean['modules_enabled'][ $key ] = ! empty( $input['modules_enabled'][ $key ] );
        }

        // Reschedule cron if frequency changed.
        $current = PWW_Utils::get_settings();
        if ( $clean['scan_frequency'] !== $current['scan_frequency'] ) {
            PWW_Cron::reschedule_scan( $clean['scan_frequency'] );
        }

        return $clean;
    }

    /**
     * Check if a module is enabled.
     *
     * @param string $module Module key.
     * @return bool
     */
    public static function is_module_enabled( $module ) {
        $settings = PWW_Utils::get_settings();
        return ! empty( $settings['modules_enabled'][ $module ] );
    }
}
