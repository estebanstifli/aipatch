<?php
/**
 * Utility functions.
 *
 * @package PatchWatch
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class PWW_Utils
 *
 * Static utility helpers used across the plugin.
 */
class PWW_Utils {

    /**
     * Get a plugin option with default fallback.
     *
     * @param string $key     Option key (without prefix).
     * @param mixed  $default Default value.
     * @return mixed
     */
    public static function get_option( $key, $default = false ) {
        return get_option( 'aipatch_' . $key, $default );
    }

    /**
     * Update a plugin option.
     *
     * @param string $key   Option key (without prefix).
     * @param mixed  $value Value.
     * @return bool
     */
    public static function update_option( $key, $value ) {
        return update_option( 'aipatch_' . $key, $value, false );
    }

    /**
     * Delete a plugin option.
     *
     * @param string $key Option key (without prefix).
     * @return bool
     */
    public static function delete_option( $key ) {
        return delete_option( 'aipatch_' . $key );
    }

    /**
     * Get default settings.
     *
     * @return array
     */
    public static function get_default_settings() {
        return array(
            'scan_frequency'    => 'daily',
            'log_retention_days' => 30,
            'rest_compat_mode'  => false,
            'modules_enabled'   => array(
                'scanner'         => true,
                'hardening'       => true,
                'vulnerabilities' => true,
                'login_protection' => true,
            ),
        );
    }

    /**
     * Get default hardening options.
     *
     * @return array
     */
    public static function get_default_hardening() {
        return array(
            'disable_xmlrpc'       => false,
            'hide_wp_version'      => false,
            'restrict_rest_api'    => false,
            'login_protection'     => false,
            'login_max_attempts'   => 5,
            'login_lockout_duration' => 15,
        );
    }

    /**
     * Get current settings merged with defaults.
     *
     * @return array
     */
    public static function get_settings() {
        $defaults = self::get_default_settings();
        $saved    = self::get_option( 'settings', array() );
        return wp_parse_args( $saved, $defaults );
    }

    /**
     * Get current hardening options merged with defaults.
     *
     * @return array
     */
    public static function get_hardening() {
        $defaults = self::get_default_hardening();
        $saved    = self::get_option( 'hardening', array() );
        return wp_parse_args( $saved, $defaults );
    }

    /**
     * Severity label with color class.
     *
     * @param string $severity Severity level.
     * @return array With 'label' and 'class' keys.
     */
    public static function severity_info( $severity ) {
        $map = array(
            'critical' => array(
                'label' => __( 'Critical', 'patchwatch-wp' ),
                'class' => 'aipatch-severity-critical',
            ),
            'high' => array(
                'label' => __( 'High', 'patchwatch-wp' ),
                'class' => 'aipatch-severity-high',
            ),
            'medium' => array(
                'label' => __( 'Medium', 'patchwatch-wp' ),
                'class' => 'aipatch-severity-medium',
            ),
            'low' => array(
                'label' => __( 'Low', 'patchwatch-wp' ),
                'class' => 'aipatch-severity-low',
            ),
        );

        return isset( $map[ $severity ] ) ? $map[ $severity ] : $map['low'];
    }

    /**
     * Get severity weight for score calculation.
     *
     * @param string $severity Severity level.
     * @return int
     */
    public static function severity_weight( $severity ) {
        $weights = array(
            'critical' => 20,
            'high'     => 15,
            'medium'   => 10,
            'low'      => 5,
        );
        return isset( $weights[ $severity ] ) ? $weights[ $severity ] : 5;
    }

    /**
     * Hash an IP address for storage (privacy-friendly).
     *
     * @param string $ip IP address.
     * @return string
     */
    public static function hash_ip( $ip ) {
        return md5( $ip . wp_salt( 'auth' ) );
    }

    /**
     * Get the real client IP address.
     *
     * @return string
     */
    public static function get_client_ip() {
        $ip = '';
        if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        }
        return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
    }

    /**
     * Check if the current user has admin capabilities.
     *
     * @return bool
     */
    public static function current_user_can_manage() {
        return current_user_can( 'manage_options' );
    }

    /**
     * Format a timestamp for display.
     *
     * @param int $timestamp Unix timestamp.
     * @return string
     */
    public static function format_time( $timestamp ) {
        if ( empty( $timestamp ) ) {
            return __( 'Never', 'patchwatch-wp' );
        }
        return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $timestamp );
    }

    /**
     * Get all plugin option keys for cleanup.
     *
     * @return array
     */
    public static function get_all_option_keys() {
        return array(
            'aipatch_settings',
            'aipatch_hardening',
            'aipatch_scan_results',
            'aipatch_last_scan',
            'aipatch_security_score',
            'aipatch_dismissed',
            'aipatch_db_version',
        );
    }
}
