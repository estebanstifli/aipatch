<?php
/**
 * Utility functions.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Utils
 *
 * Static utility helpers used across the plugin.
 */
class AIPSC_Utils {

    /**
     * Get abilities registry used for settings and defaults.
     *
     * @return array
     */
    public static function get_abilities_registry() {
        return array(
            array(
                'key'      => 'audit_site',
                'name'     => 'aipatch/audit-site',
                'label'    => __( 'Audit Site', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'audit_suspicious',
                'name'     => 'aipatch/audit-suspicious',
                'label'    => __( 'Audit Suspicious Files', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'get_async_job_status',
                'name'     => 'aipatch/get-async-job-status',
                'label'    => __( 'Get Async Job Status', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'list_findings',
                'name'     => 'aipatch/list-findings',
                'label'    => __( 'List Findings', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'findings_stats',
                'name'     => 'aipatch/findings-stats',
                'label'    => __( 'Findings Statistics', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'findings_diff',
                'name'     => 'aipatch/findings-diff',
                'label'    => __( 'Findings Diff', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'dismiss_finding',
                'name'     => 'aipatch/dismiss-finding',
                'label'    => __( 'Dismiss Finding', 'aipatch-security-scanner' ),
                'readonly' => false,
            ),
            array(
                'key'      => 'start_file_scan',
                'name'     => 'aipatch/start-file-scan',
                'label'    => __( 'Start File Scan', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'file_scan_progress',
                'name'     => 'aipatch/file-scan-progress',
                'label'    => __( 'File Scan Progress', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'file_scan_results',
                'name'     => 'aipatch/file-scan-results',
                'label'    => __( 'File Scan Results', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'process_file_scan_batch',
                'name'     => 'aipatch/process-file-scan-batch',
                'label'    => __( 'Process File Scan Batch', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'baseline_build',
                'name'     => 'aipatch/baseline-build',
                'label'    => __( 'Build File Baseline', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'baseline_diff',
                'name'     => 'aipatch/baseline-diff',
                'label'    => __( 'Baseline Integrity Diff', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'baseline_stats',
                'name'     => 'aipatch/baseline-stats',
                'label'    => __( 'Baseline Statistics', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'list_jobs',
                'name'     => 'aipatch/list-jobs',
                'label'    => __( 'List Jobs', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'apply_remediation',
                'name'     => 'aipatch/apply-remediation',
                'label'    => __( 'Apply Remediation', 'aipatch-security-scanner' ),
                'readonly' => false,
            ),
            array(
                'key'      => 'rollback_remediation',
                'name'     => 'aipatch/rollback-remediation',
                'label'    => __( 'Rollback Remediation', 'aipatch-security-scanner' ),
                'readonly' => false,
            ),
            array(
                'key'      => 'list_remediations',
                'name'     => 'aipatch/list-remediations',
                'label'    => __( 'List Remediations', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'verify_core_integrity',
                'name'     => 'aipatch/verify-core-integrity',
                'label'    => __( 'Verify Core Integrity', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'list_suspicious_files',
                'name'     => 'aipatch/list-suspicious-files',
                'label'    => __( 'List Suspicious Files', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'get_file_finding_detail',
                'name'     => 'aipatch/get-file-finding-detail',
                'label'    => __( 'Get File Finding Detail', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'get_scan_summary',
                'name'     => 'aipatch/get-scan-summary',
                'label'    => __( 'Get Scan Summary', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
            array(
                'key'      => 'get_baseline_drift',
                'name'     => 'aipatch/get-baseline-drift',
                'label'    => __( 'Get Baseline Drift', 'aipatch-security-scanner' ),
                'readonly' => true,
            ),
        );
    }

    /**
     * Get settings map (key => ability name) for ability toggles.
     *
     * @return array
     */
    public static function get_ability_settings_map() {
        $map = array();

        foreach ( self::get_abilities_registry() as $ability ) {
            if ( empty( $ability['key'] ) || empty( $ability['name'] ) ) {
                continue;
            }

            $map[ $ability['key'] ] = $ability['name'];
        }

        return $map;
    }

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
        $abilities_enabled = array();
        foreach ( array_keys( self::get_ability_settings_map() ) as $ability_key ) {
            $abilities_enabled[ $ability_key ] = ( 'audit_site' === $ability_key );
        }

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
            'abilities_enabled' => $abilities_enabled,
        );
    }

    /**
     * Get default hardening options.
     *
     * @return array
     */
    public static function get_default_hardening() {
        return array(
            'disable_xmlrpc'         => false,
            'hide_wp_version'        => false,
            'restrict_rest_api'      => false,
            'block_author_scanning'  => false,
            'login_protection'       => false,
            'login_max_attempts'     => 5,
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
        $settings = wp_parse_args( $saved, $defaults );

        $settings['modules_enabled'] = wp_parse_args(
            ( isset( $saved['modules_enabled'] ) && is_array( $saved['modules_enabled'] ) ) ? $saved['modules_enabled'] : array(),
            $defaults['modules_enabled']
        );

        $settings['abilities_enabled'] = wp_parse_args(
            ( isset( $saved['abilities_enabled'] ) && is_array( $saved['abilities_enabled'] ) ) ? $saved['abilities_enabled'] : array(),
            $defaults['abilities_enabled']
        );

        return $settings;
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
     * Map scanner issue IDs to one-click hardening fixes.
     *
     * @param string $issue_id Scanner issue ID.
     * @return array|false Array with 'key' and 'label', or false if no quick fix.
     */
    public static function get_quick_fix( $issue_id ) {
        $map = array(
            'xmlrpc_enabled'    => array(
                'key'   => 'disable_xmlrpc',
                'label' => __( 'Disable XML-RPC', 'aipatch-security-scanner' ),
            ),
            'rest_api_exposed'  => array(
                'key'   => 'restrict_rest_api',
                'label' => __( 'Restrict REST API', 'aipatch-security-scanner' ),
            ),
            'user_enumeration'  => array(
                'key'   => 'block_author_scanning',
                'label' => __( 'Block Author Scanning', 'aipatch-security-scanner' ),
            ),
        );

        return isset( $map[ $issue_id ] ) ? $map[ $issue_id ] : false;
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
                'label' => __( 'Critical', 'aipatch-security-scanner' ),
                'class' => 'aipatch-severity-critical',
            ),
            'high' => array(
                'label' => __( 'High', 'aipatch-security-scanner' ),
                'class' => 'aipatch-severity-high',
            ),
            'medium' => array(
                'label' => __( 'Medium', 'aipatch-security-scanner' ),
                'class' => 'aipatch-severity-medium',
            ),
            'low' => array(
                'label' => __( 'Low', 'aipatch-security-scanner' ),
                'class' => 'aipatch-severity-low',
            ),
            'info' => array(
                'label' => __( 'Info', 'aipatch-security-scanner' ),
                'class' => 'aipatch-severity-info',
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
            'info'     => 0,
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
            return __( 'Never', 'aipatch-security-scanner' );
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
            'aipatch_performance_results',
            'aipatch_db_version',
        );
    }
}
