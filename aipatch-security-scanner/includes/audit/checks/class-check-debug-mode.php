<?php
/**
 * Check: Debug mode active.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Debug_Mode extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'debug_mode';
    }

    public function get_title(): string {
        return __( 'Debug Mode', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'configuration';
    }

    public function run(): array {
        if ( ! defined( 'WP_DEBUG' ) || ! WP_DEBUG ) {
            return array();
        }

        $severity = 'medium';
        if ( defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY ) {
            $severity = 'high';
        }

        return array(
            $this->make_result( array(
                'id'              => 'debug_enabled',
                'title'           => __( 'Debug mode is active', 'aipatch-security-scanner' ),
                'description'     => __( 'WP_DEBUG is enabled on this site.', 'aipatch-security-scanner' ),
                'severity'        => $severity,
                'confidence'      => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'Debug mode can expose sensitive information like file paths, database queries, and PHP errors to visitors.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Disable WP_DEBUG in wp-config.php for production sites. Use WP_DEBUG_LOG instead of WP_DEBUG_DISPLAY if you need logging.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf(
                    'WP_DEBUG=%s, WP_DEBUG_DISPLAY=%s',
                    WP_DEBUG ? 'true' : 'false',
                    ( defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY ) ? 'true' : 'false'
                ),
            ) ),
        );
    }
}
