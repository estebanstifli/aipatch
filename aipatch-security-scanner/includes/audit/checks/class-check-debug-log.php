<?php
/**
 * Check: Debug log file exposure.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Debug_Log extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'debug_log';
    }

    public function get_title(): string {
        return __( 'Debug Log Exposure', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'configuration';
    }

    public function run(): array {
        $debug_log = WP_CONTENT_DIR . '/debug.log';

        if ( ! file_exists( $debug_log ) ) {
            return array();
        }

        $size = filesize( $debug_log );

        return array(
            $this->make_result( array(
                'id'              => 'debug_log_exists',
                'title'           => __( 'Debug log file exists in wp-content', 'aipatch-security-scanner' ),
                'description'     => sprintf(
                    __( 'A debug.log file (%s) was found. This file might be accessible publicly.', 'aipatch-security-scanner' ),
                    size_format( $size )
                ),
                'severity'        => 'high',
                'confidence'      => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'The debug log can contain sensitive information like file paths, database queries, plugin errors, and user data.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Delete the debug.log file and block access to it via .htaccess. If debugging is needed, use a custom log path outside the web root.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'debug.log found (%s)', size_format( $size ) ),
                'meta'            => array( 'file_size' => $size ),
            ) ),
        );
    }
}
