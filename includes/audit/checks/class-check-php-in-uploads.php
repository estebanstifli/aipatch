<?php
/**
 * Check: PHP execution in uploads directory.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_PHP_In_Uploads extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'php_in_uploads';
    }

    public function get_title(): string {
        return __( 'PHP Execution in Uploads', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'server';
    }

    public function run(): array {
        $uploads_dir  = wp_upload_dir();
        $uploads_path = $uploads_dir['basedir'];
        $php_blocked  = false;

        // Check .htaccess in uploads.
        $htaccess = $uploads_path . '/.htaccess';
        if ( file_exists( $htaccess ) ) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
            $content = @file_get_contents( $htaccess );
            if ( $content && preg_match( '/php_flag\s+engine\s+off|<FilesMatch.*\.php.*>.*Deny|RemoveHandler\s+\.php|SetHandler\s+none/si', $content ) ) {
                $php_blocked = true;
            }
        }

        // Check web.config (IIS).
        if ( ! $php_blocked ) {
            $web_config = $uploads_path . '/web.config';
            if ( file_exists( $web_config ) ) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
                $content = @file_get_contents( $web_config );
                if ( $content && stripos( $content, '.php' ) !== false && stripos( $content, 'RequestFiltering' ) !== false ) {
                    $php_blocked = true;
                }
            }
        }

        if ( $php_blocked ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'php_in_uploads',
                'title'           => __( 'PHP execution not blocked in uploads', 'aipatch-security-scanner' ),
                'description'     => __( 'The uploads directory does not have rules preventing PHP file execution.', 'aipatch-security-scanner' ),
                'severity'        => 'high',
                'confidence'      => 'high',
                'category'        => 'server',
                'why_it_matters'  => __( 'If an attacker manages to upload a PHP file (via a vulnerability), it could be executed directly, giving them full control of your server.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Add a .htaccess file in your uploads directory with: php_flag engine off. For Nginx, add a location block to deny PHP execution.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'No PHP execution restriction found in uploads directory',
                'fixable'         => true,
            ) ),
        );
    }
}
