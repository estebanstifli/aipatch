<?php
/**
 * Check: File permissions on wp-config.php (Unix only).
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_File_Permissions extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'file_permissions';
    }

    public function get_title(): string {
        return __( 'Critical File Permissions', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'server';
    }

    public function run(): array {
        // Skip on Windows.
        if ( 'WIN' === strtoupper( substr( PHP_OS, 0, 3 ) ) ) {
            return array();
        }

        $wp_config = ABSPATH . 'wp-config.php';
        if ( ! file_exists( $wp_config ) ) {
            $wp_config = dirname( ABSPATH ) . '/wp-config.php';
        }

        if ( ! file_exists( $wp_config ) ) {
            return array();
        }

        $perms = fileperms( $wp_config ) & 0777;
        if ( $perms <= 0644 ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'wpconfig_permissions',
                'title'           => __( 'wp-config.php has loose permissions', 'aipatch-security-scanner' ),
                'description'     => sprintf(
                    /* translators: %s: Octal file permissions for wp-config.php. */
                    __( 'Current permissions: %s. Recommended: 0644 or more restrictive.', 'aipatch-security-scanner' ),
                    decoct( $perms )
                ),
                'severity'        => 'high',
                'confidence'      => 'high',
                'category'        => 'server',
                'why_it_matters'  => __( 'wp-config.php contains database credentials and secret keys. Loose permissions may allow other users on the server to read it.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Set wp-config.php permissions to 0644 or 0640 via your hosting file manager or SSH.', 'aipatch-security-scanner' ),
                'dismissible'     => false,
                'evidence'        => sprintf( 'wp-config.php permissions: 0%s', decoct( $perms ) ),
            ) ),
        );
    }
}
