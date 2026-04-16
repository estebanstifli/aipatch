<?php
/**
 * Check: Sensitive files exposed.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Sensitive_Files extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'sensitive_files';
    }

    public function get_title(): string {
        return __( 'Sensitive Files Exposure', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'configuration';
    }

    public function run(): array {
        $sensitive_files = array(
            'readme.html'          => __( 'WordPress readme (exposes version)', 'aipatch-security-scanner' ),
            'license.txt'          => __( 'License file (confirms WordPress)', 'aipatch-security-scanner' ),
            'wp-config-sample.php' => __( 'Sample config (may leak server paths)', 'aipatch-security-scanner' ),
        );

        $found_files = array();
        foreach ( $sensitive_files as $file => $desc ) {
            if ( file_exists( ABSPATH . $file ) ) {
                $found_files[ $file ] = $desc;
            }
        }

        if ( empty( $found_files ) ) {
            return array();
        }

        $file_list = array_keys( $found_files );

        return array(
            $this->make_result( array(
                'id'              => 'sensitive_files_exposed',
                'title'           => sprintf(
                    _n( '%d sensitive file is publicly accessible', '%d sensitive files are publicly accessible', count( $found_files ), 'aipatch-security-scanner' ),
                    count( $found_files )
                ),
                'description'     => sprintf(
                    __( 'These files exist and may be accessible: %s', 'aipatch-security-scanner' ),
                    implode( ', ', array_map( 'esc_html', $file_list ) )
                ),
                'severity'        => 'low',
                'confidence'      => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'These files can reveal your WordPress version, server configuration, or confirm that WordPress is installed, making targeted attacks easier.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Delete readme.html, license.txt, and wp-config-sample.php. Block access via .htaccess or server config.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Found: %s', implode( ', ', $file_list ) ),
                'meta'            => array( 'files' => $found_files ),
            ) ),
        );
    }
}
