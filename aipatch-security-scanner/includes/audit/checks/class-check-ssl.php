<?php
/**
 * Check: SSL / HTTPS.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_SSL extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'ssl';
    }

    public function get_title(): string {
        return __( 'HTTPS Status', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'server';
    }

    public function run(): array {
        if ( is_ssl() ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'no_ssl',
                'title'           => __( 'Site is not using HTTPS', 'aipatch-security-scanner' ),
                'description'     => __( 'This site is accessible over an unencrypted HTTP connection.', 'aipatch-security-scanner' ),
                'severity'        => 'high',
                'confidence'      => 'high',
                'category'        => 'server',
                'why_it_matters'  => __( 'Without HTTPS, data between your visitors and the server (including passwords) is sent in plain text and can be intercepted.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Install an SSL certificate (many hosts offer free Let\'s Encrypt certificates) and force HTTPS.', 'aipatch-security-scanner' ),
                'dismissible'     => false,
                'evidence'        => sprintf( 'Site URL: %s', home_url() ),
            ) ),
        );
    }
}
