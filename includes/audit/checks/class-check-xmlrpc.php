<?php
/**
 * Check: XML-RPC enabled.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_XMLRPC extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'xmlrpc';
    }

    public function get_title(): string {
        return __( 'XML-RPC Status', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'configuration';
    }

    public function run(): array {
        $hardening       = AIPSC_Utils::get_hardening();
        $xmlrpc_disabled = ! empty( $hardening['disable_xmlrpc'] );

        if ( $xmlrpc_disabled ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'xmlrpc_enabled',
                'title'           => __( 'XML-RPC is enabled', 'aipatch-security-scanner' ),
                'description'     => __( 'The XML-RPC interface is currently accessible.', 'aipatch-security-scanner' ),
                'severity'        => 'medium',
                'confidence'      => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'XML-RPC can be exploited for brute-force amplification attacks and DDoS. Most modern sites do not need it.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Disable XML-RPC from the Hardening page unless you use Jetpack, the WordPress mobile app, or XML-RPC clients.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'XML-RPC not disabled via hardening settings',
                'fixable'         => true,
            ) ),
        );
    }
}
