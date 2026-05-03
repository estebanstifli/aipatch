<?php
/**
 * Check: PHP version.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_PHP_Version extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'php_version';
    }

    public function get_title(): string {
        return __( 'PHP Version', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'server';
    }

    public function run(): array {
        if ( version_compare( PHP_VERSION, '8.0', '>=' ) ) {
            return array();
        }

        $severity = version_compare( PHP_VERSION, '7.4', '<' ) ? 'high' : 'medium';

        return array(
            $this->make_result( array(
                'id'              => 'php_outdated',
                'title'           => sprintf(
                    /* translators: %s: Installed PHP version. */
                    __( 'PHP %s is outdated', 'aipatch-security-scanner' ),
                    PHP_VERSION
                ),
                'description'     => __( 'Your PHP version is no longer receiving active security updates.', 'aipatch-security-scanner' ),
                'severity'        => $severity,
                'confidence'      => 'high',
                'category'        => 'server',
                'why_it_matters'  => __( 'Outdated PHP versions may have unpatched security vulnerabilities and degrade performance.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Contact your hosting provider to upgrade PHP to version 8.1 or higher.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'PHP version: %s', PHP_VERSION ),
            ) ),
        );
    }
}
