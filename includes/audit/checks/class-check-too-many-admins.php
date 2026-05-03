<?php
/**
 * Check: Too many administrator accounts.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Too_Many_Admins extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'too_many_admins';
    }

    public function get_title(): string {
        return __( 'Excessive Admin Accounts', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'users';
    }

    public function run(): array {
        $admins = get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) );

        if ( count( $admins ) <= 3 ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'too_many_admins',
                'title'           => sprintf(
                    /* translators: %d: Number of administrator accounts. */
                    __( '%d administrator accounts detected', 'aipatch-security-scanner' ),
                    count( $admins )
                ),
                'description'     => __( 'Having many administrator accounts increases the attack surface.', 'aipatch-security-scanner' ),
                'severity'        => 'low',
                'confidence'      => 'high',
                'category'        => 'users',
                'why_it_matters'  => __( 'Each admin account is a potential target. If one is compromised, the attacker gains full control.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Review administrator accounts and downgrade roles where full admin access is not needed.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Found %d administrator accounts', count( $admins ) ),
                'meta'            => array( 'admin_count' => count( $admins ) ),
            ) ),
        );
    }
}
