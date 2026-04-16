<?php
/**
 * Check: Default "admin" username.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Admin_Username extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'admin_username';
    }

    public function get_title(): string {
        return __( 'Default Admin Username', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'users';
    }

    public function run(): array {
        $admin_user = get_user_by( 'login', 'admin' );
        if ( ! $admin_user ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'admin_username',
                'title'           => __( 'Default "admin" username exists', 'aipatch-security-scanner' ),
                'description'     => __( 'A user account with the username "admin" was detected.', 'aipatch-security-scanner' ),
                'severity'        => 'medium',
                'confidence'      => 'high',
                'category'        => 'users',
                'why_it_matters'  => __( 'The "admin" username is the first one attackers try in brute-force attacks. Using a unique username adds a layer of security.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Create a new administrator account with a unique username, transfer content, and delete the "admin" account.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'User "admin" exists (ID: %d)', $admin_user->ID ),
            ) ),
        );
    }
}
