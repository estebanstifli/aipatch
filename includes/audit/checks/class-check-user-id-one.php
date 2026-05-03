<?php
/**
 * Check: User ID 1 is administrator.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_User_ID_One extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'user_id_one';
    }

    public function get_title(): string {
        return __( 'User ID 1 Status', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'users';
    }

    public function run(): array {
        $user = get_user_by( 'ID', 1 );

        if ( ! $user || ! in_array( 'administrator', $user->roles, true ) ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'admin_user_id_one',
                'title'           => __( 'User ID 1 is an administrator', 'aipatch-security-scanner' ),
                'description'     => sprintf(
                    /* translators: %s: Username of the administrator account with ID 1. */
                    __( 'The user "%s" (ID 1) has administrator privileges. This is the first target in enumeration attacks.', 'aipatch-security-scanner' ),
                    $user->user_login
                ),
                'severity'        => 'low',
                'confidence'      => 'high',
                'category'        => 'users',
                'why_it_matters'  => __( 'User ID 1 is the default first account. Attackers specifically target it for brute-force and privilege escalation attacks.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Create a new admin account, transfer ownership of posts, and change user ID 1 to a subscriber or editor role.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'User ID 1 (%s) is administrator', $user->user_login ),
            ) ),
        );
    }
}
