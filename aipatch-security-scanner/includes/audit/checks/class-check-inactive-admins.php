<?php
/**
 * Check: Inactive administrator accounts.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Inactive_Admins extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'inactive_admins';
    }

    public function get_title(): string {
        return __( 'Inactive Admin Accounts', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'users';
    }

    public function run(): array {
        $admins             = get_users( array( 'role' => 'administrator', 'fields' => array( 'ID', 'user_login' ) ) );
        $inactive_threshold = strtotime( '-6 months' );
        $inactive_admins    = array();

        foreach ( $admins as $admin ) {
            $last_login = get_user_meta( $admin->ID, 'last_login', true );

            if ( empty( $last_login ) ) {
                $sessions = get_user_meta( $admin->ID, 'session_tokens', true );
                if ( is_array( $sessions ) && ! empty( $sessions ) ) {
                    $latest = 0;
                    foreach ( $sessions as $session ) {
                        if ( isset( $session['login'] ) && $session['login'] > $latest ) {
                            $latest = $session['login'];
                        }
                    }
                    $last_login = $latest > 0 ? $latest : '';
                }
            }

            if ( empty( $last_login ) || (int) $last_login < $inactive_threshold ) {
                $inactive_admins[] = $admin->user_login;
            }
        }

        if ( empty( $inactive_admins ) ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'inactive_admins',
                'title'           => sprintf(
                    _n( '%d admin account appears inactive', '%d admin accounts appear inactive', count( $inactive_admins ), 'aipatch-security-scanner' ),
                    count( $inactive_admins )
                ),
                'description'     => sprintf(
                    __( 'Admin accounts with no recent login: %s', 'aipatch-security-scanner' ),
                    implode( ', ', array_map( 'esc_html', $inactive_admins ) )
                ),
                'severity'        => 'medium',
                'confidence'      => 'medium',
                'category'        => 'users',
                'why_it_matters'  => __( 'Dormant admin accounts are prime targets for attackers. If compromised, they provide full access and may go unnoticed.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Downgrade inactive admin accounts to a lower role, or delete them if they are no longer needed.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Inactive admins (>6 months): %s', implode( ', ', $inactive_admins ) ),
                'false_positive_likelihood' => 'low',
            ) ),
        );
    }
}
