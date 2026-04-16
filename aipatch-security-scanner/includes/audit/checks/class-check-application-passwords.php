<?php
/**
 * Check: Application Passwords.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Application_Passwords extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'application_passwords';
    }

    public function get_title(): string {
        return __( 'Application Passwords', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'users';
    }

    public function run(): array {
        if ( version_compare( get_bloginfo( 'version' ), '5.6', '<' ) ) {
            return array();
        }

        $app_passwords_enabled = apply_filters( 'wp_is_application_passwords_available', true );
        if ( ! $app_passwords_enabled ) {
            return array();
        }

        $admins                    = get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) );
        $users_with_app_passwords  = 0;

        foreach ( $admins as $admin_id ) {
            $app_passwords = get_user_meta( $admin_id, '_application_passwords', true );
            if ( ! empty( $app_passwords ) ) {
                $users_with_app_passwords++;
            }
        }

        if ( $users_with_app_passwords > 0 ) {
            return array(
                $this->make_result( array(
                    'id'              => 'app_passwords_in_use',
                    'title'           => sprintf(
                        _n( '%d admin has application passwords', '%d admins have application passwords', $users_with_app_passwords, 'aipatch-security-scanner' ),
                        $users_with_app_passwords
                    ),
                    'description'     => __( 'Application Passwords provide API access that bypasses two-factor authentication if configured.', 'aipatch-security-scanner' ),
                    'severity'        => 'medium',
                    'confidence'      => 'high',
                    'category'        => 'users',
                    'why_it_matters'  => __( 'Application Passwords bypass normal login protections including 2FA. If one leaks, an attacker gets full API access.', 'aipatch-security-scanner' ),
                    'recommendation'  => __( 'Review active application passwords in each admin user\'s profile. Remove any that are not actively used.', 'aipatch-security-scanner' ),
                    'dismissible'     => true,
                    'evidence'        => sprintf( '%d admin account(s) with application passwords', $users_with_app_passwords ),
                ) ),
            );
        }

        return array(
            $this->make_result( array(
                'id'              => 'app_passwords_enabled',
                'title'           => __( 'Application Passwords feature is enabled', 'aipatch-security-scanner' ),
                'description'     => __( 'The Application Passwords feature is active. Any user can generate API credentials.', 'aipatch-security-scanner' ),
                'severity'        => 'info',
                'confidence'      => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'While not a vulnerability itself, Application Passwords provide another authentication vector that should be monitored.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'If no integrations need Application Passwords, disable the feature by adding: add_filter( \'wp_is_application_passwords_available\', \'__return_false\' );', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'Application Passwords feature active, no admin app passwords found',
            ) ),
        );
    }
}
