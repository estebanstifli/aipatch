<?php
/**
 * Check: User enumeration.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_User_Enumeration extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'user_enumeration';
    }

    public function get_title(): string {
        return __( 'User Enumeration', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'users';
    }

    public function run(): array {
        $hardening            = AIPSC_Utils::get_hardening();
        $author_enum_blocked  = ! empty( $hardening['block_author_scanning'] );

        if ( $author_enum_blocked ) {
            return array();
        }

        $response = wp_remote_get( add_query_arg( 'author', '1', home_url( '/' ) ), array(
            'timeout'     => 10,
            'sslverify'   => false,
            'redirection' => 0,
        ) );

        if ( is_wp_error( $response ) ) {
            return array();
        }

        $status   = wp_remote_retrieve_response_code( $response );
        $location = wp_remote_retrieve_header( $response, 'location' );

        $enum_possible = false;
        if ( 301 === $status && ! empty( $location ) && strpos( $location, '/author/' ) !== false ) {
            $enum_possible = true;
        }
        if ( 200 === $status ) {
            $enum_possible = true;
        }

        if ( ! $enum_possible ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'user_enumeration',
                'title'           => __( 'User enumeration is possible', 'aipatch-security-scanner' ),
                'description'     => __( 'Usernames can be discovered via the ?author= parameter or author archive URLs.', 'aipatch-security-scanner' ),
                'severity'        => 'medium',
                'confidence'      => 'high',
                'category'        => 'users',
                'why_it_matters'  => __( 'Knowing valid usernames makes brute-force attacks much more effective. Attackers only need to guess the password.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Block author scanning from the Hardening page, or redirect/block ?author= requests in your .htaccess or server config.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'GET /?author=1 reveals user information',
                'fixable'         => true,
            ) ),
        );
    }
}
