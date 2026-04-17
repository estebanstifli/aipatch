<?php
/**
 * Check: Security headers.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Security_Headers extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'security_headers';
    }

    public function get_title(): string {
        return __( 'Security Headers', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'server';
    }

    public function run(): array {
        $results = array();

        $response = wp_remote_get( home_url( '/' ), array(
            'timeout'     => 10,
            'sslverify'   => false,
            'redirection' => 0,
        ) );

        if ( is_wp_error( $response ) ) {
            return array();
        }

        $headers = wp_remote_retrieve_headers( $response );

        $security_headers = array(
            'x-content-type-options' => 'X-Content-Type-Options',
            'x-frame-options'        => 'X-Frame-Options',
            'x-xss-protection'       => 'X-XSS-Protection',
            'referrer-policy'        => 'Referrer-Policy',
            'permissions-policy'     => 'Permissions-Policy',
        );

        $missing_headers = array();
        foreach ( $security_headers as $key => $label ) {
            if ( empty( $headers[ $key ] ) ) {
                $missing_headers[] = $label;
            }
        }

        if ( ! empty( $missing_headers ) ) {
            $severity = count( $missing_headers ) >= 4 ? 'medium' : 'low';

            $results[] = $this->make_result( array(
                'id'              => 'missing_security_headers',
                'title'           => sprintf(
                    /* translators: %d: Number of missing security headers. */
                    _n( '%d security header missing', '%d security headers missing', count( $missing_headers ), 'aipatch-security-scanner' ),
                    count( $missing_headers )
                ),
                'description'     => sprintf(
                    /* translators: %s: Comma-separated list of missing security headers. */
                    __( 'Missing headers: %s', 'aipatch-security-scanner' ),
                    implode( ', ', $missing_headers )
                ),
                'severity'        => $severity,
                'confidence'      => 'high',
                'category'        => 'server',
                'why_it_matters'  => __( 'Security headers protect against common attacks like clickjacking, MIME-sniffing, and cross-site scripting.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Add security headers via your server configuration, .htaccess, or a security plugin. At minimum, add X-Content-Type-Options: nosniff and X-Frame-Options: SAMEORIGIN.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Missing: %s', implode( ', ', $missing_headers ) ),
                'meta'            => array( 'missing' => $missing_headers ),
            ) );
        }

        if ( empty( $headers['content-security-policy'] ) ) {
            $results[] = $this->make_result( array(
                'id'              => 'no_csp_header',
                'title'           => __( 'Content-Security-Policy header not set', 'aipatch-security-scanner' ),
                'description'     => __( 'No Content-Security-Policy header was detected on the homepage.', 'aipatch-security-scanner' ),
                'severity'        => 'low',
                'confidence'      => 'high',
                'category'        => 'server',
                'why_it_matters'  => __( 'CSP is one of the most effective defenses against XSS attacks. Without it, injected scripts can execute freely.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Implement a Content-Security-Policy header. Start with a report-only policy to test before enforcing.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'Content-Security-Policy header not present',
            ) );
        }

        return $results;
    }
}
