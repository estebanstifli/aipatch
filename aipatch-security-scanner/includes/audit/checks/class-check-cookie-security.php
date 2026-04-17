<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class AIPSC_Check_Cookie_Security extends AIPSC_Audit_Check_Base {
    public function get_id(): string { return 'cookie_security'; }
    public function get_title(): string { return __( 'Cookie Security Flags', 'aipatch-security-scanner' ); }
    public function get_category(): string { return 'configuration'; }

    public function run(): array {
        $results = array();

        $secure   = ini_get( 'session.cookie_secure' );
        $httponly = ini_get( 'session.cookie_httponly' );
        $samesite = ini_get( 'session.cookie_samesite' );

        if ( is_ssl() && ! $secure ) {
            $results[] = $this->make_result( array(
                'id'             => 'cookie_not_secure',
                'title'          => __( 'Session cookies not marked Secure', 'aipatch-security-scanner' ),
                'severity'       => AIPSC_Audit_Check_Result::SEVERITY_MEDIUM,
                'description'    => __( 'session.cookie_secure is not enabled despite HTTPS.', 'aipatch-security-scanner' ),
                'why_it_matters' => __( 'Cookies without the Secure flag can be sent over HTTP, enabling interception.', 'aipatch-security-scanner' ),
                'recommendation' => __( 'Set session.cookie_secure = 1 in php.ini or via ini_set().', 'aipatch-security-scanner' ),
                'evidence'       => 'session.cookie_secure = ' . ( '' === (string) $secure ? '(empty)' : (string) $secure ),
            ) );
        }

        if ( ! $httponly ) {
            $results[] = $this->make_result( array(
                'id'             => 'cookie_not_httponly',
                'title'          => __( 'Session cookies not HttpOnly', 'aipatch-security-scanner' ),
                'severity'       => AIPSC_Audit_Check_Result::SEVERITY_LOW,
                'description'    => __( 'session.cookie_httponly is not set.', 'aipatch-security-scanner' ),
                'why_it_matters' => __( 'HttpOnly flag prevents JavaScript from accessing cookies, mitigating XSS impact.', 'aipatch-security-scanner' ),
                'recommendation' => __( 'Set session.cookie_httponly = 1 in php.ini.', 'aipatch-security-scanner' ),
                'evidence'       => 'session.cookie_httponly = ' . ( '' === (string) $httponly ? '(empty)' : (string) $httponly ),
            ) );
        }

        if ( empty( $samesite ) || 'None' === $samesite ) {
            $results[] = $this->make_result( array(
                'id'             => 'cookie_no_samesite',
                'title'          => __( 'Session cookies missing SameSite attribute', 'aipatch-security-scanner' ),
                'severity'       => AIPSC_Audit_Check_Result::SEVERITY_LOW,
                'description'    => __( 'session.cookie_samesite is not set to Lax or Strict.', 'aipatch-security-scanner' ),
                'why_it_matters' => __( 'SameSite attribute helps prevent CSRF attacks.', 'aipatch-security-scanner' ),
                'recommendation' => __( 'Set session.cookie_samesite = "Lax" in php.ini.', 'aipatch-security-scanner' ),
                'evidence'       => 'session.cookie_samesite = ' . ( '' === (string) $samesite ? '(empty)' : (string) $samesite ),
            ) );
        }

        if ( empty( $results ) ) {
            $results[] = $this->make_result( array(
                'id'       => 'cookie_security',
                'title'    => $this->get_title(),
                'severity' => AIPSC_Audit_Check_Result::SEVERITY_INFO,
                'status'   => AIPSC_Audit_Check_Result::STATUS_PASS,
                'description' => __( 'All cookie security flags are properly configured.', 'aipatch-security-scanner' ),
            ) );
        }

        return $results;
    }
}
