<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class AIPSC_Check_Login_URL extends AIPSC_Audit_Check_Base {
    public function get_id(): string { return 'login_url'; }
    public function get_title(): string { return __( 'Default Login URL', 'aipatch-security-scanner' ); }
    public function get_category(): string { return 'access_control'; }

    public function run(): array {
        $login_url = wp_login_url();
        $default   = site_url( 'wp-login.php' );

        // If the login URL is the default, it's an attack surface.
        if ( $login_url === $default ) {
            return array( $this->make_result( array(
                'id'             => 'login_url_default',
                'title'          => __( 'Default wp-login.php URL in use', 'aipatch-security-scanner' ),
                'severity'       => AIPSC_Audit_Check_Result::SEVERITY_LOW,
                'confidence'     => AIPSC_Audit_Check_Result::CONFIDENCE_HIGH,
                'description'    => __( 'The login page is accessible at the default wp-login.php URL.', 'aipatch-security-scanner' ),
                'why_it_matters' => __( 'Bots and attackers automatically target wp-login.php for brute-force attacks.', 'aipatch-security-scanner' ),
                'recommendation' => __( 'Consider using a login-URL-hiding plugin or implementing login rate limiting.', 'aipatch-security-scanner' ),
                'evidence'       => $login_url,
            ) ) );
        }

        return array( $this->make_result( array(
            'id'          => 'login_url',
            'title'       => $this->get_title(),
            'severity'    => AIPSC_Audit_Check_Result::SEVERITY_INFO,
            'status'      => AIPSC_Audit_Check_Result::STATUS_PASS,
            'description' => __( 'Login URL has been customised.', 'aipatch-security-scanner' ),
        ) ) );
    }
}
