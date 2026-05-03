<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class AIPSC_Check_CORS extends AIPSC_Audit_Check_Base {
    public function get_id(): string { return 'cors_config'; }
    public function get_title(): string { return __( 'CORS Configuration', 'aipatch-security-scanner' ); }
    public function get_category(): string { return 'configuration'; }

    public function run(): array {
        // Check if any CORS headers are being sent loosely via .htaccess.
        $htaccess = ABSPATH . '.htaccess';
        if ( file_exists( $htaccess ) && is_readable( $htaccess ) ) {
            $content = file_get_contents( $htaccess ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents

            if ( false !== $content && preg_match( '/Access-Control-Allow-Origin\s*["\']?\s*\*/', $content ) ) {
                return array( $this->make_result( array(
                    'id'             => 'cors_wildcard',
                    'title'          => __( 'Wildcard CORS origin in .htaccess', 'aipatch-security-scanner' ),
                    'severity'       => AIPSC_Audit_Check_Result::SEVERITY_MEDIUM,
                    'description'    => __( '.htaccess sets Access-Control-Allow-Origin: * which allows any domain to make cross-origin requests.', 'aipatch-security-scanner' ),
                    'why_it_matters' => __( 'A wildcard CORS policy allows any website to send authenticated requests if credentials are also allowed.', 'aipatch-security-scanner' ),
                    'recommendation' => __( 'Restrict CORS origin to specific trusted domains.', 'aipatch-security-scanner' ),
                    'evidence'       => 'Access-Control-Allow-Origin: * found in .htaccess',
                ) ) );
            }
        }

        return array( $this->make_result( array(
            'id'          => 'cors_config',
            'title'       => $this->get_title(),
            'severity'    => AIPSC_Audit_Check_Result::SEVERITY_INFO,
            'status'      => AIPSC_Audit_Check_Result::STATUS_PASS,
            'description' => __( 'No risky CORS configuration detected in .htaccess.', 'aipatch-security-scanner' ),
        ) ) );
    }
}
