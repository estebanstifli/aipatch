<?php
/**
 * Check: REST API exposure.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_REST_Exposure extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'rest_exposure';
    }

    public function get_title(): string {
        return __( 'REST API Exposure', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'configuration';
    }

    public function run(): array {
        $hardening = AIPSC_Utils::get_hardening();

        if ( ! empty( $hardening['restrict_rest_api'] ) ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'rest_api_exposed',
                'title'           => __( 'REST API is publicly accessible', 'aipatch-security-scanner' ),
                'description'     => __( 'The WordPress REST API exposes user enumeration and other data to unauthenticated requests.', 'aipatch-security-scanner' ),
                'severity'        => 'low',
                'confidence'      => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'Attackers can enumerate usernames via /wp-json/wp/v2/users and gather information about your site structure.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Enable REST API restrictions from the Hardening page. Compatible mode keeps public endpoints working.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'REST API restrictions not enabled in hardening settings',
                'fixable'         => true,
            ) ),
        );
    }
}
