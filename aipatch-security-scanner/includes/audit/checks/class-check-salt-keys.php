<?php
/**
 * Check: Salt keys quality.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Salt_Keys extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'salt_keys';
    }

    public function get_title(): string {
        return __( 'Security Salt Keys', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'configuration';
    }

    public function run(): array {
        $salt_constants = array(
            'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
            'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT',
        );

        $weak_salts      = array();
        $default_phrase   = 'put your unique phrase here';

        foreach ( $salt_constants as $constant ) {
            if ( ! defined( $constant ) ) {
                $weak_salts[] = $constant;
            } else {
                $value = constant( $constant );
                if ( empty( $value ) || $value === $default_phrase || strlen( $value ) < 32 ) {
                    $weak_salts[] = $constant;
                }
            }
        }

        if ( empty( $weak_salts ) ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'weak_salt_keys',
                'title'           => sprintf(
                    _n( '%d security salt key is weak or missing', '%d security salt keys are weak or missing', count( $weak_salts ), 'aipatch-security-scanner' ),
                    count( $weak_salts )
                ),
                'description'     => sprintf(
                    __( 'Weak keys: %s', 'aipatch-security-scanner' ),
                    implode( ', ', $weak_salts )
                ),
                'severity'        => count( $weak_salts ) > 4 ? 'high' : 'medium',
                'confidence'      => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'Salt keys protect cookies and passwords. Weak or default keys make it easier for attackers to forge session cookies.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Generate new salt keys at https://api.wordpress.org/secret-key/1.1/salt/ and replace them in your wp-config.php.', 'aipatch-security-scanner' ),
                'dismissible'     => false,
                'evidence'        => sprintf( 'Weak/missing: %s', implode( ', ', $weak_salts ) ),
                'meta'            => array( 'weak_keys' => $weak_salts ),
            ) ),
        );
    }
}
