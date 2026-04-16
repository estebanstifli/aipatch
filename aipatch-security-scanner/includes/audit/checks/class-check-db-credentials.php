<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class AIPSC_Check_DB_Credentials extends AIPSC_Audit_Check_Base {
    public function get_id(): string { return 'db_credentials'; }
    public function get_title(): string { return __( 'Database Credential Security', 'aipatch-security-scanner' ); }
    public function get_category(): string { return 'configuration'; }

    public function run(): array {
        $results = array();

        // Check for weak DB password.
        if ( defined( 'DB_PASSWORD' ) ) {
            $pass = DB_PASSWORD;
            if ( strlen( $pass ) < 12 ) {
                $results[] = $this->make_result( array(
                    'id'             => 'db_password_short',
                    'title'          => __( 'Short database password', 'aipatch-security-scanner' ),
                    'severity'       => AIPSC_Audit_Check_Result::SEVERITY_HIGH,
                    'description'    => __( 'The database password is shorter than 12 characters.', 'aipatch-security-scanner' ),
                    'why_it_matters' => __( 'Short passwords are easier to brute-force if database access is exposed.', 'aipatch-security-scanner' ),
                    'recommendation' => __( 'Use a strong, randomly generated database password of at least 20 characters.', 'aipatch-security-scanner' ),
                    'evidence'       => sprintf( 'Password length: %d characters', strlen( $pass ) ),
                ) );
            }

            if ( strtolower( $pass ) === strtolower( DB_USER ) ) {
                $results[] = $this->make_result( array(
                    'id'             => 'db_password_equals_user',
                    'title'          => __( 'Database password same as username', 'aipatch-security-scanner' ),
                    'severity'       => AIPSC_Audit_Check_Result::SEVERITY_CRITICAL,
                    'description'    => __( 'DB_PASSWORD and DB_USER have the same value.', 'aipatch-security-scanner' ),
                    'why_it_matters' => __( 'This is an extremely weak credential configuration.', 'aipatch-security-scanner' ),
                    'recommendation' => __( 'Use a unique, strong database password.', 'aipatch-security-scanner' ),
                    'evidence'       => 'DB_PASSWORD === DB_USER',
                ) );
            }
        }

        // Check if DB host is external.
        if ( defined( 'DB_HOST' ) && 'localhost' !== DB_HOST && '127.0.0.1' !== DB_HOST ) {
            $results[] = $this->make_result( array(
                'id'                       => 'db_host_external',
                'title'                    => __( 'External database host', 'aipatch-security-scanner' ),
                'severity'                 => AIPSC_Audit_Check_Result::SEVERITY_LOW,
                'confidence'               => AIPSC_Audit_Check_Result::CONFIDENCE_MEDIUM,
                'description'              => __( 'Database is on a non-local host — database traffic may traverse the network.', 'aipatch-security-scanner' ),
                'why_it_matters'           => __( 'Non-local database connections can be intercepted if not encrypted.', 'aipatch-security-scanner' ),
                'recommendation'           => __( 'Ensure SSL/TLS is used for the database connection.', 'aipatch-security-scanner' ),
                'evidence'                 => 'DB_HOST = ' . DB_HOST,
                'false_positive_likelihood' => 'medium',
            ) );
        }

        if ( empty( $results ) ) {
            $results[] = $this->make_result( array(
                'id'          => 'db_credentials',
                'title'       => $this->get_title(),
                'severity'    => AIPSC_Audit_Check_Result::SEVERITY_INFO,
                'status'      => AIPSC_Audit_Check_Result::STATUS_PASS,
                'description' => __( 'Database credential configuration looks acceptable.', 'aipatch-security-scanner' ),
            ) );
        }

        return $results;
    }
}
