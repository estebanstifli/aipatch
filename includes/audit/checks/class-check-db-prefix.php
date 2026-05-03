<?php
/**
 * Check: Default database prefix.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_DB_Prefix extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'db_prefix';
    }

    public function get_title(): string {
        return __( 'Database Prefix', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'configuration';
    }

    public function run(): array {
        global $wpdb;

        if ( 'wp_' !== $wpdb->prefix ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'default_db_prefix',
                'title'           => __( 'Default database prefix (wp_) in use', 'aipatch-security-scanner' ),
                'description'     => __( 'Your database tables use the default wp_ prefix, which is well-known to attackers.', 'aipatch-security-scanner' ),
                'severity'        => 'low',
                'confidence'      => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'A custom table prefix adds a small layer of defense against automated SQL injection attacks that target the default prefix.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'For new installations, use a custom prefix. For existing sites, changing the prefix requires careful database migration.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Current DB prefix: %s', $wpdb->prefix ),
            ) ),
        );
    }
}
