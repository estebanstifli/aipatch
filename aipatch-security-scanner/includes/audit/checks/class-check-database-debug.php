<?php
/**
 * Check: Database debug settings.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Database_Debug extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'database_debug';
    }

    public function get_title(): string {
        return __( 'Database Debug Settings', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'configuration';
    }

    public function run(): array {
        global $wpdb;
        $results = array();

        if ( defined( 'SAVEQUERIES' ) && constant( 'SAVEQUERIES' ) ) {
            $results[] = $this->make_result( array(
                'id'              => 'savequeries_enabled',
                'title'           => __( 'SAVEQUERIES is enabled', 'aipatch-security-scanner' ),
                'description'     => __( 'WordPress is logging all database queries. This impacts performance and may expose sensitive data.', 'aipatch-security-scanner' ),
                'severity'        => 'medium',
                'confidence'      => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'SAVEQUERIES stores every SQL query in memory, reducing performance and potentially exposing database structure.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Remove or set SAVEQUERIES to false in wp-config.php. Use it only during active debugging sessions.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'SAVEQUERIES constant is true',
            ) );
        }

        if ( property_exists( $wpdb, 'show_errors' ) && $wpdb->show_errors ) {
            $results[] = $this->make_result( array(
                'id'              => 'db_errors_shown',
                'title'           => __( 'Database errors are displayed', 'aipatch-security-scanner' ),
                'description'     => __( 'Database error messages are being shown, potentially exposing table names and query structure.', 'aipatch-security-scanner' ),
                'severity'        => 'medium',
                'confidence'      => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'Visible database errors help attackers understand your database structure and craft SQL injection attacks.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Ensure $wpdb->show_errors is not enabled on production. This is typically controlled by WP_DEBUG.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'wpdb show_errors is enabled',
            ) );
        }

        return $results;
    }
}
