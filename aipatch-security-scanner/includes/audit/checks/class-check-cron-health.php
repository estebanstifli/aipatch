<?php
/**
 * Check: WordPress cron health.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Cron_Health extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'cron_health';
    }

    public function get_title(): string {
        return __( 'Cron Health', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'configuration';
    }

    public function run(): array {
        if ( ! defined( 'DISABLE_WP_CRON' ) || ! DISABLE_WP_CRON ) {
            return array();
        }

        $crons = _get_cron_array();
        if ( empty( $crons ) ) {
            return array();
        }

        $next    = min( array_keys( $crons ) );
        $overdue = $next < ( time() - HOUR_IN_SECONDS );

        if ( ! $overdue ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'cron_overdue',
                'title'           => __( 'WP-Cron is disabled and tasks are overdue', 'aipatch-security-scanner' ),
                'description'     => __( 'DISABLE_WP_CRON is true and scheduled tasks appear overdue.', 'aipatch-security-scanner' ),
                'severity'        => 'medium',
                'confidence'      => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'If cron isn\'t running, scheduled security scans, plugin updates, and other maintenance tasks won\'t execute.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Ensure a real system cron job calls wp-cron.php regularly (e.g. every 5 minutes) or remove DISABLE_WP_CRON.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'DISABLE_WP_CRON=true, next task due: %s', wp_date( 'Y-m-d H:i:s', $next ) ),
            ) ),
        );
    }
}
