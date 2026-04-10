<?php
/**
 * Cron module – scheduled tasks.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class PWW_Cron
 */
class PWW_Cron {

    /**
     * @var PWW_Scanner
     */
    private $scanner;

    /**
     * @var PWW_Logger
     */
    private $logger;

    /**
     * Constructor.
     *
     * @param PWW_Scanner $scanner Scanner instance.
     * @param PWW_Logger  $logger  Logger instance.
     */
    public function __construct( PWW_Scanner $scanner, PWW_Logger $logger ) {
        $this->scanner = $scanner;
        $this->logger  = $logger;
    }

    /**
     * Register cron hooks.
     */
    public function init() {
        add_action( 'aipatch_daily_scan', array( $this, 'run_scheduled_scan' ) );
        add_action( 'aipatch_log_cleanup', array( $this, 'run_log_cleanup' ) );
        add_filter( 'cron_schedules', array( $this, 'add_custom_schedules' ) );
    }

    /**
     * Add custom cron schedules.
     *
     * @param array $schedules Existing schedules.
     * @return array
     */
    public function add_custom_schedules( $schedules ) {
        $schedules['weekly'] = array(
            'interval' => WEEK_IN_SECONDS,
            'display'  => __( 'Once Weekly', 'aipatch-security-scanner' ),
        );
        return $schedules;
    }

    /**
     * Execute scheduled scan.
     */
    public function run_scheduled_scan() {
        $this->logger->info( 'cron_scan', __( 'Scheduled security scan started.', 'aipatch-security-scanner' ) );

        $results = $this->scanner->run_full_scan( 'cron' );

        $this->logger->info(
            'cron_scan',
            __( 'Scheduled security scan completed.', 'aipatch-security-scanner' ),
            array( 'score' => $results['score'], 'issues_count' => count( $results['issues'] ) )
        );
    }

    /**
     * Execute log cleanup.
     */
    public function run_log_cleanup() {
        $settings = PWW_Utils::get_settings();
        $days     = isset( $settings['log_retention_days'] ) ? (int) $settings['log_retention_days'] : 30;
        $deleted  = $this->logger->cleanup( $days );

        if ( $deleted > 0 ) {
            $this->logger->info(
                'log_cleanup',
                sprintf(
                    /* translators: %d: Number of log entries deleted. */
                    __( 'Cleaned up %d old log entries.', 'aipatch-security-scanner' ),
                    $deleted
                )
            );
        }
    }

    /**
     * Reschedule the scan cron based on settings.
     *
     * @param string $frequency daily|twicedaily|weekly.
     */
    public static function reschedule_scan( $frequency ) {
        $valid = array( 'daily', 'twicedaily', 'weekly' );
        if ( ! in_array( $frequency, $valid, true ) ) {
            $frequency = 'daily';
        }

        wp_clear_scheduled_hook( 'aipatch_daily_scan' );
        wp_schedule_event( time(), $frequency, 'aipatch_daily_scan' );
    }

    /**
     * Get next scheduled scan time.
     *
     * @return int|false
     */
    public static function get_next_scan() {
        return wp_next_scheduled( 'aipatch_daily_scan' );
    }

    /**
     * Get last scan timestamp.
     *
     * @return int
     */
    public static function get_last_scan() {
        return (int) PWW_Utils::get_option( 'last_scan', 0 );
    }
}
