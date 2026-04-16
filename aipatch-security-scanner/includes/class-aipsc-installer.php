<?php
/**
 * Plugin installer: activation, deactivation, and upgrade routines.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Installer
 */
class AIPSC_Installer {

    /**
     * Run on plugin activation.
     */
    public static function activate() {
        self::create_tables();
        self::set_default_options();
        self::schedule_cron();

        // Store installed version.
        update_option( 'aipatch_db_version', AIPATCH_DB_VERSION, false );

        // Flush rewrite rules on next load.
        set_transient( 'aipatch_flush_rewrite', 1, 60 );
    }

    /**
     * Run on plugin deactivation.
     */
    public static function deactivate() {
        wp_clear_scheduled_hook( 'aipatch_daily_scan' );
        wp_clear_scheduled_hook( 'aipatch_log_cleanup' );
    }

    /**
     * Create custom database tables.
     */
    private static function create_tables() {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();

        // Logs table.
        $logs_table = $wpdb->prefix . 'aipsc_logs';
        $sql_logs = "CREATE TABLE {$logs_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            event_type VARCHAR(50) NOT NULL DEFAULT '',
            severity VARCHAR(20) NOT NULL DEFAULT 'info',
            message TEXT NOT NULL,
            context_json LONGTEXT DEFAULT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY event_type (event_type),
            KEY severity (severity),
            KEY created_at (created_at)
        ) {$charset_collate};";

        // Scan history table.
        $scans_table = $wpdb->prefix . 'aipsc_scan_history';
        $sql_scans = "CREATE TABLE {$scans_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            scan_type VARCHAR(20) NOT NULL DEFAULT 'manual',
            score INT NOT NULL DEFAULT 0,
            issues_count INT NOT NULL DEFAULT 0,
            issues_json LONGTEXT DEFAULT NULL,
            duration_ms INT NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY scan_type (scan_type),
            KEY created_at (created_at)
        ) {$charset_collate};";

        // Jobs table — persistent job tracking.
        $jobs_table = $wpdb->prefix . 'aipsc_jobs';
        $sql_jobs = "CREATE TABLE {$jobs_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            job_id VARCHAR(64) NOT NULL,
            job_type VARCHAR(50) NOT NULL DEFAULT '',
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            progress SMALLINT UNSIGNED NOT NULL DEFAULT 0,
            total_items INT UNSIGNED NOT NULL DEFAULT 0,
            completed_items INT UNSIGNED NOT NULL DEFAULT 0,
            result_json LONGTEXT DEFAULT NULL,
            error_message TEXT DEFAULT NULL,
            input_json LONGTEXT DEFAULT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            started_at DATETIME DEFAULT NULL,
            completed_at DATETIME DEFAULT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY job_id (job_id),
            KEY status (status),
            KEY job_type (job_type),
            KEY created_at (created_at)
        ) {$charset_collate};";

        // Job items table — individual batch items within a job.
        $job_items_table = $wpdb->prefix . 'aipsc_job_items';
        $sql_job_items = "CREATE TABLE {$job_items_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            job_id VARCHAR(64) NOT NULL,
            item_key VARCHAR(255) NOT NULL DEFAULT '',
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            result_json LONGTEXT DEFAULT NULL,
            attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            processed_at DATETIME DEFAULT NULL,
            PRIMARY KEY (id),
            KEY job_id (job_id),
            KEY status (status)
        ) {$charset_collate};";

        // Findings table — persistent, deduplicated findings.
        $findings_table = $wpdb->prefix . 'aipsc_findings';
        $sql_findings = "CREATE TABLE {$findings_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            finding_id VARCHAR(100) NOT NULL,
            fingerprint VARCHAR(64) NOT NULL,
            title VARCHAR(255) NOT NULL DEFAULT '',
            severity VARCHAR(20) NOT NULL DEFAULT 'info',
            confidence VARCHAR(20) NOT NULL DEFAULT 'high',
            category VARCHAR(50) NOT NULL DEFAULT 'general',
            status VARCHAR(20) NOT NULL DEFAULT 'open',
            source VARCHAR(50) NOT NULL DEFAULT 'scanner',
            description TEXT DEFAULT NULL,
            why_it_matters TEXT DEFAULT NULL,
            recommendation TEXT DEFAULT NULL,
            evidence TEXT DEFAULT NULL,
            meta_json LONGTEXT DEFAULT NULL,
            fixable TINYINT(1) NOT NULL DEFAULT 0,
            false_positive_likelihood VARCHAR(20) NOT NULL DEFAULT 'none',
            first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            resolved_at DATETIME DEFAULT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY fingerprint (fingerprint),
            KEY finding_id (finding_id),
            KEY severity (severity),
            KEY category (category),
            KEY status (status),
            KEY source (source),
            KEY last_seen (last_seen)
        ) {$charset_collate};";

        // File baseline table — known-good file state.
        $baseline_table = $wpdb->prefix . 'aipsc_file_baseline';
        $sql_baseline = "CREATE TABLE {$baseline_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            file_path VARCHAR(500) NOT NULL,
            sha256 VARCHAR(64) NOT NULL DEFAULT '',
            file_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
            mtime INT UNSIGNED NOT NULL DEFAULT 0,
            origin_type VARCHAR(30) NOT NULL DEFAULT 'unknown',
            component_slug VARCHAR(100) NOT NULL DEFAULT '',
            component_version VARCHAR(30) NOT NULL DEFAULT '',
            first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY file_path (file_path(400)),
            KEY origin_type (origin_type),
            KEY component_slug (component_slug)
        ) {$charset_collate};";

        // File scan results — per-file risk analysis.
        $file_results_table = $wpdb->prefix . 'aipsc_file_scan_results';
        $sql_file_results = "CREATE TABLE {$file_results_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            job_id VARCHAR(64) NOT NULL DEFAULT '',
            file_path VARCHAR(500) NOT NULL,
            risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
            classification VARCHAR(50) NOT NULL DEFAULT 'clean',
            signals_json LONGTEXT DEFAULT NULL,
            sha256 VARCHAR(64) NOT NULL DEFAULT '',
            file_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
            scanned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY job_id (job_id),
            KEY file_path (file_path(400)),
            KEY risk_score (risk_score),
            KEY classification (classification)
        ) {$charset_collate};";

        // Vulnerability cache.
        $vuln_cache_table = $wpdb->prefix . 'aipsc_vulnerability_cache';
        $sql_vuln_cache = "CREATE TABLE {$vuln_cache_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            slug VARCHAR(200) NOT NULL,
            software_type VARCHAR(20) NOT NULL DEFAULT 'plugin',
            provider VARCHAR(50) NOT NULL DEFAULT 'local',
            data_json LONGTEXT DEFAULT NULL,
            fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY slug_type_provider (slug(150), software_type, provider),
            KEY expires_at (expires_at)
        ) {$charset_collate};";

        // Remediations log.
        $remediations_table = $wpdb->prefix . 'aipsc_remediations';
        $sql_remediations = "CREATE TABLE {$remediations_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            finding_fingerprint VARCHAR(64) NOT NULL DEFAULT '',
            action_type VARCHAR(50) NOT NULL DEFAULT '',
            description TEXT DEFAULT NULL,
            rollback_data LONGTEXT DEFAULT NULL,
            performed_by BIGINT UNSIGNED NOT NULL DEFAULT 0,
            status VARCHAR(20) NOT NULL DEFAULT 'applied',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            rolled_back_at DATETIME DEFAULT NULL,
            PRIMARY KEY (id),
            KEY finding_fingerprint (finding_fingerprint),
            KEY status (status),
            KEY created_at (created_at)
        ) {$charset_collate};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql_logs );
        dbDelta( $sql_scans );
        dbDelta( $sql_jobs );
        dbDelta( $sql_job_items );
        dbDelta( $sql_findings );
        dbDelta( $sql_baseline );
        dbDelta( $sql_file_results );
        dbDelta( $sql_vuln_cache );
        dbDelta( $sql_remediations );
    }

    /**
     * Set default options if they don't exist.
     */
    private static function set_default_options() {
        if ( false === get_option( 'aipatch_settings' ) ) {
            update_option( 'aipatch_settings', AIPSC_Utils::get_default_settings(), false );
        }

        if ( false === get_option( 'aipatch_hardening' ) ) {
            update_option( 'aipatch_hardening', AIPSC_Utils::get_default_hardening(), false );
        }

        if ( false === get_option( 'aipatch_dismissed' ) ) {
            update_option( 'aipatch_dismissed', array(), false );
        }
    }

    /**
     * Schedule cron events.
     */
    private static function schedule_cron() {
        if ( ! wp_next_scheduled( 'aipatch_daily_scan' ) ) {
            wp_schedule_event( time(), 'daily', 'aipatch_daily_scan' );
        }

        if ( ! wp_next_scheduled( 'aipatch_log_cleanup' ) ) {
            wp_schedule_event( time(), 'daily', 'aipatch_log_cleanup' );
        }
    }

    /**
     * Check if DB needs upgrade and run if necessary.
     */
    public static function maybe_upgrade() {
        $installed_version = get_option( 'aipatch_db_version', '0' );

        if ( version_compare( $installed_version, AIPATCH_DB_VERSION, '<' ) ) {
            self::create_tables();
            update_option( 'aipatch_db_version', AIPATCH_DB_VERSION, false );
        }
    }
}
