<?php
/**
 * Admin partial: Dashboard page (AJAX-first rendering).
 *
 * The shell renders instantly with skeleton loaders.
 * Data loads asynchronously via REST API for perceived speed.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
?>
<div class="wrap aipatch-wrap">
    <h1 class="aipatch-page-title">
        <span class="dashicons dashicons-shield"></span>
        <?php esc_html_e( 'Security Dashboard', 'aipatch-security-scanner' ); ?>
    </h1>

    <!-- Notices (populated by JS) -->
    <div id="aipatch-notices"></div>

    <!-- Top Bar: Score + Scan Panel -->
    <div class="aipatch-top-bar">
        <div class="aipatch-score-card" id="aipatch-score-card">
            <div class="aipatch-score-circle aipatch-skeleton-pulse">
                <span class="aipatch-score-number" id="aipatch-score-number">&mdash;</span>
                <span class="aipatch-score-max">/100</span>
            </div>
            <div class="aipatch-score-meta">
                <span class="aipatch-score-label" id="aipatch-score-label">
                    <span class="aipatch-skeleton-text">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>
                </span>
                <span class="aipatch-score-date" id="aipatch-score-date">
                    <span class="aipatch-skeleton-text">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>
                </span>
            </div>
        </div>

        <div class="aipatch-top-actions" id="aipatch-scan-panel">
            <div class="aipatch-scan-levels">
                <label class="aipatch-scan-level">
                    <input type="radio" name="aipatch_scan_level" value="quick" />
                    <span class="aipatch-scan-level-card">
                        <strong><?php esc_html_e( 'Quick', 'aipatch-security-scanner' ); ?></strong>
                        <small>~5s</small>
                    </span>
                </label>
                <label class="aipatch-scan-level">
                    <input type="radio" name="aipatch_scan_level" value="standard" checked />
                    <span class="aipatch-scan-level-card aipatch-scan-level-recommended">
                        <strong><?php esc_html_e( 'Standard', 'aipatch-security-scanner' ); ?></strong>
                        <small>~15s</small>
                    </span>
                </label>
                <label class="aipatch-scan-level">
                    <input type="radio" name="aipatch_scan_level" value="deep" />
                    <span class="aipatch-scan-level-card">
                        <strong><?php esc_html_e( 'Deep', 'aipatch-security-scanner' ); ?></strong>
                        <small>~60s</small>
                    </span>
                </label>
            </div>
            <button type="button" class="button button-primary button-hero" id="aipatch-run-scan">
                <span class="dashicons dashicons-search"></span>
                <?php esc_html_e( 'Run Scan', 'aipatch-security-scanner' ); ?>
            </button>
            <p class="aipatch-next-scan" id="aipatch-next-scan"></p>
        </div>
    </div>

    <!-- Scan Progress (hidden until scan starts) -->
    <div class="aipatch-scan-progress aipatch-hidden" id="aipatch-scan-progress">
        <div class="aipatch-progress-header">
            <div class="aipatch-progress-title-row">
                <span class="dashicons dashicons-update aipatch-spin" id="aipatch-progress-icon"></span>
                <strong id="aipatch-progress-title"><?php esc_html_e( 'Initializing scan...', 'aipatch-security-scanner' ); ?></strong>
            </div>
            <span class="aipatch-progress-pct" id="aipatch-progress-pct">0%</span>
        </div>
        <div class="aipatch-progress-bar-wrap">
            <div class="aipatch-progress-bar" id="aipatch-progress-bar"></div>
        </div>
        <div class="aipatch-progress-steps" id="aipatch-progress-steps"></div>
    </div>

    <!-- Score Trend Chart (hidden until data loaded → slides in) -->
    <div class="aipatch-section aipatch-chart-section aipatch-hidden" id="aipatch-chart-section">
        <div class="aipatch-section-header">
            <h2><?php esc_html_e( 'Score Trend', 'aipatch-security-scanner' ); ?></h2>
            <div class="aipatch-export-buttons">
                <button type="button" class="button button-small" id="aipatch-export-scans">
                    <span class="dashicons dashicons-download"></span>
                    <?php esc_html_e( 'Export CSV', 'aipatch-security-scanner' ); ?>
                </button>
            </div>
        </div>
        <div class="aipatch-chart-container">
            <canvas id="aipatch-score-chart" height="200"></canvas>
            <p class="aipatch-chart-empty aipatch-hidden"><?php esc_html_e( 'Run at least 2 scans to see the trend.', 'aipatch-security-scanner' ); ?></p>
        </div>
    </div>

    <!-- Summary Cards (skeleton) -->
    <div class="aipatch-cards-grid" id="aipatch-cards-grid">
        <?php for ( $aipsc_i = 0; $aipsc_i < 8; $aipsc_i++ ) : ?>
        <div class="aipatch-card aipatch-card-skeleton">
            <div class="aipatch-card-icon aipatch-skeleton-pulse aipatch-skeleton-icon"></div>
            <div class="aipatch-card-content">
                <span class="aipatch-card-value"><span class="aipatch-skeleton-text">&nbsp;&nbsp;&nbsp;&nbsp;</span></span>
                <span class="aipatch-card-label"><span class="aipatch-skeleton-text">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span></span>
            </div>
        </div>
        <?php endfor; ?>
    </div>

    <!-- Recommendations (populated by JS) -->
    <div class="aipatch-section aipatch-hidden" id="aipatch-recommendations-section">
        <h2><?php esc_html_e( 'Recommended Actions', 'aipatch-security-scanner' ); ?></h2>
        <div class="aipatch-recommendations" id="aipatch-recommendations"></div>
    </div>

    <!-- All Clear (shown by JS when no recommendations) -->
    <div class="aipatch-section aipatch-hidden" id="aipatch-all-clear">
        <div class="aipatch-all-clear">
            <span class="dashicons dashicons-yes-alt"></span>
            <p><?php esc_html_e( 'No active recommendations. Your site looks good!', 'aipatch-security-scanner' ); ?></p>
        </div>
    </div>

    <!-- Dismissed Issues (populated by JS) -->
    <div class="aipatch-section aipatch-section-collapsed aipatch-hidden" id="aipatch-dismissed-section">
        <h2 id="aipatch-dismissed-title"></h2>
        <div class="aipatch-dismissed-list" id="aipatch-dismissed-list"></div>
    </div>

    <!-- No-JS fallback -->
    <noscript>
        <div class="notice notice-warning"><p><?php esc_html_e( 'JavaScript is required for the security dashboard.', 'aipatch-security-scanner' ); ?></p></div>
        <form method="post" class="aipatch-inline-form">
            <?php wp_nonce_field( 'aipatch_run_scan', 'aipatch_scan_nonce' ); ?>
            <input type="hidden" name="aipatch_run_scan" value="1" />
            <button type="submit" class="button button-primary">
                <?php esc_html_e( 'Run Scan Now', 'aipatch-security-scanner' ); ?>
            </button>
        </form>
    </noscript>
</div>
