<?php
/**
 * Admin partial: Dashboard page.
 *
 * @package AipatchSecurityScanner
 * @var array $data Dashboard data from AIPSC_Dashboard::get_dashboard_data().
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

    <?php if ( isset( $_GET['scan'] ) && 'complete' === $_GET['scan'] ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only display of redirect query param. ?>
        <div class="notice notice-success is-dismissible">
            <p><?php esc_html_e( 'Security scan completed successfully.', 'aipatch-security-scanner' ); ?></p>
        </div>
    <?php endif; ?>

    <!-- Score + Actions Bar -->
    <div class="aipatch-top-bar">
        <div class="aipatch-score-card <?php echo esc_attr( $data['score_class'] ); ?>">
            <div class="aipatch-score-circle">
                <span class="aipatch-score-number"><?php echo esc_html( $data['score'] ); ?></span>
                <span class="aipatch-score-max">/100</span>
            </div>
            <div class="aipatch-score-meta">
                <span class="aipatch-score-label"><?php echo esc_html( $data['score_label'] ); ?></span>
                <?php if ( $data['has_scan'] ) : ?>
                    <span class="aipatch-score-date">
                        <?php
                        printf(
                            /* translators: %s: Last scan time. */
                            esc_html__( 'Last scan: %s', 'aipatch-security-scanner' ),
                            esc_html( AIPSC_Utils::format_time( $data['last_scan'] ) )
                        );
                        ?>
                    </span>
                <?php else : ?>
                    <span class="aipatch-score-date"><?php esc_html_e( 'No scan yet. Run your first scan.', 'aipatch-security-scanner' ); ?></span>
                <?php endif; ?>
            </div>
        </div>

        <div class="aipatch-top-actions">
            <form method="post" class="aipatch-inline-form">
                <?php wp_nonce_field( 'aipatch_run_scan', 'aipatch_scan_nonce' ); ?>
                <button type="submit" name="aipatch_run_scan" value="1" class="button button-primary button-hero" id="aipatch-run-scan">
                    <span class="dashicons dashicons-search"></span>
                    <?php esc_html_e( 'Run Scan Now', 'aipatch-security-scanner' ); ?>
                </button>
            </form>
            <?php if ( $data['next_scan'] ) : ?>
                <p class="aipatch-next-scan">
                    <?php
                    printf(
                        /* translators: %s: Next scan time. */
                        esc_html__( 'Next automatic scan: %s', 'aipatch-security-scanner' ),
                        esc_html( AIPSC_Utils::format_time( $data['next_scan'] ) )
                    );
                    ?>
                </p>
            <?php endif; ?>
        </div>
    </div>

    <!-- Scan History Chart -->
    <?php if ( $data['has_scan'] ) : ?>
    <div class="aipatch-section">
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
            <p class="aipatch-chart-empty" style="display:none;"><?php esc_html_e( 'Run at least 2 scans to see the trend.', 'aipatch-security-scanner' ); ?></p>
        </div>
    </div>
    <?php endif; ?>

    <!-- Summary Cards -->
    <div class="aipatch-cards-grid">
        <div class="aipatch-card">
            <div class="aipatch-card-icon dashicons dashicons-admin-plugins"></div>
            <div class="aipatch-card-content">
                <span class="aipatch-card-value"><?php echo esc_html( $data['summary']['active_plugins'] ); ?></span>
                <span class="aipatch-card-label"><?php esc_html_e( 'Active Plugins', 'aipatch-security-scanner' ); ?></span>
            </div>
        </div>

        <div class="aipatch-card <?php echo $data['summary']['outdated_plugins'] > 0 ? 'aipatch-card-warning' : ''; ?>">
            <div class="aipatch-card-icon dashicons dashicons-warning"></div>
            <div class="aipatch-card-content">
                <span class="aipatch-card-value"><?php echo esc_html( $data['summary']['outdated_plugins'] ); ?></span>
                <span class="aipatch-card-label"><?php esc_html_e( 'Plugins Outdated', 'aipatch-security-scanner' ); ?></span>
            </div>
        </div>

        <div class="aipatch-card <?php echo ( isset( $data['summary']['inactive_plugins'] ) && $data['summary']['inactive_plugins'] > 3 ) ? 'aipatch-card-warning' : ''; ?>">
            <div class="aipatch-card-icon dashicons dashicons-plugins-checked"></div>
            <div class="aipatch-card-content">
                <span class="aipatch-card-value"><?php echo esc_html( isset( $data['summary']['inactive_plugins'] ) ? $data['summary']['inactive_plugins'] : 0 ); ?></span>
                <span class="aipatch-card-label"><?php esc_html_e( 'Inactive Plugins', 'aipatch-security-scanner' ); ?></span>
            </div>
        </div>

        <div class="aipatch-card <?php echo $data['summary']['outdated_themes'] > 0 ? 'aipatch-card-warning' : ''; ?>">
            <div class="aipatch-card-icon dashicons dashicons-admin-appearance"></div>
            <div class="aipatch-card-content">
                <span class="aipatch-card-value"><?php echo esc_html( $data['summary']['outdated_themes'] ); ?></span>
                <span class="aipatch-card-label"><?php esc_html_e( 'Themes Outdated', 'aipatch-security-scanner' ); ?></span>
            </div>
        </div>

        <div class="aipatch-card">
            <div class="aipatch-card-icon dashicons dashicons-wordpress"></div>
            <div class="aipatch-card-content">
                <span class="aipatch-card-value"><?php echo esc_html( $data['summary']['wp_version'] ); ?></span>
                <span class="aipatch-card-label"><?php esc_html_e( 'WordPress Version', 'aipatch-security-scanner' ); ?></span>
            </div>
        </div>

        <div class="aipatch-card">
            <div class="aipatch-card-icon dashicons dashicons-admin-users"></div>
            <div class="aipatch-card-content">
                <span class="aipatch-card-value"><?php echo esc_html( $data['summary']['admin_count'] ); ?></span>
                <span class="aipatch-card-label"><?php esc_html_e( 'Admin Users', 'aipatch-security-scanner' ); ?></span>
            </div>
        </div>

        <div class="aipatch-card <?php echo ! empty( $data['summary']['db_prefix_default'] ) ? 'aipatch-card-warning' : ''; ?>">
            <div class="aipatch-card-icon dashicons dashicons-database"></div>
            <div class="aipatch-card-content">
                <span class="aipatch-card-value"><?php echo ! empty( $data['summary']['db_prefix_default'] ) ? esc_html__( 'Default', 'aipatch-security-scanner' ) : esc_html__( 'Custom', 'aipatch-security-scanner' ); ?></span>
                <span class="aipatch-card-label"><?php esc_html_e( 'DB Prefix', 'aipatch-security-scanner' ); ?></span>
            </div>
        </div>

        <div class="aipatch-card <?php echo $data['summary']['xmlrpc_disabled'] ? '' : 'aipatch-card-warning'; ?>">
            <div class="aipatch-card-icon dashicons dashicons-<?php echo $data['summary']['xmlrpc_disabled'] ? 'lock' : 'unlock'; ?>"></div>
            <div class="aipatch-card-content">
                <span class="aipatch-card-value"><?php echo $data['summary']['xmlrpc_disabled'] ? esc_html__( 'Disabled', 'aipatch-security-scanner' ) : esc_html__( 'Enabled', 'aipatch-security-scanner' ); ?></span>
                <span class="aipatch-card-label"><?php esc_html_e( 'XML-RPC', 'aipatch-security-scanner' ); ?></span>
            </div>
        </div>

        <div class="aipatch-card <?php echo $data['summary']['rest_restricted'] ? '' : 'aipatch-card-info'; ?>">
            <div class="aipatch-card-icon dashicons dashicons-rest-api"></div>
            <div class="aipatch-card-content">
                <span class="aipatch-card-value"><?php echo $data['summary']['rest_restricted'] ? esc_html__( 'Restricted', 'aipatch-security-scanner' ) : esc_html__( 'Public', 'aipatch-security-scanner' ); ?></span>
                <span class="aipatch-card-label"><?php esc_html_e( 'REST API', 'aipatch-security-scanner' ); ?></span>
            </div>
        </div>

        <div class="aipatch-card <?php echo $data['summary']['debug_active'] ? 'aipatch-card-danger' : ''; ?>">
            <div class="aipatch-card-icon dashicons dashicons-<?php echo $data['summary']['debug_active'] ? 'warning' : 'yes-alt'; ?>"></div>
            <div class="aipatch-card-content">
                <span class="aipatch-card-value"><?php echo $data['summary']['debug_active'] ? esc_html__( 'Active', 'aipatch-security-scanner' ) : esc_html__( 'Off', 'aipatch-security-scanner' ); ?></span>
                <span class="aipatch-card-label"><?php esc_html_e( 'Debug Mode', 'aipatch-security-scanner' ); ?></span>
            </div>
        </div>

        <div class="aipatch-card <?php echo $data['summary']['file_editor_off'] ? '' : 'aipatch-card-warning'; ?>">
            <div class="aipatch-card-icon dashicons dashicons-editor-code"></div>
            <div class="aipatch-card-content">
                <span class="aipatch-card-value"><?php echo $data['summary']['file_editor_off'] ? esc_html__( 'Disabled', 'aipatch-security-scanner' ) : esc_html__( 'Enabled', 'aipatch-security-scanner' ); ?></span>
                <span class="aipatch-card-label"><?php esc_html_e( 'File Editor', 'aipatch-security-scanner' ); ?></span>
            </div>
        </div>

        <div class="aipatch-card <?php echo $data['summary']['login_protected'] ? '' : 'aipatch-card-warning'; ?>">
            <div class="aipatch-card-icon dashicons dashicons-<?php echo $data['summary']['login_protected'] ? 'shield' : 'shield-alt'; ?>"></div>
            <div class="aipatch-card-content">
                <span class="aipatch-card-value"><?php echo $data['summary']['login_protected'] ? esc_html__( 'Protected', 'aipatch-security-scanner' ) : esc_html__( 'Open', 'aipatch-security-scanner' ); ?></span>
                <span class="aipatch-card-label"><?php esc_html_e( 'Login Protection', 'aipatch-security-scanner' ); ?></span>
            </div>
        </div>

        <div class="aipatch-card <?php echo ! empty( $data['summary']['auto_updates_core'] ) ? '' : 'aipatch-card-warning'; ?>">
            <div class="aipatch-card-icon dashicons dashicons-update"></div>
            <div class="aipatch-card-content">
                <span class="aipatch-card-value"><?php echo ! empty( $data['summary']['auto_updates_core'] ) ? esc_html__( 'On', 'aipatch-security-scanner' ) : esc_html__( 'Off', 'aipatch-security-scanner' ); ?></span>
                <span class="aipatch-card-label"><?php esc_html_e( 'Core Auto-Updates', 'aipatch-security-scanner' ); ?></span>
            </div>
        </div>

        <?php if ( ! empty( $data['summary']['total_checks'] ) ) : ?>
        <div class="aipatch-card">
            <div class="aipatch-card-icon dashicons dashicons-search"></div>
            <div class="aipatch-card-content">
                <span class="aipatch-card-value"><?php echo esc_html( $data['summary']['total_checks'] ); ?></span>
                <span class="aipatch-card-label"><?php esc_html_e( 'Security Checks', 'aipatch-security-scanner' ); ?></span>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <!-- Recommendations -->
    <?php if ( ! empty( $data['recommendations'] ) ) : ?>
    <div class="aipatch-section">
        <h2><?php esc_html_e( 'Recommended Actions', 'aipatch-security-scanner' ); ?></h2>
        <div class="aipatch-recommendations">
            <?php foreach ( $data['recommendations'] as $aipsc_rec ) :
                $aipsc_severity_info = AIPSC_Utils::severity_info( $aipsc_rec['severity'] );
                $aipsc_quick_fix = AIPSC_Utils::get_quick_fix( $aipsc_rec['id'] );
            ?>
                <div class="aipatch-recommendation">
                    <div class="aipatch-rec-header">
                        <span class="aipatch-badge <?php echo esc_attr( $aipsc_severity_info['class'] ); ?>">
                            <?php echo esc_html( $aipsc_severity_info['label'] ); ?>
                        </span>
                        <strong><?php echo esc_html( $aipsc_rec['title'] ); ?></strong>
                    </div>
                    <p><?php echo esc_html( $aipsc_rec['recommendation'] ); ?></p>
                    <div class="aipatch-rec-actions">
                        <?php if ( $aipsc_quick_fix ) : ?>
                            <form method="post" class="aipatch-inline-form">
                                <?php wp_nonce_field( 'aipatch_toggle_hardening', 'aipatch_hardening_nonce' ); ?>
                                <input type="hidden" name="hardening_key" value="<?php echo esc_attr( $aipsc_quick_fix['key'] ); ?>" />
                                <input type="hidden" name="hardening_value" value="1" />
                                <button type="submit" name="aipatch_toggle_hardening" value="1" class="button button-small button-primary">
                                    <span class="dashicons dashicons-yes"></span>
                                    <?php echo esc_html( $aipsc_quick_fix['label'] ); ?>
                                </button>
                            </form>
                        <?php endif; ?>
                        <?php if ( $aipsc_rec['dismissible'] ) : ?>
                            <form method="post" class="aipatch-inline-form">
                                <?php wp_nonce_field( 'aipatch_dismiss_issue', 'aipatch_dismiss_nonce' ); ?>
                                <input type="hidden" name="issue_id" value="<?php echo esc_attr( $aipsc_rec['id'] ); ?>" />
                                <button type="submit" name="aipatch_dismiss_issue" value="1" class="button button-small" data-dismiss-rest data-issue-id="<?php echo esc_attr( $aipsc_rec['id'] ); ?>">
                                    <?php esc_html_e( 'Dismiss', 'aipatch-security-scanner' ); ?>
                                </button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php elseif ( $data['has_scan'] ) : ?>
    <div class="aipatch-section">
        <div class="aipatch-all-clear">
            <span class="dashicons dashicons-yes-alt"></span>
            <p><?php esc_html_e( 'No active recommendations. Your site looks good!', 'aipatch-security-scanner' ); ?></p>
        </div>
    </div>
    <?php endif; ?>

    <!-- Dismissed Issues -->
    <?php if ( ! empty( $data['dismissed_issues'] ) ) : ?>
    <div class="aipatch-section aipatch-section-collapsed">
        <h2>
            <?php
            printf(
                /* translators: %d: Number of dismissed issues. */
                esc_html__( 'Dismissed Issues (%d)', 'aipatch-security-scanner' ),
                count( $data['dismissed_issues'] )
            );
            ?>
        </h2>
        <div class="aipatch-dismissed-list">
            <?php foreach ( $data['dismissed_issues'] as $aipsc_issue ) : ?>
                <div class="aipatch-dismissed-item">
                    <span><?php echo esc_html( $aipsc_issue['title'] ); ?></span>
                    <form method="post" class="aipatch-inline-form">
                        <?php wp_nonce_field( 'aipatch_restore_issue', 'aipatch_restore_nonce' ); ?>
                        <input type="hidden" name="issue_id" value="<?php echo esc_attr( $aipsc_issue['id'] ); ?>" />
                        <button type="submit" name="aipatch_restore_issue" value="1" class="button button-small button-link">
                            <?php esc_html_e( 'Restore', 'aipatch-security-scanner' ); ?>
                        </button>
                    </form>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php endif; ?>
</div>
