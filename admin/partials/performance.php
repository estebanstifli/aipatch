<?php
/**
 * Admin partial: Performance Diagnostics page.
 *
 * @package AipatchSecurityScanner
 * @var array|false $perf_data Performance results from AIPSC_Performance::get_last_results().
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
?>
<div class="wrap aipatch-wrap">
    <h1 class="aipatch-page-title">
        <span class="dashicons dashicons-performance"></span>
        <?php esc_html_e( 'Performance Diagnostics', 'aipatch-security-scanner' ); ?>
    </h1>

    <p class="aipatch-page-desc">
        <?php esc_html_e( 'Aipatch detects common reasons a WordPress site may be slow. This is a diagnostic tool — results are orientative, not exact measurements.', 'aipatch-security-scanner' ); ?>
    </p>

    <?php if ( isset( $_GET['scan'] ) && 'complete' === $_GET['scan'] ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only display of redirect query param. ?>
        <div class="notice notice-success is-dismissible">
            <p><?php esc_html_e( 'Performance diagnostics completed.', 'aipatch-security-scanner' ); ?></p>
        </div>
    <?php endif; ?>

    <!-- Health + Actions Bar -->
    <div class="aipatch-top-bar">
        <?php if ( $perf_data ) : ?>
            <div class="aipatch-health-badge <?php echo esc_attr( $perf_data['health_class'] ); ?>">
                <?php
                $aipsc_health_icon = 'good' === $perf_data['health'] ? 'yes-alt' : ( 'poor' === $perf_data['health'] ? 'dismiss' : 'warning' );
                ?>
                <span class="dashicons dashicons-<?php echo esc_attr( $aipsc_health_icon ); ?>"></span>
                <div class="aipatch-health-meta">
                    <span class="aipatch-health-label"><?php echo esc_html( $perf_data['health_label'] ); ?></span>
                    <span class="aipatch-health-date">
                        <?php
                        printf(
                            /* translators: %s: Last diagnostics time. */
                            esc_html__( 'Last run: %s', 'aipatch-security-scanner' ),
                            esc_html( AIPSC_Utils::format_time( $perf_data['timestamp'] ) )
                        );
                        ?>
                    </span>
                </div>
            </div>
        <?php else : ?>
            <div class="aipatch-health-badge aipatch-health-none">
                <span class="dashicons dashicons-info-outline"></span>
                <div class="aipatch-health-meta">
                    <span class="aipatch-health-label"><?php esc_html_e( 'No data yet', 'aipatch-security-scanner' ); ?></span>
                    <span class="aipatch-health-date"><?php esc_html_e( 'Run your first performance diagnostic.', 'aipatch-security-scanner' ); ?></span>
                </div>
            </div>
        <?php endif; ?>

        <div class="aipatch-top-actions">
            <form method="post" class="aipatch-inline-form">
                <?php wp_nonce_field( 'aipatch_run_performance', 'aipatch_perf_nonce' ); ?>
                <input type="hidden" name="aipatch_run_performance" value="1" />
                <button type="submit" class="button button-primary button-hero" id="aipatch-run-perf">
                    <span class="dashicons dashicons-performance"></span>
                    <?php esc_html_e( 'Run Diagnostics', 'aipatch-security-scanner' ); ?>
                </button>
            </form>
        </div>
    </div>

    <?php if ( $perf_data ) : ?>

    <!-- All Findings -->
    <div class="aipatch-section">
        <h2><?php esc_html_e( 'Diagnostic Results', 'aipatch-security-scanner' ); ?></h2>
        <div class="aipatch-perf-grid">
            <?php foreach ( $perf_data['findings'] as $aipsc_finding ) :
                $aipsc_status_icon  = 'good' === $aipsc_finding['status'] ? 'yes-alt' : ( 'poor' === $aipsc_finding['status'] ? 'dismiss' : 'warning' );
                $aipsc_status_class = 'aipatch-perf-status-' . $aipsc_finding['status'];
            ?>
                <div class="aipatch-perf-card <?php echo esc_attr( $aipsc_status_class ); ?>">
                    <div class="aipatch-perf-card-header">
                        <span class="dashicons dashicons-<?php echo esc_attr( $aipsc_status_icon ); ?> aipatch-perf-icon"></span>
                        <div class="aipatch-perf-card-title">
                            <strong><?php echo esc_html( $aipsc_finding['title'] ); ?></strong>
                            <span class="aipatch-perf-value"><?php echo esc_html( $aipsc_finding['value'] ); ?></span>
                        </div>
                    </div>
                    <p class="aipatch-perf-desc"><?php echo esc_html( $aipsc_finding['description'] ); ?></p>
                    <?php if ( ! empty( $aipsc_finding['recommendation'] ) ) : ?>
                        <p class="aipatch-perf-rec">
                            <span class="dashicons dashicons-lightbulb"></span>
                            <?php echo esc_html( $aipsc_finding['recommendation'] ); ?>
                        </p>
                    <?php endif; ?>

                    <?php // Autoloaded options detail table. ?>
                    <?php if ( 'autoloaded_options' === $aipsc_finding['id'] && ! empty( $aipsc_finding['details'] ) ) : ?>
                        <table class="aipatch-perf-detail-table">
                            <thead>
                                <tr>
                                    <th><?php esc_html_e( 'Option Name', 'aipatch-security-scanner' ); ?></th>
                                    <th><?php esc_html_e( 'Size', 'aipatch-security-scanner' ); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ( $aipsc_finding['details'] as $aipsc_opt ) : ?>
                                    <tr>
                                        <td><code><?php echo esc_html( $aipsc_opt['name'] ); ?></code></td>
                                        <td><?php echo esc_html( $aipsc_opt['size'] ); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>

                    <?php // Large tables detail. ?>
                    <?php if ( 'database_size' === $aipsc_finding['id'] && ! empty( $aipsc_finding['details'] ) ) : ?>
                        <table class="aipatch-perf-detail-table">
                            <thead>
                                <tr>
                                    <th><?php esc_html_e( 'Table', 'aipatch-security-scanner' ); ?></th>
                                    <th><?php esc_html_e( 'Size', 'aipatch-security-scanner' ); ?></th>
                                    <th><?php esc_html_e( 'Rows', 'aipatch-security-scanner' ); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ( $aipsc_finding['details'] as $aipsc_tbl ) : ?>
                                    <tr>
                                        <td><code><?php echo esc_html( $aipsc_tbl['name'] ); ?></code></td>
                                        <td><?php echo esc_html( $aipsc_tbl['size'] ); ?></td>
                                        <td><?php echo esc_html( $aipsc_tbl['rows'] ); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>
    </div>

    <!-- Quick Wins -->
    <?php if ( ! empty( $perf_data['quick_wins'] ) ) : ?>
    <div class="aipatch-section">
        <h2>
            <span class="dashicons dashicons-superhero"></span>
            <?php esc_html_e( 'Quick Wins', 'aipatch-security-scanner' ); ?>
        </h2>
        <p class="aipatch-page-desc"><?php esc_html_e( 'These can usually be resolved quickly and offer the most immediate improvement.', 'aipatch-security-scanner' ); ?></p>
        <div class="aipatch-recommendations">
            <?php foreach ( $perf_data['quick_wins'] as $aipsc_qw ) :
                $aipsc_qw_class = 'poor' === $aipsc_qw['status'] ? 'aipatch-severity-high' : 'aipatch-severity-medium';
            ?>
                <div class="aipatch-recommendation">
                    <div class="aipatch-rec-header">
                        <span class="aipatch-badge <?php echo esc_attr( $aipsc_qw_class ); ?>">
                            <?php echo esc_html( ucfirst( $aipsc_qw['status'] ) ); ?>
                        </span>
                        <strong><?php echo esc_html( $aipsc_qw['title'] ); ?></strong>
                        <span class="aipatch-rec-value"><?php echo esc_html( $aipsc_qw['value'] ); ?></span>
                    </div>
                    <?php if ( ! empty( $aipsc_qw['recommendation'] ) ) : ?>
                        <p><?php echo esc_html( $aipsc_qw['recommendation'] ); ?></p>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php endif; ?>

    <!-- Possible Bottlenecks -->
    <?php if ( ! empty( $perf_data['bottlenecks'] ) ) : ?>
    <div class="aipatch-section">
        <h2>
            <span class="dashicons dashicons-visibility"></span>
            <?php esc_html_e( 'Possible Bottlenecks', 'aipatch-security-scanner' ); ?>
        </h2>
        <p class="aipatch-page-desc"><?php esc_html_e( 'These findings require further investigation. They may or may not be causing issues on your site.', 'aipatch-security-scanner' ); ?></p>
        <div class="aipatch-recommendations">
            <?php foreach ( $perf_data['bottlenecks'] as $aipsc_bn ) :
                $aipsc_bn_class = 'poor' === $aipsc_bn['status'] ? 'aipatch-severity-high' : 'aipatch-severity-medium';
            ?>
                <div class="aipatch-recommendation">
                    <div class="aipatch-rec-header">
                        <span class="aipatch-badge <?php echo esc_attr( $aipsc_bn_class ); ?>">
                            <?php echo esc_html( ucfirst( $aipsc_bn['status'] ) ); ?>
                        </span>
                        <strong><?php echo esc_html( $aipsc_bn['title'] ); ?></strong>
                        <span class="aipatch-rec-value"><?php echo esc_html( $aipsc_bn['value'] ); ?></span>
                    </div>
                    <?php if ( ! empty( $aipsc_bn['recommendation'] ) ) : ?>
                        <p><?php echo esc_html( $aipsc_bn['recommendation'] ); ?></p>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php endif; ?>

    <?php if ( empty( $perf_data['quick_wins'] ) && empty( $perf_data['bottlenecks'] ) ) : ?>
    <div class="aipatch-section">
        <div class="aipatch-all-clear">
            <span class="dashicons dashicons-yes-alt"></span>
            <p><?php esc_html_e( 'No performance issues detected. Your site looks healthy!', 'aipatch-security-scanner' ); ?></p>
        </div>
    </div>
    <?php endif; ?>

    <?php endif; // end if perf_data. ?>

    <!-- Advanced Diagnostic Tools -->
    <div class="aipatch-section aipatch-muted-box">
        <h3>
            <span class="dashicons dashicons-admin-tools"></span>
            <?php esc_html_e( 'Advanced Diagnostic Tools', 'aipatch-security-scanner' ); ?>
        </h3>
        <p><?php esc_html_e( 'For deeper performance analysis, consider these specialized tools:', 'aipatch-security-scanner' ); ?></p>
        <?php if ( $perf_data && ! empty( $perf_data['tools'] ) ) : ?>
            <div class="aipatch-tools-list">
                <?php foreach ( $perf_data['tools'] as $aipsc_tool ) : ?>
                    <div class="aipatch-tool-item">
                        <strong><?php echo esc_html( $aipsc_tool['name'] ); ?></strong>
                        <?php if ( 'plugin' === $aipsc_tool['type'] ) : ?>
                            <span class="aipatch-badge aipatch-severity-info"><?php esc_html_e( 'Plugin', 'aipatch-security-scanner' ); ?></span>
                        <?php else : ?>
                            <span class="aipatch-badge aipatch-severity-info"><?php esc_html_e( 'External', 'aipatch-security-scanner' ); ?></span>
                        <?php endif; ?>
                        <p><?php echo esc_html( $aipsc_tool['description'] ); ?></p>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php else : ?>
            <ul>
                <li><strong>Query Monitor</strong> — <?php esc_html_e( 'Detailed breakdown of database queries, hooks, and HTTP requests per page.', 'aipatch-security-scanner' ); ?></li>
                <li><strong>PageSpeed Insights</strong> — <?php esc_html_e( 'Google\'s tool for measuring real-world Core Web Vitals.', 'aipatch-security-scanner' ); ?></li>
                <li><strong>GTmetrix</strong> — <?php esc_html_e( 'Comprehensive page speed analysis with waterfall charts.', 'aipatch-security-scanner' ); ?></li>
                <li><strong>WebPageTest</strong> — <?php esc_html_e( 'Advanced performance testing from multiple locations.', 'aipatch-security-scanner' ); ?></li>
            </ul>
        <?php endif; ?>
    </div>
</div>
