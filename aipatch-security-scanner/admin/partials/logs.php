<?php
/**
 * Admin partial: Logs page.
 *
 * @package AipatchSecurityScanner
 * @var array  $logs        Log entries.
 * @var int    $total       Total log count.
 * @var int    $total_pages Total pages.
 * @var int    $page        Current page.
 * @var string $severity    Active severity filter.
 * @var int    $per_page    Items per page.
 * @var array  $counts      Counts by severity.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

$aipsc_base_url = admin_url( 'admin.php?page=aipatch-security-scanner-logs' );
?>
<div class="wrap aipatch-wrap">
    <h1 class="aipatch-page-title">
        <span class="dashicons dashicons-list-view"></span>
        <?php esc_html_e( 'Security Logs', 'aipatch-security-scanner' ); ?>
    </h1>

    <?php if ( isset( $_GET['cleared'] ) && '1' === $_GET['cleared'] ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only display of redirect query param. ?>
        <div class="notice notice-success is-dismissible">
            <p><?php esc_html_e( 'All logs have been cleared.', 'aipatch-security-scanner' ); ?></p>
        </div>
    <?php endif; ?>

    <!-- Filter + Actions Bar -->
    <div class="aipatch-logs-toolbar">
        <div class="aipatch-severity-filters">
            <a href="<?php echo esc_url( $aipsc_base_url ); ?>" class="<?php echo empty( $severity ) ? 'current' : ''; ?>">
                <?php
                printf(
                    /* translators: %d: Count. */
                    esc_html__( 'All (%d)', 'aipatch-security-scanner' ),
                    absint( $counts['total'] )
                );
                ?>
            </a>
            |
            <a href="<?php echo esc_url( add_query_arg( 'severity', 'critical', $aipsc_base_url ) ); ?>" class="<?php echo 'critical' === $severity ? 'current' : ''; ?>">
                <?php
                printf(
                    /* translators: %d: Count. */
                    esc_html__( 'Critical (%d)', 'aipatch-security-scanner' ),
                    absint( $counts['critical'] )
                );
                ?>
            </a>
            |
            <a href="<?php echo esc_url( add_query_arg( 'severity', 'error', $aipsc_base_url ) ); ?>" class="<?php echo 'error' === $severity ? 'current' : ''; ?>">
                <?php
                printf(
                    /* translators: %d: Count. */
                    esc_html__( 'Error (%d)', 'aipatch-security-scanner' ),
                    absint( $counts['error'] )
                );
                ?>
            </a>
            |
            <a href="<?php echo esc_url( add_query_arg( 'severity', 'warning', $aipsc_base_url ) ); ?>" class="<?php echo 'warning' === $severity ? 'current' : ''; ?>">
                <?php
                printf(
                    /* translators: %d: Count. */
                    esc_html__( 'Warning (%d)', 'aipatch-security-scanner' ),
                    absint( $counts['warning'] )
                );
                ?>
            </a>
            |
            <a href="<?php echo esc_url( add_query_arg( 'severity', 'info', $aipsc_base_url ) ); ?>" class="<?php echo 'info' === $severity ? 'current' : ''; ?>">
                <?php
                printf(
                    /* translators: %d: Count. */
                    esc_html__( 'Info (%d)', 'aipatch-security-scanner' ),
                    absint( $counts['info'] )
                );
                ?>
            </a>
        </div>

        <form method="post" class="aipatch-inline-form">
            <?php wp_nonce_field( 'aipatch_clear_logs', 'aipatch_clear_nonce' ); ?>
            <button type="submit" name="aipatch_clear_logs" value="1" class="button" onclick="return confirm(aipatchAdmin.i18n.confirmClear);">
                <span class="dashicons dashicons-trash"></span>
                <?php esc_html_e( 'Clear All Logs', 'aipatch-security-scanner' ); ?>
            </button>
        </form>
        <button type="button" class="button button-small" id="aipatch-export-logs">
            <span class="dashicons dashicons-download"></span>
            <?php esc_html_e( 'Export CSV', 'aipatch-security-scanner' ); ?>
        </button>
    </div>

    <!-- Logs Table -->
    <?php if ( ! empty( $logs ) ) : ?>
    <table class="widefat aipatch-table aipatch-logs-table">
        <thead>
            <tr>
                <th class="aipatch-col-severity"><?php esc_html_e( 'Severity', 'aipatch-security-scanner' ); ?></th>
                <th class="aipatch-col-event"><?php esc_html_e( 'Event', 'aipatch-security-scanner' ); ?></th>
                <th><?php esc_html_e( 'Message', 'aipatch-security-scanner' ); ?></th>
                <th class="aipatch-col-date"><?php esc_html_e( 'Date', 'aipatch-security-scanner' ); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ( $logs as $aipsc_log ) : ?>
                <tr class="aipatch-log-<?php echo esc_attr( $aipsc_log->severity ); ?>">
                    <td>
                        <span class="aipatch-log-severity aipatch-log-severity-<?php echo esc_attr( $aipsc_log->severity ); ?>">
                            <?php echo esc_html( ucfirst( $aipsc_log->severity ) ); ?>
                        </span>
                    </td>
                    <td><code><?php echo esc_html( $aipsc_log->event_type ); ?></code></td>
                    <td><?php echo esc_html( $aipsc_log->message ); ?></td>
                    <td><?php echo esc_html( AIPSC_Utils::format_time( strtotime( $aipsc_log->created_at ) ) ); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>

    <!-- Pagination -->
    <?php if ( $total_pages > 1 ) : ?>
    <div class="aipatch-pagination">
        <?php
        $aipsc_pagination_args = array(
            'base'    => add_query_arg( 'paged', '%#%', $aipsc_base_url ),
            'format'  => '',
            'current' => $page,
            'total'   => $total_pages,
            'type'    => 'plain',
        );
        if ( ! empty( $severity ) ) {
            $aipsc_pagination_args['base'] = add_query_arg(
                array( 'severity' => $severity, 'paged' => '%#%' ),
                $aipsc_base_url
            );
        }
        echo wp_kses_post( paginate_links( $aipsc_pagination_args ) );
        ?>
    </div>
    <?php endif; ?>

    <?php else : ?>
    <div class="aipatch-section">
        <div class="aipatch-all-clear">
            <span class="dashicons dashicons-yes-alt"></span>
            <p><?php esc_html_e( 'No log entries found.', 'aipatch-security-scanner' ); ?></p>
        </div>
    </div>
    <?php endif; ?>
</div>
