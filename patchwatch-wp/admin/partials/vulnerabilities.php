<?php
/**
 * Admin partial: Vulnerabilities page.
 *
 * @package PatchWatch
 * @var array $vulns       Vulnerability records.
 * @var bool  $has_external Whether an external provider is connected.
 * @var array $providers   Provider status list.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
?>
<div class="wrap aipatch-wrap">
    <h1 class="aipatch-page-title">
        <span class="dashicons dashicons-warning"></span>
        <?php esc_html_e( 'Vulnerability Intelligence', 'patchwatch-wp' ); ?>
    </h1>

    <?php if ( ! $has_external ) : ?>
        <div class="notice notice-info">
            <p>
                <strong><?php esc_html_e( 'No external vulnerability feed connected.', 'patchwatch-wp' ); ?></strong>
                <?php esc_html_e( 'Displaying local mock data for demonstration. Connect an external provider for real-time vulnerability intelligence.', 'patchwatch-wp' ); ?>
            </p>
        </div>
    <?php endif; ?>

    <!-- Provider Status -->
    <div class="aipatch-provider-status">
        <h3><?php esc_html_e( 'Data Sources', 'patchwatch-wp' ); ?></h3>
        <ul>
            <?php foreach ( $providers as $provider ) : ?>
                <li>
                    <span class="dashicons dashicons-<?php echo $provider['available'] ? 'yes-alt aipatch-text-success' : 'marker aipatch-text-muted'; ?>"></span>
                    <?php echo esc_html( $provider['name'] ); ?>
                    –
                    <?php echo $provider['available']
                        ? esc_html__( 'Active', 'patchwatch-wp' )
                        : esc_html__( 'Not configured', 'patchwatch-wp' ); ?>
                </li>
            <?php endforeach; ?>
        </ul>
    </div>

    <!-- Vulnerability Table -->
    <?php if ( ! empty( $vulns ) ) : ?>
    <div class="aipatch-section">
        <table class="widefat aipatch-table" id="aipatch-vuln-table">
            <thead>
                <tr>
                    <th><?php esc_html_e( 'Severity', 'patchwatch-wp' ); ?></th>
                    <th><?php esc_html_e( 'Software', 'patchwatch-wp' ); ?></th>
                    <th><?php esc_html_e( 'Type', 'patchwatch-wp' ); ?></th>
                    <th><?php esc_html_e( 'Vulnerability', 'patchwatch-wp' ); ?></th>
                    <th><?php esc_html_e( 'Installed', 'patchwatch-wp' ); ?></th>
                    <th><?php esc_html_e( 'Fix Version', 'patchwatch-wp' ); ?></th>
                    <th><?php esc_html_e( 'Source', 'patchwatch-wp' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ( $vulns as $vuln ) :
                    $sev = PWW_Utils::severity_info( $vuln['severity'] );
                ?>
                    <tr>
                        <td>
                            <span class="aipatch-badge <?php echo esc_attr( $sev['class'] ); ?>">
                                <?php echo esc_html( $sev['label'] ); ?>
                            </span>
                        </td>
                        <td><strong><?php echo esc_html( $vuln['slug'] ); ?></strong></td>
                        <td><?php echo esc_html( $vuln['software_type'] ); ?></td>
                        <td>
                            <strong><?php echo esc_html( $vuln['title'] ); ?></strong>
                            <p class="description"><?php echo esc_html( $vuln['description'] ); ?></p>
                        </td>
                        <td><code><?php echo esc_html( $vuln['installed_version'] ); ?></code></td>
                        <td>
                            <?php if ( ! empty( $vuln['fix_version'] ) ) : ?>
                                <span class="aipatch-fix-available">
                                    <span class="dashicons dashicons-yes"></span>
                                    <?php echo esc_html( $vuln['fix_version'] ); ?>
                                </span>
                            <?php else : ?>
                                <span class="aipatch-text-muted"><?php esc_html_e( 'Unknown', 'patchwatch-wp' ); ?></span>
                            <?php endif; ?>
                        </td>
                        <td><span class="aipatch-source-badge"><?php echo esc_html( $vuln['source'] ); ?></span></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php else : ?>
    <div class="aipatch-section">
        <div class="aipatch-all-clear">
            <span class="dashicons dashicons-yes-alt"></span>
            <p><?php esc_html_e( 'No known vulnerabilities detected for your installed software.', 'patchwatch-wp' ); ?></p>
        </div>
    </div>
    <?php endif; ?>

    <div class="aipatch-section aipatch-muted-box">
        <h3><?php esc_html_e( 'About Vulnerability Data', 'patchwatch-wp' ); ?></h3>
        <p>
            <?php esc_html_e( 'Vulnerability data is compared against your installed plugins, themes, and WordPress core version. In the current MVP, data is sourced from a local demonstration database. Future versions will support external vulnerability feeds for real-time intelligence.', 'patchwatch-wp' ); ?>
        </p>
    </div>
</div>
