<?php
/**
 * Admin partial: Hardening page.
 *
 * @package AipatchSecurityScanner
 * @var array $rules Hardening rules from PWW_Hardening::get_status().
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
?>
<div class="wrap aipatch-wrap">
    <h1 class="aipatch-page-title">
        <span class="dashicons dashicons-lock"></span>
        <?php esc_html_e( 'Security Hardening', 'aipatch-security-scanner' ); ?>
    </h1>

    <?php if ( isset( $_GET['updated'] ) && '1' === $_GET['updated'] ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only display of redirect query param. ?>
        <div class="notice notice-success is-dismissible">
            <p><?php esc_html_e( 'Hardening setting updated successfully.', 'aipatch-security-scanner' ); ?></p>
        </div>
    <?php endif; ?>

    <p class="aipatch-page-desc">
        <?php esc_html_e( 'Enable or disable security hardening measures. Each option includes an explanation and a compatibility warning. Changes take effect immediately.', 'aipatch-security-scanner' ); ?>
    </p>

    <div class="aipatch-hardening-list">
        <?php foreach ( $rules as $rule ) :
            $sev = PWW_Utils::severity_info( $rule['severity'] );
        ?>
        <div class="aipatch-hardening-item <?php echo $rule['enabled'] ? 'aipatch-hardening-active' : ''; ?>">
            <div class="aipatch-hardening-header">
                <div class="aipatch-hardening-info">
                    <h3>
                        <?php echo esc_html( $rule['title'] ); ?>
                        <span class="aipatch-badge <?php echo esc_attr( $sev['class'] ); ?>"><?php echo esc_html( $sev['label'] ); ?></span>
                    </h3>
                    <p><?php echo esc_html( $rule['description'] ); ?></p>
                    <?php if ( ! empty( $rule['warning'] ) ) : ?>
                        <p class="aipatch-hardening-warning">
                            <span class="dashicons dashicons-info"></span>
                            <?php echo esc_html( $rule['warning'] ); ?>
                        </p>
                    <?php endif; ?>
                </div>
                <div class="aipatch-hardening-toggle">
                    <form method="post">
                        <?php wp_nonce_field( 'aipatch_toggle_hardening', 'aipatch_hardening_nonce' ); ?>
                        <input type="hidden" name="hardening_key" value="<?php echo esc_attr( $rule['key'] ); ?>" />
                        <?php if ( $rule['enabled'] ) : ?>
                            <input type="hidden" name="hardening_value" value="" />
                            <button type="submit" name="aipatch_toggle_hardening" value="1" class="aipatch-toggle-btn aipatch-toggle-on" title="<?php esc_attr_e( 'Click to disable', 'aipatch-security-scanner' ); ?>">
                                <span class="aipatch-toggle-slider"></span>
                            </button>
                        <?php else : ?>
                            <input type="hidden" name="hardening_value" value="1" />
                            <button type="submit" name="aipatch_toggle_hardening" value="1" class="aipatch-toggle-btn aipatch-toggle-off" title="<?php esc_attr_e( 'Click to enable', 'aipatch-security-scanner' ); ?>">
                                <span class="aipatch-toggle-slider"></span>
                            </button>
                        <?php endif; ?>
                    </form>
                </div>
            </div>

            <?php if ( ! empty( $rule['settings'] ) ) : ?>
            <div class="aipatch-hardening-settings">
                <p class="aipatch-meta-label"><?php esc_html_e( 'Current settings:', 'aipatch-security-scanner' ); ?></p>
                <ul>
                    <?php if ( isset( $rule['settings']['login_max_attempts'] ) ) : ?>
                        <li>
                            <?php
                            printf(
                                /* translators: %d: Max attempts. */
                                esc_html__( 'Max attempts: %d', 'aipatch-security-scanner' ),
                                (int) $rule['settings']['login_max_attempts']
                            );
                            ?>
                        </li>
                    <?php endif; ?>
                    <?php if ( isset( $rule['settings']['login_lockout_duration'] ) ) : ?>
                        <li>
                            <?php
                            printf(
                                /* translators: %d: Minutes. */
                                esc_html__( 'Lockout duration: %d minutes', 'aipatch-security-scanner' ),
                                (int) $rule['settings']['login_lockout_duration']
                            );
                            ?>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
            <?php endif; ?>
        </div>
        <?php endforeach; ?>
    </div>

    <div class="aipatch-section aipatch-muted-box">
        <h3><?php esc_html_e( 'About Hardening', 'aipatch-security-scanner' ); ?></h3>
        <p>
            <?php esc_html_e( 'Security hardening applies protective measures to reduce your site\'s attack surface. These measures are safe for most WordPress sites, but review the compatibility warnings before enabling. Some features like XML-RPC or public REST API access may be required by specific plugins or services.', 'aipatch-security-scanner' ); ?>
        </p>
        <p>
            <strong><?php esc_html_e( 'File Editor:', 'aipatch-security-scanner' ); ?></strong>
            <?php esc_html_e( 'To disable the WordPress file editor, add this line to your wp-config.php file:', 'aipatch-security-scanner' ); ?>
            <code>define( 'DISALLOW_FILE_EDIT', true );</code>
        </p>
    </div>
</div>
