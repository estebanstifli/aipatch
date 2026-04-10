<?php
/**
 * Admin partial: Settings page.
 *
 * @package AipatchSecurityScanner
 * @var array $settings Current settings from PWW_Utils::get_settings().
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
?>
<div class="wrap aipatch-wrap">
    <h1 class="aipatch-page-title">
        <span class="dashicons dashicons-admin-generic"></span>
        <?php esc_html_e( 'Settings', 'aipatch-security-scanner' ); ?>
    </h1>

    <form method="post" action="options.php">
        <?php settings_fields( 'aipatch_settings_group' ); ?>

        <table class="form-table aipatch-settings-table" role="presentation">
            <!-- Scan Frequency -->
            <tr>
                <th scope="row">
                    <label for="aipatch_scan_frequency"><?php esc_html_e( 'Scan Frequency', 'aipatch-security-scanner' ); ?></label>
                </th>
                <td>
                    <select name="aipatch_settings[scan_frequency]" id="aipatch_scan_frequency">
                        <option value="twicedaily" <?php selected( $settings['scan_frequency'], 'twicedaily' ); ?>>
                            <?php esc_html_e( 'Twice Daily', 'aipatch-security-scanner' ); ?>
                        </option>
                        <option value="daily" <?php selected( $settings['scan_frequency'], 'daily' ); ?>>
                            <?php esc_html_e( 'Daily', 'aipatch-security-scanner' ); ?>
                        </option>
                        <option value="weekly" <?php selected( $settings['scan_frequency'], 'weekly' ); ?>>
                            <?php esc_html_e( 'Weekly', 'aipatch-security-scanner' ); ?>
                        </option>
                    </select>
                    <p class="description">
                        <?php esc_html_e( 'How often the automatic security scan should run.', 'aipatch-security-scanner' ); ?>
                    </p>
                </td>
            </tr>

            <!-- Log Retention -->
            <tr>
                <th scope="row">
                    <label for="aipatch_log_retention"><?php esc_html_e( 'Log Retention', 'aipatch-security-scanner' ); ?></label>
                </th>
                <td>
                    <select name="aipatch_settings[log_retention_days]" id="aipatch_log_retention">
                        <option value="7" <?php selected( $settings['log_retention_days'], 7 ); ?>>
                            <?php esc_html_e( '7 days', 'aipatch-security-scanner' ); ?>
                        </option>
                        <option value="14" <?php selected( $settings['log_retention_days'], 14 ); ?>>
                            <?php esc_html_e( '14 days', 'aipatch-security-scanner' ); ?>
                        </option>
                        <option value="30" <?php selected( $settings['log_retention_days'], 30 ); ?>>
                            <?php esc_html_e( '30 days', 'aipatch-security-scanner' ); ?>
                        </option>
                        <option value="60" <?php selected( $settings['log_retention_days'], 60 ); ?>>
                            <?php esc_html_e( '60 days', 'aipatch-security-scanner' ); ?>
                        </option>
                        <option value="90" <?php selected( $settings['log_retention_days'], 90 ); ?>>
                            <?php esc_html_e( '90 days', 'aipatch-security-scanner' ); ?>
                        </option>
                    </select>
                    <p class="description">
                        <?php esc_html_e( 'How long to keep log entries before automatic cleanup.', 'aipatch-security-scanner' ); ?>
                    </p>
                </td>
            </tr>

            <!-- REST Compatibility Mode -->
            <tr>
                <th scope="row">
                    <?php esc_html_e( 'REST API Compatibility Mode', 'aipatch-security-scanner' ); ?>
                </th>
                <td>
                    <label>
                        <input type="checkbox" name="aipatch_settings[rest_compat_mode]" value="1" <?php checked( $settings['rest_compat_mode'] ); ?> />
                        <?php esc_html_e( 'Enable compatibility mode', 'aipatch-security-scanner' ); ?>
                    </label>
                    <p class="description">
                        <?php esc_html_e( 'When enabled, REST API restrictions are relaxed to ensure maximum compatibility with third-party plugins and headless setups. This bypasses the REST API hardening filter.', 'aipatch-security-scanner' ); ?>
                    </p>
                </td>
            </tr>

            <!-- Modules -->
            <tr>
                <th scope="row">
                    <?php esc_html_e( 'Active Modules', 'aipatch-security-scanner' ); ?>
                </th>
                <td>
                    <fieldset>
                        <label>
                            <input type="checkbox" name="aipatch_settings[modules_enabled][scanner]" value="1" <?php checked( ! empty( $settings['modules_enabled']['scanner'] ) ); ?> />
                            <?php esc_html_e( 'Security Scanner', 'aipatch-security-scanner' ); ?>
                        </label><br>

                        <label>
                            <input type="checkbox" name="aipatch_settings[modules_enabled][hardening]" value="1" <?php checked( ! empty( $settings['modules_enabled']['hardening'] ) ); ?> />
                            <?php esc_html_e( 'Hardening Module', 'aipatch-security-scanner' ); ?>
                        </label><br>

                        <label>
                            <input type="checkbox" name="aipatch_settings[modules_enabled][vulnerabilities]" value="1" <?php checked( ! empty( $settings['modules_enabled']['vulnerabilities'] ) ); ?> />
                            <?php esc_html_e( 'Known Vulnerabilities', 'aipatch-security-scanner' ); ?>
                        </label><br>

                        <label>
                            <input type="checkbox" name="aipatch_settings[modules_enabled][login_protection]" value="1" <?php checked( ! empty( $settings['modules_enabled']['login_protection'] ) ); ?> />
                            <?php esc_html_e( 'Login Protection', 'aipatch-security-scanner' ); ?>
                        </label>
                    </fieldset>
                    <p class="description">
                        <?php esc_html_e( 'Enable or disable individual plugin modules.', 'aipatch-security-scanner' ); ?>
                    </p>
                </td>
            </tr>
        </table>

        <?php submit_button( __( 'Save Settings', 'aipatch-security-scanner' ) ); ?>
    </form>

    <div class="aipatch-section aipatch-muted-box">
        <h3><?php esc_html_e( 'Plugin Information', 'aipatch-security-scanner' ); ?></h3>
        <table class="aipatch-info-table">
            <tr>
                <td><strong><?php esc_html_e( 'Version', 'aipatch-security-scanner' ); ?></strong></td>
                <td><?php echo esc_html( AIPATCH_VERSION ); ?></td>
            </tr>
            <tr>
                <td><strong><?php esc_html_e( 'Database Version', 'aipatch-security-scanner' ); ?></strong></td>
                <td><?php echo esc_html( get_option( 'aipatch_db_version', 'N/A' ) ); ?></td>
            </tr>
            <tr>
                <td><strong><?php esc_html_e( 'PHP Version', 'aipatch-security-scanner' ); ?></strong></td>
                <td><?php echo esc_html( PHP_VERSION ); ?></td>
            </tr>
            <tr>
                <td><strong><?php esc_html_e( 'WordPress Version', 'aipatch-security-scanner' ); ?></strong></td>
                <td><?php echo esc_html( get_bloginfo( 'version' ) ); ?></td>
            </tr>
        </table>
    </div>
</div>
