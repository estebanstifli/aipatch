<?php
/**
 * AI PatchWatch – Security Intelligence
 *
 * @package     PatchWatch
 * @author      PatchWatch
 * @copyright   2026 PatchWatch
 * @license     GPL-2.0-or-later
 *
 * @wordpress-plugin
 * Plugin Name: AI PatchWatch – Security Intelligence
 * Plugin URI:  https://github.com/estebanstifli/aipatch
 * Description: Lightweight security intelligence for your site. Detect vulnerabilities, assess risks, and apply safe hardening measures.
 * Version:     1.0.0
 * Requires at least: 6.5
 * Requires PHP: 7.4
 * Author:      AI PatchWatch
 * Author URI:  https://github.com/estebanstifli/aipatch
 * Text Domain: patchwatch
 * Domain Path: /languages
 * License:     GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Plugin constants.
 */
define( 'AIPATCH_VERSION', '1.0.0' );
define( 'AIPATCH_PLUGIN_FILE', __FILE__ );
define( 'AIPATCH_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'AIPATCH_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'AIPATCH_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
define( 'AIPATCH_DB_VERSION', '1.0' );
define( 'AIPATCH_MIN_PHP', '7.4' );
define( 'AIPATCH_MIN_WP', '6.5' );
define( 'AIPATCH_REST_NAMESPACE', 'patchwatch/v1' );

/**
 * Plugin activation.
 */
function aipatch_activate() {
    require_once AIPATCH_PLUGIN_DIR . 'includes/class-pww-utils.php';
    require_once AIPATCH_PLUGIN_DIR . 'includes/class-pww-installer.php';
    PWW_Installer::activate();
}
register_activation_hook( __FILE__, 'aipatch_activate' );

/**
 * Plugin deactivation.
 */
function aipatch_deactivate() {
    require_once AIPATCH_PLUGIN_DIR . 'includes/class-pww-installer.php';
    PWW_Installer::deactivate();
}
register_deactivation_hook( __FILE__, 'aipatch_deactivate' );

/**
 * Bootstrap the plugin after all plugins are loaded.
 */
function aipatch_init() {
    // PHP version check.
    if ( version_compare( PHP_VERSION, AIPATCH_MIN_PHP, '<' ) ) {
        add_action( 'admin_notices', 'aipatch_php_notice' );
        return;
    }

    // WordPress version check.
    global $wp_version;
    if ( version_compare( $wp_version, AIPATCH_MIN_WP, '<' ) ) {
        add_action( 'admin_notices', 'aipatch_wp_notice' );
        return;
    }

    require_once AIPATCH_PLUGIN_DIR . 'includes/class-pww-loader.php';
    $plugin = new PWW_Loader();
    $plugin->run();
}
add_action( 'plugins_loaded', 'aipatch_init' );

/**
 * Admin notice: PHP version too low.
 */
function aipatch_php_notice() {
    printf(
        '<div class="notice notice-error"><p>%s</p></div>',
        esc_html(
            sprintf(
                /* translators: 1: Required PHP version, 2: Current PHP version. */
                __( 'AI PatchWatch requires PHP %1$s or higher. You are running PHP %2$s.', 'patchwatch' ),
                AIPATCH_MIN_PHP,
                PHP_VERSION
            )
        )
    );
}

/**
 * Admin notice: WordPress version too low.
 */
function aipatch_wp_notice() {
    global $wp_version;
    printf(
        '<div class="notice notice-error"><p>%s</p></div>',
        esc_html(
            sprintf(
                /* translators: 1: Required WP version, 2: Current WP version. */
                __( 'AI PatchWatch requires WordPress %1$s or higher. You are running %2$s.', 'patchwatch' ),
                AIPATCH_MIN_WP,
                $wp_version
            )
        )
    );
}
