<?php
/**
 * Internationalization handler.
 *
 * @package PatchWatch
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class PWW_I18n
 */
class PWW_I18n {

    /**
     * Load the plugin text domain.
     *
     * Since WordPress 4.6, translations are loaded automatically for plugins
     * hosted on WordPress.org. This method is kept as a no-op for backward
     * compatibility with the hook registered in the loader.
     */
    public function load_textdomain() {
        // Intentionally left empty. Since WP 4.6, translations for plugins
        // hosted on WordPress.org are loaded automatically by WordPress.
    }
}
