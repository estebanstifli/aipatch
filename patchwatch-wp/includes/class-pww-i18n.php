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
     */
    public function load_textdomain() {
        load_plugin_textdomain(
            'patchwatch-wp',
            false,
            dirname( AIPATCH_PLUGIN_BASENAME ) . '/languages/'
        );
    }
}
