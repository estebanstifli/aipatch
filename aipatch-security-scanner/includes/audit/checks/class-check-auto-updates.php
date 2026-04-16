<?php
/**
 * Check: Auto-updates status.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Auto_Updates extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'auto_updates';
    }

    public function get_title(): string {
        return __( 'Auto-Updates Configuration', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'configuration';
    }

    public function run(): array {
        $results = array();

        // Core auto-updates.
        $core_auto_update = defined( 'WP_AUTO_UPDATE_CORE' ) ? WP_AUTO_UPDATE_CORE : 'minor';

        if ( false === $core_auto_update || 'false' === $core_auto_update ) {
            $results[] = $this->make_result( array(
                'id'              => 'core_auto_updates_off',
                'title'           => __( 'Core auto-updates are disabled', 'aipatch-security-scanner' ),
                'description'     => __( 'Automatic updates for WordPress core are completely disabled.', 'aipatch-security-scanner' ),
                'severity'        => 'high',
                'confidence'      => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'Security patches are often released urgently. Without auto-updates, your site remains vulnerable until you manually update.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'At minimum, enable minor/security auto-updates by setting WP_AUTO_UPDATE_CORE to "minor" in wp-config.php.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'WP_AUTO_UPDATE_CORE = %s', var_export( $core_auto_update, true ) ),
            ) );
        }

        // Plugin auto-updates.
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $active_plugins      = get_option( 'active_plugins', array() );
        $auto_update_plugins = get_site_option( 'auto_update_plugins', array() );

        if ( ! is_array( $auto_update_plugins ) ) {
            $auto_update_plugins = array();
        }

        $all_plugins    = get_plugins();
        $no_auto_update = array();

        foreach ( $active_plugins as $plugin_file ) {
            if ( ! in_array( $plugin_file, $auto_update_plugins, true ) && isset( $all_plugins[ $plugin_file ] ) ) {
                $no_auto_update[] = $all_plugins[ $plugin_file ]['Name'];
            }
        }

        if ( count( $no_auto_update ) > 0 && count( $active_plugins ) > 0 ) {
            $pct = round( ( count( $no_auto_update ) / count( $active_plugins ) ) * 100 );
            if ( $pct > 50 ) {
                $results[] = $this->make_result( array(
                    'id'              => 'plugins_auto_updates_off',
                    'title'           => sprintf(
                        __( '%d%% of active plugins lack auto-updates', 'aipatch-security-scanner' ),
                        $pct
                    ),
                    'description'     => sprintf(
                        __( '%1$d of %2$d active plugins do not have auto-updates enabled.', 'aipatch-security-scanner' ),
                        count( $no_auto_update ),
                        count( $active_plugins )
                    ),
                    'severity'        => 'medium',
                    'confidence'      => 'high',
                    'category'        => 'plugins',
                    'why_it_matters'  => __( 'Plugins without auto-updates won\'t receive security patches automatically.', 'aipatch-security-scanner' ),
                    'recommendation'  => __( 'Enable auto-updates for trusted plugins from the Plugins page.', 'aipatch-security-scanner' ),
                    'dismissible'     => true,
                    'evidence'        => sprintf( '%d of %d plugins without auto-updates', count( $no_auto_update ), count( $active_plugins ) ),
                ) );
            }
        }

        return $results;
    }
}
