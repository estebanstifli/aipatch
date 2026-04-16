<?php
/**
 * Check: Outdated active plugins.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Plugins_Outdated extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'plugins_outdated';
    }

    public function get_title(): string {
        return __( 'Outdated Active Plugins', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'plugins';
    }

    public function run(): array {
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins    = get_plugins();
        $active_plugins = get_option( 'active_plugins', array() );
        $update_data    = get_site_transient( 'update_plugins' );
        $outdated       = array();

        foreach ( $all_plugins as $file => $data ) {
            if ( ! in_array( $file, $active_plugins, true ) ) {
                continue;
            }
            if ( isset( $update_data->response[ $file ] ) ) {
                $outdated[] = $data['Name'];
            }
        }

        if ( empty( $outdated ) ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'plugins_outdated',
                'title'           => sprintf(
                    _n( '%d plugin needs updating', '%d plugins need updating', count( $outdated ), 'aipatch-security-scanner' ),
                    count( $outdated )
                ),
                'description'     => sprintf(
                    __( 'Outdated plugins: %s', 'aipatch-security-scanner' ),
                    implode( ', ', array_map( 'esc_html', array_slice( $outdated, 0, 10 ) ) )
                ),
                'severity'        => count( $outdated ) > 3 ? 'high' : 'medium',
                'confidence'      => 'high',
                'category'        => 'plugins',
                'why_it_matters'  => __( 'Outdated plugins are one of the most common entry points for attackers. Updates often include security patches.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Update all plugins from Dashboard → Updates, or enable auto-updates for trusted plugins.', 'aipatch-security-scanner' ),
                'dismissible'     => false,
                'evidence'        => sprintf( 'Outdated: %s', implode( ', ', array_slice( $outdated, 0, 10 ) ) ),
                'meta'            => array( 'outdated_count' => count( $outdated ), 'names' => $outdated ),
            ) ),
        );
    }
}
