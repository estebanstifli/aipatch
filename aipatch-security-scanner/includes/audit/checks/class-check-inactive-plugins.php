<?php
/**
 * Check: Inactive plugins (outdated + too many).
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Inactive_Plugins extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'inactive_plugins';
    }

    public function get_title(): string {
        return __( 'Inactive Plugins', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'plugins';
    }

    public function run(): array {
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $results        = array();
        $all_plugins    = get_plugins();
        $active_plugins = get_option( 'active_plugins', array() );
        $update_data    = get_site_transient( 'update_plugins' );

        $inactive_outdated = array();
        $inactive_count    = 0;

        foreach ( $all_plugins as $file => $data ) {
            if ( in_array( $file, $active_plugins, true ) ) {
                continue;
            }
            $inactive_count++;
            if ( isset( $update_data->response[ $file ] ) ) {
                $inactive_outdated[] = $data['Name'];
            }
        }

        if ( ! empty( $inactive_outdated ) ) {
            $results[] = $this->make_result( array(
                'id'              => 'inactive_plugins_outdated',
                'title'           => sprintf(
                    _n( '%d inactive plugin is outdated', '%d inactive plugins are outdated', count( $inactive_outdated ), 'aipatch-security-scanner' ),
                    count( $inactive_outdated )
                ),
                'description'     => sprintf(
                    __( 'Inactive outdated plugins: %s', 'aipatch-security-scanner' ),
                    implode( ', ', array_map( 'esc_html', array_slice( $inactive_outdated, 0, 10 ) ) )
                ),
                'severity'        => count( $inactive_outdated ) > 2 ? 'high' : 'medium',
                'confidence'      => 'high',
                'category'        => 'plugins',
                'why_it_matters'  => __( 'Inactive plugins can still be exploited if they contain vulnerabilities. Their code is still on the server and accessible.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Delete inactive plugins you no longer need. If you plan to reactivate them, update them first.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Inactive outdated: %s', implode( ', ', array_slice( $inactive_outdated, 0, 10 ) ) ),
            ) );
        }

        if ( $inactive_count > 3 ) {
            $results[] = $this->make_result( array(
                'id'              => 'too_many_inactive_plugins',
                'title'           => sprintf(
                    __( '%d inactive plugins installed', 'aipatch-security-scanner' ),
                    $inactive_count
                ),
                'description'     => __( 'Having many inactive plugins increases the attack surface even though they are deactivated.', 'aipatch-security-scanner' ),
                'severity'        => 'low',
                'confidence'      => 'high',
                'category'        => 'plugins',
                'why_it_matters'  => __( 'Inactive plugin files remain on the server and can be targeted. Each unused plugin is unnecessary risk.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Delete plugins you are not using. Keep only the ones you plan to reactivate soon.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Found %d inactive plugins', $inactive_count ),
            ) );
        }

        return $results;
    }
}
