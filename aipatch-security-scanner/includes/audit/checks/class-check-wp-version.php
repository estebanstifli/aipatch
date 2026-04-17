<?php
/**
 * Check: WordPress core version.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_WP_Version extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'wp_version';
    }

    public function get_title(): string {
        return __( 'WordPress Core Version', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'core';
    }

    public function run(): array {
        global $wp_version;

        $update_data  = get_site_transient( 'update_core' );
        $needs_update = false;

        if ( isset( $update_data->updates ) && is_array( $update_data->updates ) ) {
            foreach ( $update_data->updates as $update ) {
                if ( 'upgrade' === $update->response ) {
                    $needs_update = true;
                    break;
                }
            }
        }

        if ( ! $needs_update ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'wp_outdated',
                'title'           => __( 'WordPress core is outdated', 'aipatch-security-scanner' ),
                'description'     => sprintf(
                    /* translators: %s: Installed WordPress version. */
                    __( 'You are running WordPress %s. A newer version is available.', 'aipatch-security-scanner' ),
                    $wp_version
                ),
                'severity'        => 'high',
                'confidence'      => 'high',
                'category'        => 'core',
                'why_it_matters'  => __( 'Outdated WordPress versions may contain known security vulnerabilities that attackers can exploit.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Update WordPress to the latest version from Dashboard → Updates.', 'aipatch-security-scanner' ),
                'dismissible'     => false,
                'evidence'        => sprintf( 'Installed: %s', $wp_version ),
            ) ),
        );
    }
}
