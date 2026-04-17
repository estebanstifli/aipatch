<?php
/**
 * Check: Outdated themes.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Themes_Outdated extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'themes_outdated';
    }

    public function get_title(): string {
        return __( 'Outdated Themes', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'themes';
    }

    public function run(): array {
        $update_data = get_site_transient( 'update_themes' );
        $outdated    = array();

        if ( isset( $update_data->response ) && is_array( $update_data->response ) ) {
            foreach ( $update_data->response as $slug => $data ) {
                $theme = wp_get_theme( $slug );
                if ( $theme->exists() ) {
                    $outdated[] = $theme->get( 'Name' );
                }
            }
        }

        if ( empty( $outdated ) ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'themes_outdated',
                'title'           => sprintf(
                    /* translators: %d: Number of installed themes needing updates. */
                    _n( '%d theme needs updating', '%d themes need updating', count( $outdated ), 'aipatch-security-scanner' ),
                    count( $outdated )
                ),
                'description'     => sprintf(
                    /* translators: %s: Comma-separated list of outdated theme names. */
                    __( 'Outdated themes: %s', 'aipatch-security-scanner' ),
                    implode( ', ', array_map( 'esc_html', $outdated ) )
                ),
                'severity'        => 'medium',
                'confidence'      => 'high',
                'category'        => 'themes',
                'why_it_matters'  => __( 'Theme vulnerabilities can be exploited even if the theme is not active. Keep all installed themes updated.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Update themes from Dashboard → Updates. Remove unused themes.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Outdated: %s', implode( ', ', $outdated ) ),
            ) ),
        );
    }
}
