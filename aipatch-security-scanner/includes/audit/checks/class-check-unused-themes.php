<?php
/**
 * Check: Unused themes.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Unused_Themes extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'unused_themes';
    }

    public function get_title(): string {
        return __( 'Unused Themes', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'themes';
    }

    public function run(): array {
        $results       = array();
        $active_theme  = get_stylesheet();
        $parent_theme  = get_template();
        $all_themes    = wp_get_themes();
        $update_data   = get_site_transient( 'update_themes' );
        $unused        = array();
        $unused_outdated = array();

        foreach ( $all_themes as $slug => $theme ) {
            if ( $slug === $active_theme || $slug === $parent_theme ) {
                continue;
            }
            $unused[] = $theme->get( 'Name' );
            if ( isset( $update_data->response[ $slug ] ) ) {
                $unused_outdated[] = $theme->get( 'Name' );
            }
        }

        if ( ! empty( $unused_outdated ) ) {
            $results[] = $this->make_result( array(
                'id'              => 'unused_themes_outdated',
                'title'           => sprintf(
                    /* translators: %d: Number of outdated unused themes. */
                    _n( '%d unused theme is outdated', '%d unused themes are outdated', count( $unused_outdated ), 'aipatch-security-scanner' ),
                    count( $unused_outdated )
                ),
                'description'     => sprintf(
                    /* translators: %s: Comma-separated list of outdated unused theme names. */
                    __( 'Unused outdated themes: %s', 'aipatch-security-scanner' ),
                    implode( ', ', array_map( 'esc_html', $unused_outdated ) )
                ),
                'severity'        => 'medium',
                'confidence'      => 'high',
                'category'        => 'themes',
                'why_it_matters'  => __( 'Unused themes with known vulnerabilities can be exploited even though they are not active.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Delete unused themes. WordPress recommends keeping only the active theme and one default fallback theme.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Unused outdated themes: %s', implode( ', ', $unused_outdated ) ),
            ) );
        }

        if ( count( $unused ) > 2 ) {
            $results[] = $this->make_result( array(
                'id'              => 'too_many_unused_themes',
                'title'           => sprintf(
                    /* translators: %d: Number of unused installed themes. */
                    __( '%d unused themes installed', 'aipatch-security-scanner' ),
                    count( $unused )
                ),
                'description'     => __( 'Multiple inactive themes are installed. Each adds potential attack vectors.', 'aipatch-security-scanner' ),
                'severity'        => 'low',
                'confidence'      => 'high',
                'category'        => 'themes',
                'why_it_matters'  => __( 'Extra themes increase your attack surface. Their files can be exploited regardless of activation status.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Remove unused themes, keeping only the active theme and one default theme as fallback.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => sprintf( 'Found %d unused themes: %s', count( $unused ), implode( ', ', array_slice( $unused, 0, 10 ) ) ),
            ) );
        }

        return $results;
    }
}
