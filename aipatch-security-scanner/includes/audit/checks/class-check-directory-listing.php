<?php
/**
 * Check: Directory listing in uploads.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_Directory_Listing extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'directory_listing';
    }

    public function get_title(): string {
        return __( 'Directory Listing Protection', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'server';
    }

    public function run(): array {
        $uploads_dir  = wp_upload_dir();
        $uploads_path = $uploads_dir['basedir'];

        $has_index = file_exists( $uploads_path . '/index.php' ) || file_exists( $uploads_path . '/index.html' );

        if ( $has_index ) {
            return array();
        }

        $htaccess  = ABSPATH . '.htaccess';
        $protected = false;
        if ( file_exists( $htaccess ) ) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
            $content = @file_get_contents( $htaccess );
            if ( $content && stripos( $content, 'Options -Indexes' ) !== false ) {
                $protected = true;
            }
        }

        if ( $protected ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'directory_listing',
                'title'           => __( 'Directory listing may be enabled', 'aipatch-security-scanner' ),
                'description'     => __( 'The uploads directory does not have an index file and no .htaccess protection was detected.', 'aipatch-security-scanner' ),
                'severity'        => 'low',
                'confidence'      => 'medium',
                'category'        => 'server',
                'why_it_matters'  => __( 'Directory listing allows anyone to browse your files, which can expose sensitive information.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Add an empty index.php file to your uploads directory or add "Options -Indexes" to your .htaccess file.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'No index.php in uploads directory, no Options -Indexes in .htaccess',
                'false_positive_likelihood' => 'medium',
            ) ),
        );
    }
}
