<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class AIPSC_Check_Uploads_Index extends AIPSC_Audit_Check_Base {
    public function get_id(): string { return 'uploads_index'; }
    public function get_title(): string { return __( 'Uploads Directory Index Protection', 'aipatch-security-scanner' ); }
    public function get_category(): string { return 'malware_surface'; }

    public function run(): array {
        $uploads_dir = wp_upload_dir();
        $base        = $uploads_dir['basedir'];
        $checks      = array();

        // Check for index.html/index.php in the uploads directory.
        $has_index = file_exists( $base . '/index.html' ) || file_exists( $base . '/index.php' );

        // Check for .htaccess in uploads.
        $htaccess      = $base . '/.htaccess';
        $has_htaccess  = file_exists( $htaccess );
        $blocks_php    = false;

        if ( $has_htaccess && is_readable( $htaccess ) ) {
            $content = file_get_contents( $htaccess ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
            if ( false !== $content ) {
                // Look for PHP execution blocking rules.
                $blocks_php = (bool) preg_match( '/(?:php_flag\s+engine\s+off|deny\s+from\s+all|RemoveHandler\s+\.php|<FilesMatch[^>]*\\\\\.php)/i', $content );
            }
        }

        $results = array();

        if ( ! $has_index ) {
            $results[] = $this->make_result( array(
                'id'             => 'uploads_no_index',
                'title'          => __( 'Uploads directory has no index file', 'aipatch-security-scanner' ),
                'severity'       => AIPSC_Audit_Check_Result::SEVERITY_LOW,
                'description'    => __( 'The uploads directory lacks an index.html or index.php, potentially allowing directory listing.', 'aipatch-security-scanner' ),
                'why_it_matters' => __( 'Directory listing reveals all uploaded files, which may include sensitive documents.', 'aipatch-security-scanner' ),
                'recommendation' => __( 'Add an empty index.html file in the uploads directory.', 'aipatch-security-scanner' ),
                'evidence'       => $base,
                'fixable'        => true,
            ) );
        }

        if ( ! $blocks_php ) {
            $results[] = $this->make_result( array(
                'id'             => 'uploads_php_execution',
                'title'          => __( 'PHP execution not blocked in uploads', 'aipatch-security-scanner' ),
                'severity'       => AIPSC_Audit_Check_Result::SEVERITY_HIGH,
                'confidence'     => $has_htaccess ? AIPSC_Audit_Check_Result::CONFIDENCE_HIGH : AIPSC_Audit_Check_Result::CONFIDENCE_MEDIUM,
                'description'    => __( 'The uploads directory does not block PHP execution, allowing uploaded shells to run.', 'aipatch-security-scanner' ),
                'why_it_matters' => __( 'If an attacker uploads a PHP file, it can be executed and give full server access.', 'aipatch-security-scanner' ),
                'recommendation' => __( 'Add .htaccess rules to block PHP execution in the uploads directory.', 'aipatch-security-scanner' ),
                'evidence'       => $has_htaccess ? '.htaccess exists but no PHP blocking rules' : 'No .htaccess in uploads directory',
                'fixable'        => true,
            ) );
        }

        if ( empty( $results ) ) {
            $results[] = $this->make_result( array(
                'id'          => 'uploads_index',
                'title'       => $this->get_title(),
                'severity'    => AIPSC_Audit_Check_Result::SEVERITY_INFO,
                'status'      => AIPSC_Audit_Check_Result::STATUS_PASS,
                'description' => __( 'Uploads directory is properly protected.', 'aipatch-security-scanner' ),
            ) );
        }

        return $results;
    }
}
