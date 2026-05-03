<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class AIPSC_Check_Phpinfo extends AIPSC_Audit_Check_Base {
    public function get_id(): string { return 'phpinfo_exposure'; }
    public function get_title(): string { return __( 'phpinfo() Files Exposed', 'aipatch-security-scanner' ); }
    public function get_category(): string { return 'malware_surface'; }

    public function run(): array {
        $candidates = array(
            'phpinfo.php',
            'info.php',
            'php_info.php',
            'test.php',
            'i.php',
            'pi.php',
        );

        $found = array();

        foreach ( $candidates as $file ) {
            $path = ABSPATH . $file;
            if ( file_exists( $path ) ) {
                // Verify it actually calls phpinfo.
                $content = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
                if ( false !== $content && preg_match( '/\bphpinfo\s*\(/', $content ) ) {
                    $found[] = $file;
                }
            }
        }

        if ( ! empty( $found ) ) {
            return array( $this->make_result( array(
                'id'             => 'phpinfo_exposed',
                'title'          => $this->get_title(),
                'severity'       => AIPSC_Audit_Check_Result::SEVERITY_HIGH,
                'description'    => sprintf(
                    /* translators: %d: Number of phpinfo files found. */
                    __( 'Found %d phpinfo file(s) accessible from the web.', 'aipatch-security-scanner' ),
                    count( $found )
                ),
                'why_it_matters' => __( 'phpinfo() exposes PHP version, extensions, environment variables, and server paths that aid attackers.', 'aipatch-security-scanner' ),
                'recommendation' => __( 'Delete phpinfo files from the server.', 'aipatch-security-scanner' ),
                'evidence'       => implode( ', ', $found ),
                'meta'           => array( 'files' => $found ),
            ) ) );
        }

        return array( $this->make_result( array(
            'id'          => 'phpinfo_exposure',
            'title'       => $this->get_title(),
            'severity'    => AIPSC_Audit_Check_Result::SEVERITY_INFO,
            'status'      => AIPSC_Audit_Check_Result::STATUS_PASS,
            'description' => __( 'No phpinfo files found.', 'aipatch-security-scanner' ),
        ) ) );
    }
}
