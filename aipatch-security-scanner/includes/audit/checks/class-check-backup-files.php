<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class AIPSC_Check_Backup_Files extends AIPSC_Audit_Check_Base {
    public function get_id(): string { return 'backup_files'; }
    public function get_title(): string { return __( 'Exposed Backup Files', 'aipatch-security-scanner' ); }
    public function get_category(): string { return 'malware_surface'; }

    public function run(): array {
        $dangerous = array(
            '.sql',
            '.sql.gz',
            '.tar.gz',
            '.zip',
            '.bak',
            '.old',
            '.swp',
            '.orig',
        );

        $candidates = array(
            'wp-config.php.bak',
            'wp-config.php.old',
            'wp-config.php.orig',
            'wp-config.php.save',
            'wp-config.bak',
            'wp-config.old',
            '.wp-config.php.swp',
            'wp-config.php~',
            'database.sql',
            'backup.sql',
            'dump.sql',
            'db.sql',
            'backup.zip',
            'backup.tar.gz',
            'site.zip',
        );

        $found = array();

        foreach ( $candidates as $file ) {
            $path = ABSPATH . $file;
            if ( file_exists( $path ) ) {
                $found[] = $file;
            }
        }

        // Also check for common backup directories.
        $backup_dirs = array( 'backups', 'backup', 'bak', 'old', 'sql' );
        foreach ( $backup_dirs as $dir ) {
            $dir_path = ABSPATH . $dir;
            if ( is_dir( $dir_path ) ) {
                $found[] = $dir . '/';
            }
        }

        if ( ! empty( $found ) ) {
            return array( $this->make_result( array(
                'id'             => 'backup_files_exposed',
                'title'          => $this->get_title(),
                'severity'       => AIPSC_Audit_Check_Result::SEVERITY_HIGH,
                'confidence'     => AIPSC_Audit_Check_Result::CONFIDENCE_HIGH,
                'description'    => sprintf(
                    __( 'Found %d potentially sensitive backup file(s) in the web root.', 'aipatch-security-scanner' ),
                    count( $found )
                ),
                'why_it_matters' => __( 'Backup files can expose database credentials, source code, or full database dumps to attackers.', 'aipatch-security-scanner' ),
                'recommendation' => __( 'Remove backup files from the web root or move them outside the document root.', 'aipatch-security-scanner' ),
                'evidence'       => implode( ', ', $found ),
                'meta'           => array( 'files' => $found ),
            ) ) );
        }

        return array( $this->make_result( array(
            'id'          => 'backup_files',
            'title'       => $this->get_title(),
            'severity'    => AIPSC_Audit_Check_Result::SEVERITY_INFO,
            'status'      => AIPSC_Audit_Check_Result::STATUS_PASS,
            'description' => __( 'No common backup files found in the web root.', 'aipatch-security-scanner' ),
        ) ) );
    }
}
