<?php
/**
 * Check: Plugin/theme installation from admin.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_File_Install extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'file_install';
    }

    public function get_title(): string {
        return __( 'File Installation Permissions', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'configuration';
    }

    public function run(): array {
        $file_mods_allowed = ! defined( 'DISALLOW_FILE_MODS' ) || ! constant( 'DISALLOW_FILE_MODS' );

        if ( ! $file_mods_allowed ) {
            return array();
        }

        if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! constant( 'DISALLOW_FILE_EDIT' ) ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'file_mods_allowed',
                'title'           => __( 'Plugin/theme installation from admin is allowed', 'aipatch-security-scanner' ),
                'description'     => __( 'File editing is disabled but file installations are still possible from the admin panel.', 'aipatch-security-scanner' ),
                'severity'        => 'low',
                'confidence'      => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'If an attacker gains admin access, they could install a malicious plugin or theme.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'For maximum security, add define( \'DISALLOW_FILE_MODS\', true ); to wp-config.php.', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'DISALLOW_FILE_EDIT is true but DISALLOW_FILE_MODS is not set',
            ) ),
        );
    }
}
