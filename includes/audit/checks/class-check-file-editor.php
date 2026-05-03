<?php
/**
 * Check: File editor enabled.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class AIPSC_Check_File_Editor extends AIPSC_Audit_Check_Base {

    public function get_id(): string {
        return 'file_editor';
    }

    public function get_title(): string {
        return __( 'WordPress File Editor', 'aipatch-security-scanner' );
    }

    public function get_category(): string {
        return 'configuration';
    }

    public function run(): array {
        $disabled = defined( 'DISALLOW_FILE_EDIT' ) ? (bool) constant( 'DISALLOW_FILE_EDIT' ) : false;

        if ( $disabled ) {
            return array();
        }

        return array(
            $this->make_result( array(
                'id'              => 'file_editor_enabled',
                'title'           => __( 'WordPress file editor is enabled', 'aipatch-security-scanner' ),
                'description'     => __( 'The built-in plugin and theme editor is accessible from the admin panel.', 'aipatch-security-scanner' ),
                'severity'        => 'high',
                'confidence'      => 'high',
                'category'        => 'configuration',
                'why_it_matters'  => __( 'If an attacker gains admin access, they can inject malicious code directly through the file editor.', 'aipatch-security-scanner' ),
                'recommendation'  => __( 'Add this line to your wp-config.php: define( \'DISALLOW_FILE_EDIT\', true );', 'aipatch-security-scanner' ),
                'dismissible'     => true,
                'evidence'        => 'DISALLOW_FILE_EDIT constant not defined or false',
            ) ),
        );
    }
}
