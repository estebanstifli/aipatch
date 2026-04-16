<?php
/**
 * Abstract base class for audit checks.
 *
 * Provides common helpers so individual checks stay lean.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Audit_Check_Base
 */
abstract class AIPSC_Audit_Check_Base implements AIPSC_Audit_Check_Interface {

    /**
     * Create a result object with common defaults filled in.
     *
     * @param array $args Result arguments (see AIPSC_Audit_Check_Result constructor).
     * @return AIPSC_Audit_Check_Result
     */
    protected function make_result( array $args ): AIPSC_Audit_Check_Result {
        // Set source to scanner by default.
        if ( empty( $args['source'] ) ) {
            $args['source'] = 'scanner';
        }
        return new AIPSC_Audit_Check_Result( $args );
    }
}
