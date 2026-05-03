<?php
/**
 * Audit Check Interface.
 *
 * Contract that every audit check must implement.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Interface AIPSC_Audit_Check_Interface
 *
 * Defines the contract for individual security audit checks.
 */
interface AIPSC_Audit_Check_Interface {

    /**
     * Return a unique machine-readable identifier for this check.
     *
     * @return string
     */
    public function get_id(): string;

    /**
     * Human-readable title of the check.
     *
     * @return string
     */
    public function get_title(): string;

    /**
     * Category this check belongs to.
     *
     * @return string One of: core, plugins, themes, users, configuration, server, files, vulnerabilities.
     */
    public function get_category(): string;

    /**
     * Run the check and return an array of AIPSC_Audit_Check_Result objects.
     *
     * A check may return zero results (nothing found) or multiple results.
     *
     * @return AIPSC_Audit_Check_Result[]
     */
    public function run(): array;
}
