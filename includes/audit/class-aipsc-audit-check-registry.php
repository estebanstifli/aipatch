<?php
/**
 * Audit Check Registry.
 *
 * Singleton that holds all registered audit checks, grouped by category.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Audit_Check_Registry
 *
 * Central catalog of all audit checks.
 */
class AIPSC_Audit_Check_Registry {

    /**
     * Registered checks indexed by ID.
     *
     * @var array<string, AIPSC_Audit_Check_Interface>
     */
    private $checks = array();

    /**
     * Singleton instance.
     *
     * @var self|null
     */
    private static $instance = null;

    /**
     * Get the singleton instance.
     *
     * @return self
     */
    public static function instance(): self {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Register a check.
     *
     * @param AIPSC_Audit_Check_Interface $check Check instance.
     * @return void
     */
    public function register( AIPSC_Audit_Check_Interface $check ): void {
        $this->checks[ $check->get_id() ] = $check;
    }

    /**
     * Unregister a check by ID.
     *
     * @param string $id Check ID.
     * @return void
     */
    public function unregister( string $id ): void {
        unset( $this->checks[ $id ] );
    }

    /**
     * Get a check by ID.
     *
     * @param string $id Check ID.
     * @return AIPSC_Audit_Check_Interface|null
     */
    public function get( string $id ) {
        return $this->checks[ $id ] ?? null;
    }

    /**
     * Get all registered checks.
     *
     * @return array<string, AIPSC_Audit_Check_Interface>
     */
    public function get_all(): array {
        return $this->checks;
    }

    /**
     * Get checks filtered by category.
     *
     * @param string $category Category string.
     * @return AIPSC_Audit_Check_Interface[]
     */
    public function get_by_category( string $category ): array {
        $filtered = array();
        foreach ( $this->checks as $check ) {
            if ( $check->get_category() === $category ) {
                $filtered[] = $check;
            }
        }
        return $filtered;
    }

    /**
     * Get all unique categories.
     *
     * @return string[]
     */
    public function get_categories(): array {
        $categories = array();
        foreach ( $this->checks as $check ) {
            $categories[ $check->get_category() ] = true;
        }
        return array_keys( $categories );
    }

    /**
     * Get total count of registered checks.
     *
     * @return int
     */
    public function count(): int {
        return count( $this->checks );
    }

    /**
     * Get check IDs.
     *
     * @return string[]
     */
    public function get_ids(): array {
        return array_keys( $this->checks );
    }

    /**
     * Reset the registry (used for testing).
     *
     * @return void
     */
    public function reset(): void {
        $this->checks = array();
    }
}
