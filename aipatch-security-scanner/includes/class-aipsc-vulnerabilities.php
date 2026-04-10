<?php
/**
 * Vulnerabilities module – provider-based vulnerability intelligence.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Interface AIPSC_Vulnerability_Provider
 *
 * Contract for vulnerability data sources.
 * Future providers (remote API, WPScan, etc.) implement this interface.
 */
interface AIPSC_Vulnerability_Provider {

    /**
     * Get vulnerabilities for installed software.
     *
     * @param array $installed Array of installed software items.
     * @return array Array of vulnerability records.
     */
    public function get_vulnerabilities( array $installed ): array;

    /**
     * Get provider source name.
     *
     * @return string
     */
    public function get_source_name(): string;

    /**
     * Check if this provider is available/configured.
     *
     * @return bool
     */
    public function is_available(): bool;
}

/**
 * Class AIPSC_Local_Vulnerability_Provider
 *
 * Built-in provider with a curated local knowledge base of known vulnerabilities.
 * Checks installed software against known vulnerability records.
 */
class AIPSC_Local_Vulnerability_Provider implements AIPSC_Vulnerability_Provider {

    /**
     * @inheritDoc
     */
    public function get_vulnerabilities( array $installed ): array {
        $known_vulns = $this->get_known_vulnerabilities();
        $matches = array();

        foreach ( $installed as $item ) {
            $slug = $item['slug'];
            if ( isset( $known_vulns[ $slug ] ) ) {
                foreach ( $known_vulns[ $slug ] as $vuln ) {
                    // Check if installed version is in affected range.
                    if ( version_compare( $item['version'], $vuln['fix_version'], '<' ) ) {
                        $vuln['installed_version'] = $item['version'];
                        $vuln['slug']              = $slug;
                        $vuln['software_type']     = $item['type'];
                        $vuln['source']            = $this->get_source_name();
                        $matches[]                 = $vuln;
                    }
                }
            }
        }

        return $matches;
    }

    /**
     * @inheritDoc
     */
    public function get_source_name(): string {
        return 'local-db';
    }

    /**
     * @inheritDoc
     */
    public function is_available(): bool {
        return true;
    }

    /**
     * Known vulnerability database.
     *
     * Curated set of high-profile vulnerabilities used when no external
     * feed is configured. Updated with each plugin release.
     *
     * @return array
     */
    private function get_known_vulnerabilities(): array {
        return array(
            'contact-form-7' => array(
                array(
                    'title'             => 'Unrestricted File Upload',
                    'description'       => 'Allows unauthenticated file upload via crafted form submission.',
                    'severity'          => 'critical',
                    'affected_versions' => '< 5.8.1',
                    'fix_version'       => '5.8.1',
                    'references'        => array(),
                ),
            ),
            'elementor' => array(
                array(
                    'title'             => 'Authenticated Stored XSS',
                    'description'       => 'Contributor-level users can inject stored XSS via widget attributes.',
                    'severity'          => 'medium',
                    'affected_versions' => '< 3.18.1',
                    'fix_version'       => '3.18.1',
                    'references'        => array(),
                ),
            ),
            'woocommerce' => array(
                array(
                    'title'             => 'Unauthorized Order Access',
                    'description'       => 'IDOR vulnerability allows customers to access other users\' order details.',
                    'severity'          => 'high',
                    'affected_versions' => '< 8.4.0',
                    'fix_version'       => '8.4.0',
                    'references'        => array(),
                ),
            ),
            'wordpress' => array(
                array(
                    'title'             => 'Authenticated SQL Injection in WP_Query',
                    'description'       => 'Improper sanitization of query parameters allows SQL injection by authenticated users.',
                    'severity'          => 'high',
                    'affected_versions' => '< 6.4.3',
                    'fix_version'       => '6.4.3',
                    'references'        => array(),
                ),
            ),
        );
    }
}

/**
 * Class AIPSC_Vulnerabilities
 *
 * Orchestrates vulnerability providers and formats results.
 */
class AIPSC_Vulnerabilities {

    /**
     * Registered providers.
     *
     * @var AIPSC_Vulnerability_Provider[]
     */
    private $providers = array();

    /**
     * Constructor.
     */
    public function __construct() {
        // Register the built-in local provider.
        $this->register_provider( new AIPSC_Local_Vulnerability_Provider() );

        /**
         * Allow external code to register additional providers.
         *
         * @param AIPSC_Vulnerabilities $instance The vulnerabilities module.
         */
        do_action( 'aipatch_register_vulnerability_providers', $this );
    }

    /**
     * Register a vulnerability provider.
     *
     * @param AIPSC_Vulnerability_Provider $provider Provider instance.
     */
    public function register_provider( AIPSC_Vulnerability_Provider $provider ) {
        $this->providers[ $provider->get_source_name() ] = $provider;
    }

    /**
     * Get all vulnerabilities for currently installed software.
     *
     * @return array
     */
    public function get_all_vulnerabilities() {
        $installed = $this->get_installed_software();
        $all_vulns = array();

        foreach ( $this->providers as $provider ) {
            if ( ! $provider->is_available() ) {
                continue;
            }

            $vulns = $provider->get_vulnerabilities( $installed );
            $all_vulns = array_merge( $all_vulns, $vulns );
        }

        // Sort by severity.
        $severity_order = array( 'critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3 );
        usort( $all_vulns, function ( $a, $b ) use ( $severity_order ) {
            $sa = isset( $severity_order[ $a['severity'] ] ) ? $severity_order[ $a['severity'] ] : 4;
            $sb = isset( $severity_order[ $b['severity'] ] ) ? $severity_order[ $b['severity'] ] : 4;
            return $sa - $sb;
        } );

        return $all_vulns;
    }

    /**
     * Get list of installed software for vulnerability checking.
     *
     * @return array
     */
    public function get_installed_software() {
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $software = array();

        // WordPress core.
        global $wp_version;
        $software[] = array(
            'type'    => 'core',
            'slug'    => 'wordpress',
            'name'    => 'WordPress',
            'version' => $wp_version,
        );

        // Active plugins.
        $plugins        = get_plugins();
        $active_plugins = get_option( 'active_plugins', array() );

        foreach ( $plugins as $file => $data ) {
            if ( ! in_array( $file, $active_plugins, true ) ) {
                continue;
            }

            $slug = dirname( $file );
            if ( '.' === $slug ) {
                $slug = basename( $file, '.php' );
            }

            $software[] = array(
                'type'    => 'plugin',
                'slug'    => $slug,
                'name'    => $data['Name'],
                'version' => $data['Version'],
            );
        }

        // Active theme and parent.
        $theme = wp_get_theme();
        $software[] = array(
            'type'    => 'theme',
            'slug'    => $theme->get_stylesheet(),
            'name'    => $theme->get( 'Name' ),
            'version' => $theme->get( 'Version' ),
        );

        if ( $theme->parent() ) {
            $parent = $theme->parent();
            $software[] = array(
                'type'    => 'theme',
                'slug'    => $parent->get_stylesheet(),
                'name'    => $parent->get( 'Name' ),
                'version' => $parent->get( 'Version' ),
            );
        }

        return $software;
    }

    /**
     * Check if any external provider is connected.
     *
     * @return bool
     */
    public function has_external_provider() {
        foreach ( $this->providers as $provider ) {
            if ( 'local-db' !== $provider->get_source_name() && $provider->is_available() ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get provider status summary.
     *
     * @return array
     */
    public function get_provider_status() {
        $status = array();
        foreach ( $this->providers as $name => $provider ) {
            $status[] = array(
                'name'      => $name,
                'available' => $provider->is_available(),
            );
        }
        return $status;
    }
}
