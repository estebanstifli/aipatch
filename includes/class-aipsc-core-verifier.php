<?php
/**
 * WordPress Core Integrity Verifier.
 *
 * Fetches official checksums from api.wordpress.org and compares them
 * against the local filesystem to detect modified, missing, and
 * unexpected files in core paths.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Core_Verifier
 */
class AIPSC_Core_Verifier {

    /**
     * Transient key for cached checksums.
     */
    const CACHE_KEY = 'aipsc_core_checksums';

    /**
     * Cache TTL: 12 hours.
     */
    const CACHE_TTL = 43200;

    /**
     * Known root-level core files that ship with WordPress.
     *
     * @var string[]
     */
    private static $known_root_files = array(
        'index.php',
        'wp-activate.php',
        'wp-blog-header.php',
        'wp-comments-post.php',
        'wp-config-sample.php',
        'wp-cron.php',
        'wp-links-opml.php',
        'wp-load.php',
        'wp-login.php',
        'wp-mail.php',
        'wp-settings.php',
        'wp-signup.php',
        'wp-trackback.php',
        'xmlrpc.php',
    );

    /**
     * @var AIPSC_Logger
     */
    private $logger;

    /**
     * Cached checksum map: relative_path => md5.
     *
     * @var array<string, string>|null
     */
    private $checksums;

    /**
     * Constructor.
     *
     * @param AIPSC_Logger $logger Logger.
     */
    public function __construct( AIPSC_Logger $logger ) {
        $this->logger = $logger;
    }

    /**
     * Fetch official WordPress core checksums for the current version and locale.
     *
     * Results are cached in a transient for CACHE_TTL seconds.
     *
     * @param bool $force_refresh Bypass cache.
     * @return array<string, string> Relative path => MD5 hash map, or empty on failure.
     */
    public function get_checksums( $force_refresh = false ) {
        if ( null !== $this->checksums && ! $force_refresh ) {
            return $this->checksums;
        }

        if ( ! $force_refresh ) {
            $cached = get_transient( self::CACHE_KEY );
            if ( is_array( $cached ) && ! empty( $cached ) ) {
                $this->checksums = $cached;
                return $this->checksums;
            }
        }

        global $wp_version, $wp_local_package;

        $locale = isset( $wp_local_package ) && ! empty( $wp_local_package ) ? $wp_local_package : 'en_US';

        $url = sprintf(
            'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s',
            rawurlencode( $wp_version ),
            rawurlencode( $locale )
        );

        $response = wp_remote_get( $url, array(
            'timeout'   => 15,
            'sslverify' => true,
        ) );

        if ( is_wp_error( $response ) ) {
            $this->logger->warning(
                'core_verifier',
                sprintf( 'Failed to fetch core checksums: %s', $response->get_error_message() )
            );
            $this->checksums = array();
            return $this->checksums;
        }

        $code = wp_remote_retrieve_response_code( $response );
        if ( 200 !== $code ) {
            $this->logger->warning(
                'core_verifier',
                sprintf( 'Core checksums API returned HTTP %d', $code )
            );
            $this->checksums = array();
            return $this->checksums;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( ! is_array( $body ) || empty( $body['checksums'] ) ) {
            $this->logger->warning(
                'core_verifier',
                'Core checksums API returned invalid response'
            );
            $this->checksums = array();
            return $this->checksums;
        }

        $this->checksums = $body['checksums'];

        set_transient( self::CACHE_KEY, $this->checksums, self::CACHE_TTL );

        $this->logger->info(
            'core_verifier',
            sprintf( 'Fetched %d core checksums for WP %s (%s)', count( $this->checksums ), $wp_version, $locale )
        );

        return $this->checksums;
    }

    /**
     * Verify a single file against the official checksum.
     *
     * @param string $relative Relative path from ABSPATH (forward slashes).
     * @param string $abs_path Absolute path on disk.
     * @return array{
     *     status: string,
     *     expected_md5?: string,
     *     actual_md5?: string,
     * } Status: 'match'|'modified'|'missing'|'not_core'|'unavailable'
     */
    public function verify_file( $relative, $abs_path = '' ) {
        $checksums = $this->get_checksums();

        if ( empty( $checksums ) ) {
            return array( 'status' => 'unavailable' );
        }

        $relative = wp_normalize_path( $relative );

        if ( ! isset( $checksums[ $relative ] ) ) {
            return array( 'status' => 'not_core' );
        }

        if ( '' === $abs_path ) {
            $abs_path = ABSPATH . $relative;
        }

        if ( ! file_exists( $abs_path ) ) {
            return array(
                'status'       => 'missing',
                'expected_md5' => $checksums[ $relative ],
            );
        }

        $actual_md5 = md5_file( $abs_path );

        if ( $actual_md5 === $checksums[ $relative ] ) {
            return array( 'status' => 'match' );
        }

        return array(
            'status'       => 'modified',
            'expected_md5' => $checksums[ $relative ],
            'actual_md5'   => $actual_md5,
        );
    }

    /**
     * Perform a full core integrity verification.
     *
     * Checks every file in the official checksum list and also detects
     * unexpected files in wp-admin/ and wp-includes/ that shouldn't exist.
     *
     * @return array{
     *     verified: int,
     *     modified: array,
     *     missing: array,
     *     unexpected: array,
     *     checksums_available: bool,
     *     wp_version: string,
     * }
     */
    public function verify_core() {
        global $wp_version;

        $checksums = $this->get_checksums();

        $result = array(
            'verified'             => 0,
            'modified'             => array(),
            'missing'              => array(),
            'unexpected'           => array(),
            'checksums_available'  => ! empty( $checksums ),
            'wp_version'           => $wp_version,
        );

        if ( empty( $checksums ) ) {
            return $result;
        }

        // ── 1. Check every official core file ────────────────────
        foreach ( $checksums as $relative => $expected_md5 ) {
            $abs_path = ABSPATH . $relative;

            if ( ! file_exists( $abs_path ) ) {
                // Skip wp-config-sample.php — often intentionally removed.
                if ( 'wp-config-sample.php' === $relative ) {
                    continue;
                }
                $result['missing'][] = array(
                    'file_path'    => $relative,
                    'expected_md5' => $expected_md5,
                );
                continue;
            }

            $actual_md5 = md5_file( $abs_path );

            if ( $actual_md5 === $expected_md5 ) {
                $result['verified']++;
                continue;
            }

            // wp-config.php is always different (user-configured).
            if ( 'wp-config.php' === $relative ) {
                $result['verified']++;
                continue;
            }

            $result['modified'][] = array(
                'file_path'    => $relative,
                'expected_md5' => $expected_md5,
                'actual_md5'   => $actual_md5,
                'file_size'    => filesize( $abs_path ),
            );
        }

        // ── 2. Detect unexpected files in core directories ───────
        $core_dirs = array( 'wp-admin', 'wp-includes' );

        foreach ( $core_dirs as $dir ) {
            $abs_dir = ABSPATH . $dir;
            if ( ! is_dir( $abs_dir ) ) {
                continue;
            }

            $iterator = new \RecursiveDirectoryIterator(
                $abs_dir,
                \RecursiveDirectoryIterator::SKIP_DOTS
            );
            $flat = new \RecursiveIteratorIterator( $iterator, \RecursiveIteratorIterator::LEAVES_ONLY );

            foreach ( $flat as $file ) {
                if ( ! $file->isFile() ) {
                    continue;
                }
                $abs  = wp_normalize_path( $file->getPathname() );
                $rel  = wp_normalize_path( str_replace( wp_normalize_path( ABSPATH ), '', $abs ) );

                if ( ! isset( $checksums[ $rel ] ) ) {
                    $ext = strtolower( pathinfo( $rel, PATHINFO_EXTENSION ) );
                    $result['unexpected'][] = array(
                        'file_path' => $rel,
                        'extension' => $ext,
                        'file_size' => $file->getSize(),
                        'is_php'    => in_array( $ext, array( 'php', 'phtml', 'phar', 'php5', 'php7', 'pht' ), true ),
                    );
                }
            }
        }

        // ── 3. Check root-level unexpected PHP files ─────────────
        $root = rtrim( ABSPATH, '/\\' );
        $root_known = array_flip( array_keys( $checksums ) );
        $root_extra = array_flip( self::$known_root_files );

        $root_iter = new \DirectoryIterator( $root );
        foreach ( $root_iter as $item ) {
            if ( $item->isDot() || $item->isDir() ) {
                continue;
            }
            $name = $item->getFilename();
            $ext  = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );

            if ( ! in_array( $ext, array( 'php', 'phtml', 'phar', 'php5', 'php7' ), true ) ) {
                continue;
            }

            // Skip if it's in the official checksums or known root files.
            if ( isset( $root_known[ $name ] ) || isset( $root_extra[ $name ] ) ) {
                continue;
            }

            // Skip wp-config.php — always user-modified.
            if ( 'wp-config.php' === $name ) {
                continue;
            }

            $result['unexpected'][] = array(
                'file_path' => $name,
                'extension' => $ext,
                'file_size' => $item->getSize(),
                'is_php'    => true,
            );
        }

        $this->logger->info(
            'core_verifier',
            sprintf(
                'Core verification: %d verified, %d modified, %d missing, %d unexpected.',
                $result['verified'],
                count( $result['modified'] ),
                count( $result['missing'] ),
                count( $result['unexpected'] )
            )
        );

        return $result;
    }

    /**
     * Check if a relative path is an official core file.
     *
     * @param string $relative Relative path.
     * @return bool
     */
    public function is_core_file( $relative ) {
        $checksums = $this->get_checksums();
        return isset( $checksums[ wp_normalize_path( $relative ) ] );
    }

    /**
     * Get the expected MD5 for a core file, or empty if not a core file.
     *
     * @param string $relative Relative path.
     * @return string MD5 or empty.
     */
    public function get_expected_md5( $relative ) {
        $checksums = $this->get_checksums();
        $relative  = wp_normalize_path( $relative );
        return isset( $checksums[ $relative ] ) ? $checksums[ $relative ] : '';
    }
}
