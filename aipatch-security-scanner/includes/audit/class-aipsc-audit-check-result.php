<?php
/**
 * Audit Check Result (Finding model).
 *
 * Unified, immutable value object representing a single security finding.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Audit_Check_Result
 *
 * Immutable value object for a single security finding.
 */
class AIPSC_Audit_Check_Result {

    /**
     * Allowed severity levels.
     */
    const SEVERITY_CRITICAL = 'critical';
    const SEVERITY_HIGH     = 'high';
    const SEVERITY_MEDIUM   = 'medium';
    const SEVERITY_LOW      = 'low';
    const SEVERITY_INFO     = 'info';

    /**
     * Allowed statuses.
     */
    const STATUS_OPEN      = 'open';
    const STATUS_PASS      = 'pass';
    const STATUS_DISMISSED  = 'dismissed';
    const STATUS_FIXED      = 'fixed';
    const STATUS_ACCEPTED   = 'accepted';

    /**
     * Confidence levels.
     */
    const CONFIDENCE_HIGH   = 'high';
    const CONFIDENCE_MEDIUM = 'medium';
    const CONFIDENCE_LOW    = 'low';

    /**
     * Internal data array.
     *
     * @var array
     */
    private $data;

    /**
     * Constructor — builds an immutable result.
     *
     * @param array $args {
     *     Required and optional arguments.
     *
     *     @type string $id                       Unique finding identifier.
     *     @type string $title                     Human-readable title.
     *     @type string $severity                  One of the SEVERITY_* constants.
     *     @type string $confidence                One of the CONFIDENCE_* constants.
     *     @type string $category                  Categorisation string.
     *     @type string $status                    One of the STATUS_* constants.
     *     @type string $description               What was found.
     *     @type string $why_it_matters            Security explanation.
     *     @type string $recommendation            How to fix.
     *     @type string $evidence                  Raw evidence string.
     *     @type string $source                    Origin module (e.g. scanner, file_scanner, vuln_intel).
     *     @type string $fingerprint               Stable hash for dedup/tracking.
     *     @type bool   $fixable                   Whether automatic remediation is available.
     *     @type string $false_positive_likelihood  none|low|medium|high.
     *     @type bool   $dismissible               Whether the user can dismiss this finding.
     *     @type array  $meta                      Arbitrary extra data (key-value).
     * }
     */
    public function __construct( array $args ) {
        $defaults = array(
            'id'                       => '',
            'title'                    => '',
            'severity'                 => self::SEVERITY_INFO,
            'confidence'               => self::CONFIDENCE_HIGH,
            'category'                 => 'general',
            'status'                   => self::STATUS_OPEN,
            'description'              => '',
            'why_it_matters'           => '',
            'recommendation'           => '',
            'evidence'                 => '',
            'source'                   => 'scanner',
            'fingerprint'              => '',
            'fixable'                  => false,
            'false_positive_likelihood' => 'none',
            'dismissible'              => true,
            'meta'                     => array(),
        );

        $this->data = wp_parse_args( $args, $defaults );

        // Auto-generate fingerprint if not provided.
        if ( empty( $this->data['fingerprint'] ) ) {
            $this->data['fingerprint'] = md5( $this->data['id'] . ':' . $this->data['evidence'] );
        }
    }

    /**
     * Magic getter.
     *
     * @param string $name Property name.
     * @return mixed
     */
    public function __get( $name ) {
        return $this->data[ $name ] ?? null;
    }

    /**
     * Check if a property exists.
     *
     * @param string $name Property name.
     * @return bool
     */
    public function __isset( $name ) {
        return isset( $this->data[ $name ] );
    }

    /**
     * Get the finding ID.
     *
     * @return string
     */
    public function get_id(): string {
        return $this->data['id'];
    }

    /**
     * Get severity.
     *
     * @return string
     */
    public function get_severity(): string {
        return $this->data['severity'];
    }

    /**
     * Get confidence.
     *
     * @return string
     */
    public function get_confidence(): string {
        return $this->data['confidence'];
    }

    /**
     * Get category.
     *
     * @return string
     */
    public function get_category(): string {
        return $this->data['category'];
    }

    /**
     * Get status.
     *
     * @return string
     */
    public function get_status(): string {
        return $this->data['status'];
    }

    /**
     * Get title.
     *
     * @return string
     */
    public function get_title(): string {
        return $this->data['title'];
    }

    /**
     * Get fingerprint.
     *
     * @return string
     */
    public function get_fingerprint(): string {
        return $this->data['fingerprint'];
    }

    /**
     * Get source.
     *
     * @return string
     */
    public function get_source(): string {
        return $this->data['source'];
    }

    /**
     * Get description.
     *
     * @return string
     */
    public function get_description(): string {
        return $this->data['description'];
    }

    /**
     * Get why it matters.
     *
     * @return string
     */
    public function get_why_it_matters(): string {
        return $this->data['why_it_matters'];
    }

    /**
     * Get recommendation.
     *
     * @return string
     */
    public function get_recommendation(): string {
        return $this->data['recommendation'];
    }

    /**
     * Get evidence.
     *
     * @return string
     */
    public function get_evidence(): string {
        return $this->data['evidence'];
    }

    /**
     * Get meta data.
     *
     * @return array
     */
    public function get_meta(): array {
        return $this->data['meta'];
    }

    /**
     * Whether automatic fix is available.
     *
     * @return bool
     */
    public function is_fixable(): bool {
        return (bool) $this->data['fixable'];
    }

    /**
     * Get false positive likelihood.
     *
     * @return string
     */
    public function get_false_positive_likelihood(): string {
        return $this->data['false_positive_likelihood'];
    }

    /**
     * Return the numeric severity weight for score calculations.
     *
     * @return int
     */
    public function get_severity_weight(): int {
        $weights = array(
            self::SEVERITY_CRITICAL => 25,
            self::SEVERITY_HIGH     => 15,
            self::SEVERITY_MEDIUM   => 10,
            self::SEVERITY_LOW      => 5,
            self::SEVERITY_INFO     => 0,
        );

        return $weights[ $this->data['severity'] ] ?? 0;
    }

    /**
     * Convert to the legacy issue array format for backward compatibility.
     *
     * @return array
     */
    public function to_legacy_array(): array {
        return array(
            'id'              => $this->data['id'],
            'title'           => $this->data['title'],
            'description'     => $this->data['description'],
            'severity'        => $this->data['severity'],
            'category'        => $this->data['category'],
            'why_it_matters'  => $this->data['why_it_matters'],
            'recommendation'  => $this->data['recommendation'],
            'dismissible'     => $this->data['dismissible'],
            'evidence'        => $this->data['evidence'],
            'source'          => $this->data['source'],
            'fingerprint'     => $this->data['fingerprint'],
        );
    }

    /**
     * Convert to full array (new format).
     *
     * @return array
     */
    public function to_array(): array {
        return $this->data;
    }

    /**
     * Create from a legacy issue array.
     *
     * @param array $issue Legacy issue array.
     * @return self
     */
    public static function from_legacy_array( array $issue ): self {
        return new self( array(
            'id'              => $issue['id'] ?? '',
            'title'           => $issue['title'] ?? '',
            'severity'        => $issue['severity'] ?? self::SEVERITY_INFO,
            'confidence'      => self::CONFIDENCE_HIGH,
            'category'        => $issue['category'] ?? 'general',
            'status'          => self::STATUS_OPEN,
            'description'     => $issue['description'] ?? '',
            'why_it_matters'  => $issue['why_it_matters'] ?? '',
            'recommendation'  => $issue['recommendation'] ?? '',
            'evidence'        => $issue['evidence'] ?? '',
            'source'          => $issue['source'] ?? 'scanner',
            'fingerprint'     => $issue['fingerprint'] ?? '',
            'fixable'         => false,
            'dismissible'     => $issue['dismissible'] ?? true,
            'false_positive_likelihood' => 'none',
        ) );
    }
}
