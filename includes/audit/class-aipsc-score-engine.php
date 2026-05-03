<?php
/**
 * Weighted security score engine.
 *
 * Replaces the simple "start at 100, subtract penalties" model with a
 * multi-dimensional score that considers severity, category, exploitability,
 * and confidence.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Score_Engine
 */
class AIPSC_Score_Engine {

    /**
     * Severity weights (max impact per finding).
     */
    const SEVERITY_WEIGHTS = array(
        'critical' => 30,
        'high'     => 18,
        'medium'   => 10,
        'low'      => 4,
        'info'     => 0,
    );

    /**
     * Confidence multiplier (scales the weight).
     */
    const CONFIDENCE_MULTIPLIER = array(
        'high'   => 1.0,
        'medium' => 0.7,
        'low'    => 0.4,
    );

    /**
     * Category grouping for area-based risk posture.
     */
    const AREA_MAP = array(
        'core'            => 'software',
        'plugins'         => 'software',
        'themes'          => 'software',
        'users'           => 'access_control',
        'configuration'   => 'configuration',
        'server'          => 'infrastructure',
        'files'           => 'malware_surface',
        'vulnerabilities' => 'vulnerability_exposure',
    );

    /**
     * Compute the full score breakdown from an array of AIPSC_Audit_Check_Result.
     *
     * @param AIPSC_Audit_Check_Result[] $results    All findings.
     * @param array                      $dismissed  Map of dismissed IDs.
     * @return array {
     *     @type int   $overall_score     0-100 composite score.
     *     @type array $risk_posture      Per-area scores { area_name => { score, findings_count, max_severity } }.
     *     @type array $severity_counts   { critical => n, high => n, medium => n, low => n, info => n }.
     *     @type array $category_counts   { category_name => n, ... }.
     *     @type float $total_penalty     Raw penalty before capping.
     *     @type int   $active_findings   Number of non-dismissed findings.
     * }
     */
    public static function compute( array $results, array $dismissed = array() ): array {
        $severity_counts  = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0 );
        $category_counts  = array();
        $area_penalties   = array();
        $area_max_sev     = array();
        $area_counts      = array();
        $total_penalty    = 0.0;
        $active_findings  = 0;

        // Initialize areas.
        foreach ( array_unique( array_values( self::AREA_MAP ) ) as $area ) {
            $area_penalties[ $area ] = 0.0;
            $area_max_sev[ $area ]   = 'info';
            $area_counts[ $area ]    = 0;
        }
        // Fallback area for unknown categories.
        $area_penalties['other'] = 0.0;
        $area_max_sev['other']   = 'info';
        $area_counts['other']    = 0;

        foreach ( $results as $result ) {
            $id       = $result->get_id();
            $severity = $result->get_severity();

            // Skip dismissed.
            if ( isset( $dismissed[ $id ] ) ) {
                continue;
            }

            $active_findings++;

            // Severity counts.
            if ( isset( $severity_counts[ $severity ] ) ) {
                $severity_counts[ $severity ]++;
            }

            // Category counts.
            $category = $result->get_category();
            if ( ! isset( $category_counts[ $category ] ) ) {
                $category_counts[ $category ] = 0;
            }
            $category_counts[ $category ]++;

            // Weight calculation.
            $base_weight = self::SEVERITY_WEIGHTS[ $severity ] ?? 0;
            $confidence  = $result->get_confidence();
            $multiplier  = self::CONFIDENCE_MULTIPLIER[ $confidence ] ?? 1.0;
            $penalty     = $base_weight * $multiplier;

            $total_penalty += $penalty;

            // Area accumulation.
            $area = self::AREA_MAP[ $category ] ?? 'other';
            $area_penalties[ $area ] += $penalty;
            $area_counts[ $area ]++;

            // Track max severity per area.
            if ( self::severity_rank( $severity ) > self::severity_rank( $area_max_sev[ $area ] ) ) {
                $area_max_sev[ $area ] = $severity;
            }
        }

        // Overall score: start at 100, subtract penalty, capped [0, 100].
        // Apply diminishing returns for extreme penalty totals so the score
        // doesn't hit 0 with just a handful of medium findings.
        $overall_score = self::penalty_to_score( $total_penalty );

        // Per-area scores (each area is 0-100).
        $risk_posture = array();
        foreach ( $area_penalties as $area => $pen ) {
            if ( 0 === $area_counts[ $area ] ) {
                continue; // Skip empty areas.
            }
            $risk_posture[ $area ] = array(
                'score'          => self::penalty_to_score( $pen ),
                'findings_count' => $area_counts[ $area ],
                'max_severity'   => $area_max_sev[ $area ],
            );
        }

        return array(
            'overall_score'   => $overall_score,
            'risk_posture'    => $risk_posture,
            'severity_counts' => $severity_counts,
            'category_counts' => $category_counts,
            'total_penalty'   => round( $total_penalty, 2 ),
            'active_findings' => $active_findings,
        );
    }

    /**
     * Convenience: compute from legacy issue arrays.
     *
     * @param array $issues   Legacy issue arrays.
     * @param array $dismissed Dismissed IDs.
     * @return array Same structure as compute().
     */
    public static function compute_from_legacy( array $issues, array $dismissed = array() ): array {
        $results = array();
        foreach ( $issues as $issue ) {
            $results[] = AIPSC_Audit_Check_Result::from_legacy_array( $issue );
        }
        return self::compute( $results, $dismissed );
    }

    /**
     * Convert a raw penalty value to a 0-100 score using a logarithmic curve.
     *
     * This gives diminishing returns: a penalty of 30 drops the score to ~73,
     * 60 → ~54, 100 → ~38, 200 → ~17.
     *
     * @param float $penalty Raw penalty.
     * @return int Score 0-100.
     */
    private static function penalty_to_score( float $penalty ): int {
        if ( $penalty <= 0.0 ) {
            return 100;
        }

        // Tuning constant: higher k = slower decay.
        $k     = 120.0;
        $score = 100.0 * ( $k / ( $k + $penalty ) );

        return max( 0, min( 100, (int) round( $score ) ) );
    }

    /**
     * Numeric rank for severity levels (higher = worse).
     *
     * @param string $severity Severity string.
     * @return int
     */
    private static function severity_rank( string $severity ): int {
        $ranks = array(
            'info'     => 0,
            'low'      => 1,
            'medium'   => 2,
            'high'     => 3,
            'critical' => 4,
        );
        return $ranks[ $severity ] ?? 0;
    }

    /**
     * Get a human-readable label for a score.
     *
     * @param int $score 0-100.
     * @return string
     */
    public static function get_score_label( int $score ): string {
        if ( $score >= 90 ) {
            return __( 'Excellent', 'aipatch-security-scanner' );
        }
        if ( $score >= 70 ) {
            return __( 'Good', 'aipatch-security-scanner' );
        }
        if ( $score >= 50 ) {
            return __( 'Needs Attention', 'aipatch-security-scanner' );
        }
        if ( $score >= 30 ) {
            return __( 'At Risk', 'aipatch-security-scanner' );
        }
        return __( 'Critical', 'aipatch-security-scanner' );
    }

    /**
     * Get CSS class for a score.
     *
     * @param int $score 0-100.
     * @return string
     */
    public static function get_score_class( int $score ): string {
        if ( $score >= 90 ) {
            return 'excellent';
        }
        if ( $score >= 70 ) {
            return 'good';
        }
        if ( $score >= 50 ) {
            return 'warning';
        }
        return 'danger';
    }
}
