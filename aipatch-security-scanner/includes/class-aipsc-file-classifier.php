<?php
/**
 * File Classifier.
 *
 * Takes heuristic signals for a single file and produces a risk score
 * (0–100) plus a classification label.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_File_Classifier
 */
class AIPSC_File_Classifier {

    const CLASS_CLEAN      = 'clean';
    const CLASS_SUSPICIOUS = 'suspicious';
    const CLASS_RISKY      = 'risky';
    const CLASS_MALICIOUS  = 'malicious';

    /**
     * Classify a file based on its heuristic signals.
     *
     * @param array  $signals Array of signal arrays from AIPSC_File_Heuristics::analyse().
     * @param string $path    Relative file path (affects contextual adjustments).
     * @return array{
     *     risk_score: int,
     *     classification: string,
     *     top_signal: string,
     *     signal_count: int,
     * }
     */
    public static function classify( array $signals, $path = '' ) {
        if ( empty( $signals ) ) {
            return array(
                'risk_score'      => 0,
                'classification'  => self::CLASS_CLEAN,
                'top_signal'      => '',
                'signal_count'    => 0,
            );
        }

        // Base score: sum of weights.
        $total_weight = 0;
        $max_weight   = 0;
        $top_signal   = '';

        foreach ( $signals as $signal ) {
            $w = (int) $signal['weight'];
            $total_weight += $w;
            if ( $w > $max_weight ) {
                $max_weight = $w;
                $top_signal = $signal['label'];
            }
        }

        // Logarithmic scaling so many low signals don't instantly hit 100.
        // score = 100 * (total / (total + k)) where k = 25
        $k    = 25;
        $score = (int) round( 100 * ( $total_weight / ( $total_weight + $k ) ) );

        // Contextual adjustments.
        $score = self::adjust_for_context( $score, $signals, $path );

        $score = max( 0, min( 100, $score ) );

        return array(
            'risk_score'     => $score,
            'classification' => self::label( $score ),
            'top_signal'     => $top_signal,
            'signal_count'   => count( $signals ),
        );
    }

    /**
     * Map score to classification label.
     *
     * @param int $score 0–100.
     * @return string
     */
    public static function label( $score ) {
        if ( $score >= 75 ) {
            return self::CLASS_MALICIOUS;
        }
        if ( $score >= 45 ) {
            return self::CLASS_RISKY;
        }
        if ( $score >= 15 ) {
            return self::CLASS_SUSPICIOUS;
        }
        return self::CLASS_CLEAN;
    }

    /**
     * Adjust risk score based on file path context.
     *
     * @param int    $score   Current score.
     * @param array  $signals Signals array.
     * @param string $path    Relative file path.
     * @return int
     */
    private static function adjust_for_context( $score, array $signals, $path ) {
        // PHP in uploads directory is inherently more suspicious.
        if ( false !== strpos( $path, '/uploads/' ) ) {
            $score = (int) round( $score * 1.3 );
        }

        // Files in wp-includes or wp-admin that aren't part of core are suspicious.
        if ( preg_match( '#^wp-(includes|admin)/#', $path ) ) {
            $score = (int) round( $score * 1.15 );
        }

        // Reduce score for files in a known dev tool directory.
        if ( preg_match( '#/(vendor|node_modules|tests?)/#i', $path ) ) {
            $score = (int) round( $score * 0.6 );
        }

        return $score;
    }
}
