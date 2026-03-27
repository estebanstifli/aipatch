<?php
/**
 * Dashboard module – aggregates security data for the main admin view.
 *
 * @package PatchWatch
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class PWW_Dashboard
 */
class PWW_Dashboard {

    /**
     * @var PWW_Scanner
     */
    private $scanner;

    /**
     * @var PWW_Vulnerabilities
     */
    private $vulnerabilities;

    /**
     * Constructor.
     *
     * @param PWW_Scanner         $scanner         Scanner module.
     * @param PWW_Vulnerabilities $vulnerabilities Vulnerabilities module.
     */
    public function __construct( PWW_Scanner $scanner, PWW_Vulnerabilities $vulnerabilities ) {
        $this->scanner         = $scanner;
        $this->vulnerabilities = $vulnerabilities;
    }

    /**
     * Get complete dashboard data.
     *
     * @return array
     */
    public function get_dashboard_data() {
        $scan_results = $this->scanner->get_last_results();
        $summary      = $this->scanner->get_summary();
        $dismissed    = PWW_Utils::get_option( 'dismissed', array() );

        $score  = $scan_results ? $scan_results['score'] : 0;
        $issues = $scan_results ? $scan_results['issues'] : array();

        // Separate active and dismissed issues.
        $active_issues    = array();
        $dismissed_issues = array();

        foreach ( $issues as $issue ) {
            if ( isset( $dismissed[ $issue['id'] ] ) ) {
                $dismissed_issues[] = $issue;
            } else {
                $active_issues[] = $issue;
            }
        }

        // Sort by severity weight (critical first).
        usort( $active_issues, function ( $a, $b ) {
            return PWW_Utils::severity_weight( $b['severity'] ) - PWW_Utils::severity_weight( $a['severity'] );
        } );

        // Prioritized recommendations from active issues.
        $recommendations = array_map( function ( $issue ) {
            return array(
                'id'             => $issue['id'],
                'title'          => $issue['title'],
                'severity'       => $issue['severity'],
                'recommendation' => $issue['recommendation'],
                'dismissible'    => $issue['dismissible'],
            );
        }, $active_issues );

        return array(
            'score'            => $score,
            'score_label'      => $this->get_score_label( $score ),
            'score_class'      => $this->get_score_class( $score ),
            'summary'          => $summary,
            'issues'           => $active_issues,
            'dismissed_issues' => $dismissed_issues,
            'recommendations'  => $recommendations,
            'last_scan'        => PWW_Utils::get_option( 'last_scan', 0 ),
            'next_scan'        => PWW_Cron::get_next_scan(),
            'has_scan'         => ! empty( $scan_results ),
        );
    }

    /**
     * Get human-readable score label.
     *
     * @param int $score Security score.
     * @return string
     */
    private function get_score_label( $score ) {
        if ( $score >= 90 ) {
            return __( 'Excellent', 'patchwatch' );
        }
        if ( $score >= 70 ) {
            return __( 'Good', 'patchwatch' );
        }
        if ( $score >= 50 ) {
            return __( 'Needs Attention', 'patchwatch' );
        }
        if ( $score >= 30 ) {
            return __( 'At Risk', 'patchwatch' );
        }
        return __( 'Critical', 'patchwatch' );
    }

    /**
     * Get CSS class for score display.
     *
     * @param int $score Security score.
     * @return string
     */
    private function get_score_class( $score ) {
        if ( $score >= 90 ) {
            return 'aipatch-score-excellent';
        }
        if ( $score >= 70 ) {
            return 'aipatch-score-good';
        }
        if ( $score >= 50 ) {
            return 'aipatch-score-warning';
        }
        return 'aipatch-score-danger';
    }

    /**
     * Dismiss a risk issue.
     *
     * @param string $issue_id Issue identifier.
     * @return bool
     */
    public function dismiss_issue( $issue_id ) {
        $dismissed = PWW_Utils::get_option( 'dismissed', array() );
        $dismissed[ sanitize_key( $issue_id ) ] = array(
            'dismissed_at' => time(),
            'dismissed_by' => get_current_user_id(),
        );
        return PWW_Utils::update_option( 'dismissed', $dismissed );
    }

    /**
     * Restore a dismissed issue.
     *
     * @param string $issue_id Issue identifier.
     * @return bool
     */
    public function restore_issue( $issue_id ) {
        $dismissed = PWW_Utils::get_option( 'dismissed', array() );
        unset( $dismissed[ sanitize_key( $issue_id ) ] );
        return PWW_Utils::update_option( 'dismissed', $dismissed );
    }
}
