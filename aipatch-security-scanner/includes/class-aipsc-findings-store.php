<?php
/**
 * Findings Store.
 *
 * Persists audit findings to the database with automatic deduplication
 * via fingerprint. Provides query, dismiss, resolve, and statistics.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Findings_Store
 */
class AIPSC_Findings_Store {

    const STATUS_OPEN      = 'open';
    const STATUS_DISMISSED = 'dismissed';
    const STATUS_RESOLVED  = 'resolved';

    /**
     * Synchronise an array of AIPSC_Audit_Check_Result objects into the DB.
     *
     * New fingerprints are inserted; existing ones get last_seen updated
     * and status reopened if previously resolved.
     *
     * @param AIPSC_Audit_Check_Result[] $results Results from the audit engine.
     * @return array{ inserted: int, updated: int, resolved: int }
     */
    public function sync( array $results ) {
        global $wpdb;

        $table = $wpdb->prefix . 'aipsc_findings';
        $now   = current_time( 'mysql', true );
        $stats = array( 'inserted' => 0, 'updated' => 0, 'resolved' => 0 );

        $seen_fingerprints = array();

        foreach ( $results as $result ) {
            if ( ! $result instanceof AIPSC_Audit_Check_Result ) {
                continue;
            }

            // Only persist actionable findings.
            if ( AIPSC_Audit_Check_Result::STATUS_PASS === $result->get_status() ) {
                continue;
            }

            $fp = $result->get_fingerprint();
            $seen_fingerprints[] = $fp;

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $existing = $wpdb->get_row(
                $wpdb->prepare(
                    "SELECT id, status FROM {$table} WHERE fingerprint = %s LIMIT 1",
                    $fp
                )
            );

            $data = $this->result_to_row( $result, $now );

            if ( $existing ) {
                $update = array(
                    'last_seen'       => $now,
                    'severity'        => $data['severity'],
                    'confidence'      => $data['confidence'],
                    'description'     => $data['description'],
                    'why_it_matters'  => $data['why_it_matters'],
                    'recommendation'  => $data['recommendation'],
                    'evidence'        => $data['evidence'],
                    'meta_json'       => $data['meta_json'],
                    'fixable'         => $data['fixable'],
                    'false_positive_likelihood' => $data['false_positive_likelihood'],
                );

                // Reopen resolved findings that reappear.
                if ( self::STATUS_RESOLVED === $existing->status ) {
                    $update['status']      = self::STATUS_OPEN;
                    $update['resolved_at'] = null;
                }

                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->update( $table, $update, array( 'id' => $existing->id ) );
                $stats['updated']++;
            } else {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
                $wpdb->insert( $table, $data );
                $stats['inserted']++;
            }
        }

        // Auto-resolve open findings that were NOT in this scan.
        if ( ! empty( $seen_fingerprints ) ) {
            $placeholders = implode( ',', array_fill( 0, count( $seen_fingerprints ), '%s' ) );
            $values       = array_merge( array( $now ), $seen_fingerprints );

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $stats['resolved'] = (int) $wpdb->query(
                $wpdb->prepare(
                    "UPDATE {$table} SET status = 'resolved', resolved_at = %s WHERE status = 'open' AND fingerprint NOT IN ({$placeholders})",
                    $values
                )
            );
        }

        return $stats;
    }

    /**
     * Query findings.
     *
     * @param array $args {
     *     @type string $status   Filter by status.
     *     @type string $severity Filter by severity.
     *     @type string $category Filter by category.
     *     @type string $source   Filter by source.
     *     @type int    $limit    Max rows.
     *     @type int    $offset   Offset.
     *     @type string $orderby  Column.
     *     @type string $order    ASC|DESC.
     * }
     * @return array
     */
    public function query( array $args = array() ) {
        global $wpdb;

        $defaults = array(
            'status'   => '',
            'severity' => '',
            'category' => '',
            'source'   => '',
            'limit'    => 100,
            'offset'   => 0,
            'orderby'  => 'last_seen',
            'order'    => 'DESC',
        );
        $args = wp_parse_args( $args, $defaults );

        $where  = array( '1=1' );
        $values = array();

        foreach ( array( 'status', 'severity', 'category', 'source' ) as $filter ) {
            if ( ! empty( $args[ $filter ] ) ) {
                $where[]  = "{$filter} = %s";
                $values[] = sanitize_text_field( $args[ $filter ] );
            }
        }

        $allowed_orderby = array( 'last_seen', 'first_seen', 'severity', 'category', 'status' );
        $orderby = in_array( $args['orderby'], $allowed_orderby, true ) ? $args['orderby'] : 'last_seen';
        $order   = 'ASC' === strtoupper( $args['order'] ) ? 'ASC' : 'DESC';

        $where_clause = implode( ' AND ', $where );
        $values[]     = absint( $args['limit'] );
        $values[]     = absint( $args['offset'] );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}aipsc_findings WHERE {$where_clause} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d",
                $values
            )
        );
    }

    /**
     * Get a single finding by fingerprint.
     *
     * @param string $fingerprint SHA-256 fingerprint.
     * @return object|null
     */
    public function get_by_fingerprint( $fingerprint ) {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}aipsc_findings WHERE fingerprint = %s LIMIT 1",
                $fingerprint
            )
        );
    }

    /**
     * Dismiss a finding (mark as accepted risk).
     *
     * @param string $fingerprint SHA-256 fingerprint.
     * @return bool
     */
    public function dismiss( $fingerprint ) {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return (bool) $wpdb->update(
            $wpdb->prefix . 'aipsc_findings',
            array( 'status' => self::STATUS_DISMISSED ),
            array( 'fingerprint' => $fingerprint )
        );
    }

    /**
     * Resolve a finding.
     *
     * @param string $fingerprint SHA-256 fingerprint.
     * @return bool
     */
    public function resolve( $fingerprint ) {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return (bool) $wpdb->update(
            $wpdb->prefix . 'aipsc_findings',
            array(
                'status'      => self::STATUS_RESOLVED,
                'resolved_at' => current_time( 'mysql', true ),
            ),
            array( 'fingerprint' => $fingerprint )
        );
    }

    /**
     * Summary statistics for the findings table.
     *
     * @return array
     */
    public function stats() {
        global $wpdb;

        $table = $wpdb->prefix . 'aipsc_findings';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $by_status = $wpdb->get_results(
            "SELECT status, COUNT(*) as cnt FROM {$table} GROUP BY status",
            OBJECT_K
        );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $by_severity = $wpdb->get_results(
            "SELECT severity, COUNT(*) as cnt FROM {$table} WHERE status = 'open' GROUP BY severity",
            OBJECT_K
        );

        return array(
            'total_open'      => isset( $by_status['open'] ) ? (int) $by_status['open']->cnt : 0,
            'total_dismissed'  => isset( $by_status['dismissed'] ) ? (int) $by_status['dismissed']->cnt : 0,
            'total_resolved'   => isset( $by_status['resolved'] ) ? (int) $by_status['resolved']->cnt : 0,
            'open_by_severity' => array(
                'critical' => isset( $by_severity['critical'] ) ? (int) $by_severity['critical']->cnt : 0,
                'high'     => isset( $by_severity['high'] ) ? (int) $by_severity['high']->cnt : 0,
                'medium'   => isset( $by_severity['medium'] ) ? (int) $by_severity['medium']->cnt : 0,
                'low'      => isset( $by_severity['low'] ) ? (int) $by_severity['low']->cnt : 0,
                'info'     => isset( $by_severity['info'] ) ? (int) $by_severity['info']->cnt : 0,
            ),
        );
    }

    /**
     * Purge resolved findings older than given days.
     *
     * @param int $days Threshold.
     * @return int      Rows deleted.
     */
    public function purge_resolved( $days = 90 ) {
        global $wpdb;

        $cutoff = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return (int) $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->prefix}aipsc_findings WHERE status = 'resolved' AND resolved_at < %s",
                $cutoff
            )
        );
    }

    /* ---------------------------------------------------------------
     * Internal
     * ------------------------------------------------------------- */

    /**
     * Convert an audit result object to a DB row array.
     *
     * @param AIPSC_Audit_Check_Result $result Result.
     * @param string                   $now    Current datetime.
     * @return array
     */
    private function result_to_row( AIPSC_Audit_Check_Result $result, $now ) {
        return array(
            'finding_id'              => $result->get_id(),
            'fingerprint'             => $result->get_fingerprint(),
            'title'                   => $result->get_title(),
            'severity'                => $result->get_severity(),
            'confidence'              => $result->get_confidence(),
            'category'                => $result->get_category(),
            'status'                  => self::STATUS_OPEN,
            'source'                  => $result->get_source(),
            'description'             => $result->get_description(),
            'why_it_matters'          => $result->get_why_it_matters(),
            'recommendation'          => $result->get_recommendation(),
            'evidence'                => $result->get_evidence(),
            'meta_json'               => wp_json_encode( $result->get_meta() ),
            'fixable'                 => $result->is_fixable() ? 1 : 0,
            'false_positive_likelihood' => $result->get_false_positive_likelihood(),
            'first_seen'              => $now,
            'last_seen'               => $now,
        );
    }
}
