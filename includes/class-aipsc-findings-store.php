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

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $existing = $wpdb->get_row(
                $wpdb->prepare(
                    "SELECT id, status FROM {$wpdb->prefix}aipsc_findings WHERE fingerprint = %s LIMIT 1",
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

            // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $stats['resolved'] = (int) $wpdb->query(
                $wpdb->prepare(
                    "UPDATE {$wpdb->prefix}aipsc_findings SET status = 'resolved', resolved_at = %s WHERE status = 'open' AND fingerprint NOT IN ({$placeholders})",
                    ...$values
                )
            );
            // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter
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

        // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter
        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}aipsc_findings WHERE {$where_clause} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d",
                ...$values
            )
        );
        // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter
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

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $by_status = $wpdb->get_results(
            "SELECT status, COUNT(*) as cnt FROM {$wpdb->prefix}aipsc_findings GROUP BY status",
            OBJECT_K
        );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $by_severity = $wpdb->get_results(
            "SELECT severity, COUNT(*) as cnt FROM {$wpdb->prefix}aipsc_findings WHERE status = 'open' GROUP BY severity",
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
     * File Scanner Sync
     * ------------------------------------------------------------- */

    /**
     * Synchronise file scanner results into persistent findings.
     *
     * Each file with risk_score >= 15 becomes one finding. Deduplication
     * is by file path fingerprint. Only source='file_scanner' findings
     * are auto-resolved, preserving audit-engine findings.
     *
     * @param array  $file_results Array of enriched file result arrays.
     *               Each must contain at minimum: file_path, risk_score,
     *               risk_level/classification, and optionally the full
     *               enriched data from signals_json.
     * @param string $job_id       Current job ID (stored in meta).
     * @return array{ inserted: int, updated: int, resolved: int, unchanged: int }
     */
    public function sync_file_findings( array $file_results, $job_id = '' ) {
        global $wpdb;

        $table = $wpdb->prefix . 'aipsc_findings';
        $now   = current_time( 'mysql', true );
        $stats = array( 'inserted' => 0, 'updated' => 0, 'resolved' => 0, 'unchanged' => 0 );

        $seen_fingerprints = array();

        foreach ( $file_results as $fr ) {
            $score = isset( $fr['risk_score'] ) ? (int) $fr['risk_score'] : 0;

            // Only persist actionable findings.
            if ( $score < 15 ) {
                continue;
            }

            $file_path   = isset( $fr['file_path'] ) ? $fr['file_path'] : '';
            $fingerprint = hash( 'sha256', 'file_scan:' . $file_path );

            $seen_fingerprints[] = $fingerprint;

            // Build the finding data from the file scan result.
            $data = $this->file_result_to_row( $fr, $fingerprint, $job_id, $now );

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $existing = $wpdb->get_row(
                $wpdb->prepare(
                    "SELECT id, status, severity, meta_json FROM {$wpdb->prefix}aipsc_findings WHERE fingerprint = %s LIMIT 1",
                    $fingerprint
                )
            );

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
                    'title'           => $data['title'],
                    'category'        => $data['category'],
                    'false_positive_likelihood' => $data['false_positive_likelihood'],
                );

                // Reopen resolved findings that reappear.
                if ( self::STATUS_RESOLVED === $existing->status ) {
                    $update['status']      = self::STATUS_OPEN;
                    $update['resolved_at'] = null;
                    $stats['updated']++;
                } else {
                    // Check if anything material changed.
                    $old_severity = $existing->severity;
                    if ( $old_severity !== $data['severity'] ) {
                        $stats['updated']++;
                    } else {
                        $stats['unchanged']++;
                    }
                }

                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->update( $table, $update, array( 'id' => $existing->id ) );
            } else {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
                $wpdb->insert( $table, $data );
                $stats['inserted']++;
            }
        }

        // Auto-resolve file_scanner findings NOT in current scan.
        // Scoped to source = 'file_scanner' to avoid touching audit-engine findings.
        if ( ! empty( $seen_fingerprints ) ) {
            $placeholders = implode( ',', array_fill( 0, count( $seen_fingerprints ), '%s' ) );
            $values       = array_merge( array( $now ), $seen_fingerprints );

            // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $stats['resolved'] = (int) $wpdb->query(
                $wpdb->prepare(
                    "UPDATE {$wpdb->prefix}aipsc_findings SET status = 'resolved', resolved_at = %s WHERE status = 'open' AND source = 'file_scanner' AND fingerprint NOT IN ({$placeholders})",
                    ...$values
                )
            );
            // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter
        } else {
            // No findings at all — resolve all open file_scanner findings.
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $stats['resolved'] = (int) $wpdb->query(
                $wpdb->prepare(
                    "UPDATE {$wpdb->prefix}aipsc_findings SET status = 'resolved', resolved_at = %s WHERE status = 'open' AND source = 'file_scanner'",
                    $now
                )
            );
        }

        return $stats;
    }

    /**
     * Get findings diff relative to a point in time.
     *
     * Returns findings grouped as new, resolved, or changed since
     * the given timestamp.
     *
     * @param string $since    Datetime string (UTC).
     * @param string $source   Optional source filter (e.g. 'file_scanner').
     * @return array{ new: array, resolved: array, risk_increased: array, risk_decreased: array }
     */
    public function diff_since( $since, $source = '' ) {
        global $wpdb;

        $source_clause = '';
        $values_new    = array( $since );
        $values_res    = array( $since );

        if ( '' !== $source ) {
            $source_clause = ' AND source = %s';
            $values_new[]  = $source;
            $values_res[]  = $source;
        }

        // New findings: first_seen >= $since.
        // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $new = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}aipsc_findings WHERE first_seen >= %s{$source_clause} ORDER BY severity DESC",
                ...$values_new
            )
        );
        // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter

        // Resolved findings: resolved_at >= $since.
        // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $resolved = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}aipsc_findings WHERE status = 'resolved' AND resolved_at >= %s{$source_clause} ORDER BY severity DESC",
                ...$values_res
            )
        );
        // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter

        return array(
            'new'      => $new,
            'resolved' => $resolved,
            'since'    => $since,
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

    /**
     * Convert a file scanner result array to a findings DB row.
     *
     * @param array  $fr          Enriched file result (decoded signals_json + file_path + risk_score).
     * @param string $fingerprint Pre-computed fingerprint.
     * @param string $job_id      Job ID for tracking.
     * @param string $now         Current datetime.
     * @return array
     */
    private function file_result_to_row( array $fr, $fingerprint, $job_id, $now ) {
        $file_path   = isset( $fr['file_path'] ) ? $fr['file_path'] : '';
        $risk_score  = isset( $fr['risk_score'] ) ? (int) $fr['risk_score'] : 0;
        $risk_level  = isset( $fr['risk_level'] ) ? $fr['risk_level'] : 'suspicious';
        $family      = isset( $fr['family'] ) ? $fr['family'] : '';
        $family_label = isset( $fr['family_label'] ) ? $fr['family_label'] : '';
        $family_confidence = isset( $fr['family_confidence'] ) ? $fr['family_confidence'] : 'low';
        $remediation = isset( $fr['remediation_hint'] ) ? $fr['remediation_hint'] : '';
        $matched_rules = isset( $fr['matched_rules'] ) ? $fr['matched_rules'] : array();
        $reasons     = isset( $fr['reasons'] ) ? $fr['reasons'] : array();
        $sha256      = isset( $fr['sha256'] ) ? $fr['sha256'] : '';
        $core_tampered    = ! empty( $fr['core_tampered'] );
        $unexpected_core  = ! empty( $fr['unexpected_in_core'] );
        $integrity_flags  = isset( $fr['integrity_flags'] ) ? $fr['integrity_flags'] : array();

        // ── Severity determination ──────────────────────────────
        // Core tampering always gets critical/high regardless of risk_level.
        if ( $core_tampered ) {
            $severity = 'critical';
        } elseif ( $unexpected_core ) {
            $severity = 'high';
        } else {
            $severity_map = array(
                'malicious'  => 'critical',
                'risky'      => 'high',
                'suspicious' => 'medium',
            );
            $severity = isset( $severity_map[ $risk_level ] ) ? $severity_map[ $risk_level ] : 'medium';
        }

        // FP likelihood — core findings verified against official checksums
        // have zero false positive likelihood.
        if ( $core_tampered ) {
            $fp_likelihood = 'none';
        } elseif ( $unexpected_core ) {
            $fp_likelihood = 'none';
        } else {
            $fp_map = array(
                'high'   => 'none',
                'medium' => 'low',
                'low'    => 'medium',
                'none'   => 'high',
            );
            $fp_likelihood = isset( $fp_map[ $family_confidence ] ) ? $fp_map[ $family_confidence ] : 'low';
        }

        // ── Title ───────────────────────────────────────────────
        if ( $core_tampered ) {
            $title = sprintf( 'Core file tampered — %s', $file_path );
        } elseif ( $unexpected_core ) {
            $title = sprintf( 'Unexpected file in core directory — %s', $file_path );
        } elseif ( $family_label ) {
            $title = sprintf( '%s — %s', $family_label, $file_path );
        } else {
            $title = sprintf( 'Suspicious file — %s', $file_path );
        }

        // Category from family or fallback.
        $category = ! empty( $family ) ? $family : 'file_scan';

        // ── Description ─────────────────────────────────────────
        if ( $core_tampered ) {
            $description = sprintf(
                'WordPress core file has been modified. Official checksum mismatch detected for %s. %s',
                $file_path,
                ! empty( $reasons ) ? implode( '; ', array_slice( $reasons, 0, 3 ) ) : ''
            );
        } elseif ( $unexpected_core ) {
            $description = sprintf(
                'File %s exists in a WordPress core directory but is not part of the official WordPress distribution.',
                $file_path
            );
        } elseif ( ! empty( $reasons ) ) {
            $description = implode( '; ', array_slice( $reasons, 0, 5 ) );
        } else {
            $description = sprintf( 'File scored %d/100 in risk analysis.', $risk_score );
        }

        // ── Why it matters ──────────────────────────────────────
        if ( $core_tampered ) {
            $why_it_matters = 'Modified core files are a strong indicator of compromise. Attackers often inject backdoors into core files to survive plugin updates and maintain persistent access.';
        } elseif ( $unexpected_core ) {
            $why_it_matters = 'Files in wp-admin/ or wp-includes/ that are not part of the official WordPress release are highly suspicious. Attackers plant files here because these directories are rarely inspected manually.';
        } elseif ( 'malicious' === $risk_level ) {
            $why_it_matters = 'This file shows strong indicators of malicious code and may actively compromise the site.';
        } elseif ( 'risky' === $risk_level ) {
            $why_it_matters = 'This file contains patterns commonly associated with backdoors or malware.';
        } else {
            $why_it_matters = 'This file contains suspicious patterns that warrant manual review.';
        }

        // ── Recommendation ──────────────────────────────────────
        if ( $core_tampered ) {
            $recommendation = $remediation ?: 'Reinstall WordPress core files immediately via wp-cli (wp core download --force) or dashboard one-click reinstall. Then scan for persistence backdoors.';
        } elseif ( $unexpected_core ) {
            $recommendation = $remediation ?: 'Delete this file after verifying it is not a legitimate server-level addition. Scan for additional injected files.';
        } else {
            $recommendation = $remediation ?: 'Review this file manually and delete if it is not part of a known plugin or theme.';
        }

        // Evidence: top matched rules.
        $evidence = ! empty( $matched_rules )
            ? implode( ', ', array_slice( $matched_rules, 0, 10 ) )
            : '';

        // Meta: everything useful for UI/MCP.
        $meta = array(
            'job_id'             => $job_id,
            'file_path'          => $file_path,
            'risk_score'         => $risk_score,
            'risk_level'         => $risk_level,
            'family'             => $family,
            'family_label'       => $family_label,
            'family_confidence'  => $family_confidence,
            'sha256'             => $sha256,
            'matched_rules'      => $matched_rules,
            'context_flags'      => isset( $fr['context_flags'] ) ? $fr['context_flags'] : array(),
            'integrity_flags'    => $integrity_flags,
            'layer_scores'       => isset( $fr['layer_scores'] ) ? $fr['layer_scores'] : array(),
            'is_new'             => ! empty( $fr['is_new'] ),
            'is_modified'        => ! empty( $fr['is_modified'] ),
            'core_tampered'      => $core_tampered,
            'unexpected_in_core' => $unexpected_core,
            'core_checksum'      => isset( $fr['core_checksum'] ) ? $fr['core_checksum'] : '',
        );

        return array(
            'finding_id'              => 'file_scan:' . $file_path,
            'fingerprint'             => $fingerprint,
            'title'                   => $title,
            'severity'                => $severity,
            'confidence'              => $core_tampered || $unexpected_core ? 'high' : ( $family_confidence ?: 'low' ),
            'category'                => $category,
            'status'                  => self::STATUS_OPEN,
            'source'                  => 'file_scanner',
            'description'             => $description,
            'why_it_matters'          => $why_it_matters,
            'recommendation'          => $recommendation,
            'evidence'                => $evidence,
            'meta_json'               => wp_json_encode( $meta ),
            'fixable'                 => $core_tampered ? 1 : 0,
            'false_positive_likelihood' => $fp_likelihood,
            'first_seen'              => $now,
            'last_seen'               => $now,
        );
    }
}
