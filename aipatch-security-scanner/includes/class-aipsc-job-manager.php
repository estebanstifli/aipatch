<?php
/**
 * Persistent Job Manager.
 *
 * Provides database-backed job lifecycle management for long-running
 * operations (file scans, baseline builds, vulnerability fetches).
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Job_Manager
 */
class AIPSC_Job_Manager {

    /* Job statuses */
    const STATUS_PENDING    = 'pending';
    const STATUS_RUNNING    = 'running';
    const STATUS_COMPLETED  = 'completed';
    const STATUS_FAILED     = 'failed';
    const STATUS_CANCELLED  = 'cancelled';

    /**
     * Create a new job.
     *
     * @param string $job_type  Identifier for the kind of job (e.g. 'file_scan').
     * @param array  $input     Arbitrary input data stored as JSON.
     * @param int    $total     Expected total items (0 if unknown).
     * @return string|false     The job_id or false on failure.
     */
    public function create( $job_type, array $input = array(), $total = 0 ) {
        global $wpdb;

        $job_id = wp_generate_uuid4();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $inserted = $wpdb->insert(
            $wpdb->prefix . 'aipsc_jobs',
            array(
                'job_id'          => $job_id,
                'job_type'        => sanitize_key( $job_type ),
                'status'          => self::STATUS_PENDING,
                'progress'        => 0,
                'total_items'     => absint( $total ),
                'completed_items' => 0,
                'input_json'      => wp_json_encode( $input ),
                'created_at'      => current_time( 'mysql', true ),
            ),
            array( '%s', '%s', '%s', '%d', '%d', '%d', '%s', '%s' )
        );

        return $inserted ? $job_id : false;
    }

    /**
     * Retrieve a job by its UUID.
     *
     * @param string $job_id UUID.
     * @return object|null   Row object or null.
     */
    public function get( $job_id ) {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}aipsc_jobs WHERE job_id = %s LIMIT 1",
                $job_id
            )
        );
    }

    /**
     * Mark a job as running.
     *
     * @param string $job_id UUID.
     * @return bool
     */
    public function start( $job_id ) {
        return $this->update_status( $job_id, self::STATUS_RUNNING, array(
            'started_at' => current_time( 'mysql', true ),
        ) );
    }

    /**
     * Update progress counters.
     *
     * @param string $job_id          UUID.
     * @param int    $completed_items Number of items processed so far.
     * @param int    $total_items     Updated total (0 = keep existing).
     * @return bool
     */
    public function progress( $job_id, $completed_items, $total_items = 0 ) {
        global $wpdb;

        $data   = array(
            'completed_items' => absint( $completed_items ),
        );
        $format = array( '%d' );

        if ( $total_items > 0 ) {
            $data['total_items'] = absint( $total_items );
            $format[]            = '%d';
        }

        // Compute progress percentage.
        $total = $total_items > 0 ? $total_items : null;
        if ( null === $total ) {
            $job = $this->get( $job_id );
            $total = $job ? (int) $job->total_items : 0;
        }
        $data['progress'] = $total > 0 ? min( 100, (int) round( ( $completed_items / $total ) * 100 ) ) : 0;
        $format[]         = '%d';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return (bool) $wpdb->update(
            $wpdb->prefix . 'aipsc_jobs',
            $data,
            array( 'job_id' => $job_id ),
            $format,
            array( '%s' )
        );
    }

    /**
     * Mark a job as completed and store its result.
     *
     * @param string $job_id UUID.
     * @param mixed  $result Arbitrary result data (stored as JSON).
     * @return bool
     */
    public function complete( $job_id, $result = null ) {
        return $this->update_status( $job_id, self::STATUS_COMPLETED, array(
            'progress'     => 100,
            'result_json'  => null !== $result ? wp_json_encode( $result ) : null,
            'completed_at' => current_time( 'mysql', true ),
        ) );
    }

    /**
     * Mark a job as failed.
     *
     * @param string $job_id UUID.
     * @param string $error  Error description.
     * @return bool
     */
    public function fail( $job_id, $error = '' ) {
        return $this->update_status( $job_id, self::STATUS_FAILED, array(
            'error_message' => sanitize_text_field( $error ),
            'completed_at'  => current_time( 'mysql', true ),
        ) );
    }

    /**
     * Cancel a job.
     *
     * @param string $job_id UUID.
     * @return bool
     */
    public function cancel( $job_id ) {
        return $this->update_status( $job_id, self::STATUS_CANCELLED, array(
            'completed_at' => current_time( 'mysql', true ),
        ) );
    }

    /**
     * List jobs, optionally filtered.
     *
     * @param array $args {
     *     @type string $job_type Filter by type.
     *     @type string $status   Filter by status.
     *     @type int    $limit    Max rows.
     *     @type int    $offset   Offset.
     *     @type string $orderby  Column to order by.
     *     @type string $order    ASC or DESC.
     * }
     * @return array
     */
    public function list_jobs( array $args = array() ) {
        global $wpdb;

        $defaults = array(
            'job_type' => '',
            'status'   => '',
            'limit'    => 20,
            'offset'   => 0,
            'orderby'  => 'created_at',
            'order'    => 'DESC',
        );
        $args = wp_parse_args( $args, $defaults );

        $where  = array( '1=1' );
        $values = array();

        if ( ! empty( $args['job_type'] ) ) {
            $where[]  = 'job_type = %s';
            $values[] = sanitize_key( $args['job_type'] );
        }

        if ( ! empty( $args['status'] ) ) {
            $where[]  = 'status = %s';
            $values[] = sanitize_key( $args['status'] );
        }

        $allowed_orderby = array( 'created_at', 'started_at', 'completed_at', 'status', 'job_type' );
        $orderby         = in_array( $args['orderby'], $allowed_orderby, true ) ? $args['orderby'] : 'created_at';
        $order           = 'ASC' === strtoupper( $args['order'] ) ? 'ASC' : 'DESC';

        $where_clause = implode( ' AND ', $where );
        $values[]     = absint( $args['limit'] );
        $values[]     = absint( $args['offset'] );

        // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter
        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}aipsc_jobs WHERE {$where_clause} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d",
                ...$values
            )
        );
        // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter
    }

    /* ---------------------------------------------------------------
     * Job Items
     * ------------------------------------------------------------- */

    /**
     * Add batch items to a job.
     *
     * @param string $job_id UUID.
     * @param array  $keys   Array of item keys (e.g. file paths).
     * @return int           Number of items inserted.
     */
    public function add_items( $job_id, array $keys ) {
        global $wpdb;

        $table = $wpdb->prefix . 'aipsc_job_items';
        $count = 0;
        $now   = current_time( 'mysql', true );

        foreach ( $keys as $key ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
            $inserted = $wpdb->insert(
                $table,
                array(
                    'job_id'     => $job_id,
                    'item_key'   => $key,
                    'status'     => self::STATUS_PENDING,
                    'created_at' => $now,
                ),
                array( '%s', '%s', '%s', '%s' )
            );
            if ( $inserted ) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * Claim the next batch of pending items.
     *
     * @param string $job_id    UUID.
     * @param int    $batch_size Number of items to claim.
     * @return array             Array of row objects.
     */
    public function claim_items( $job_id, $batch_size = 50 ) {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $items = $wpdb->get_results(
            $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}aipsc_job_items WHERE job_id = %s AND status = %s ORDER BY id ASC LIMIT %d",
                $job_id,
                self::STATUS_PENDING,
                absint( $batch_size )
            )
        );

        if ( empty( $items ) ) {
            return array();
        }

        $ids = wp_list_pluck( $items, 'id' );
        $placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );

        // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query(
            $wpdb->prepare(
                "UPDATE {$wpdb->prefix}aipsc_job_items SET status = 'running', attempts = attempts + 1 WHERE id IN ({$placeholders})",
                ...$ids
            )
        );
        // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter

        return $items;
    }

    /**
     * Mark a job item as completed.
     *
     * @param int   $item_id Row ID.
     * @param mixed $result  Result data.
     * @return bool
     */
    public function complete_item( $item_id, $result = null ) {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return (bool) $wpdb->update(
            $wpdb->prefix . 'aipsc_job_items',
            array(
                'status'       => self::STATUS_COMPLETED,
                'result_json'  => null !== $result ? wp_json_encode( $result ) : null,
                'processed_at' => current_time( 'mysql', true ),
            ),
            array( 'id' => absint( $item_id ) ),
            array( '%s', '%s', '%s' ),
            array( '%d' )
        );
    }

    /**
     * Mark a job item as failed.
     *
     * @param int    $item_id Row ID.
     * @param string $error   Error message.
     * @return bool
     */
    public function fail_item( $item_id, $error = '' ) {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return (bool) $wpdb->update(
            $wpdb->prefix . 'aipsc_job_items',
            array(
                'status'       => self::STATUS_FAILED,
                'result_json'  => wp_json_encode( array( 'error' => $error ) ),
                'processed_at' => current_time( 'mysql', true ),
            ),
            array( 'id' => absint( $item_id ) ),
            array( '%s', '%s', '%s' ),
            array( '%d' )
        );
    }

    /**
     * Count items by status for a job.
     *
     * @param string $job_id UUID.
     * @return array         Associative array of status => count.
     */
    public function count_items( $job_id ) {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT status, COUNT(*) as cnt FROM {$wpdb->prefix}aipsc_job_items WHERE job_id = %s GROUP BY status",
                $job_id
            )
        );

        $counts = array(
            'pending'   => 0,
            'running'   => 0,
            'completed' => 0,
            'failed'    => 0,
        );

        foreach ( $rows as $row ) {
            $counts[ $row->status ] = (int) $row->cnt;
        }

        return $counts;
    }

    /* ---------------------------------------------------------------
     * Cleanup Helpers
     * ------------------------------------------------------------- */

    /**
     * Purge completed/failed jobs older than given days.
     *
     * @param int $days Age threshold.
     * @return int      Rows deleted.
     */
    public function purge_old( $days = 30 ) {
        global $wpdb;

        $cutoff = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );

        // Delete child items first.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query(
            $wpdb->prepare(
                "DELETE ji FROM {$wpdb->prefix}aipsc_job_items ji
                 INNER JOIN {$wpdb->prefix}aipsc_jobs j ON ji.job_id = j.job_id
                 WHERE j.status IN ('completed','failed','cancelled') AND j.completed_at < %s",
                $cutoff
            )
        );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return (int) $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->prefix}aipsc_jobs WHERE status IN ('completed','failed','cancelled') AND completed_at < %s",
                $cutoff
            )
        );
    }

    /**
     * Get a summary of a job suitable for REST / MCP responses.
     *
     * @param string $job_id UUID.
     * @return array|null
     */
    public function summary( $job_id ) {
        $job = $this->get( $job_id );
        if ( ! $job ) {
            return null;
        }

        $item_counts = $this->count_items( $job_id );

        return array(
            'job_id'          => $job->job_id,
            'job_type'        => $job->job_type,
            'status'          => $job->status,
            'progress'        => (int) $job->progress,
            'total_items'     => (int) $job->total_items,
            'completed_items' => (int) $job->completed_items,
            'item_counts'     => $item_counts,
            'created_at'      => $job->created_at,
            'started_at'      => $job->started_at,
            'completed_at'    => $job->completed_at,
            'has_result'      => ! empty( $job->result_json ),
            'has_error'       => ! empty( $job->error_message ),
            'error_message'   => $job->error_message,
        );
    }

    /* ---------------------------------------------------------------
     * Internal
     * ------------------------------------------------------------- */

    /**
     * Change job status and optionally set extra columns.
     *
     * @param string $job_id UUID.
     * @param string $status New status.
     * @param array  $extra  Additional column => value pairs.
     * @return bool
     */
    private function update_status( $job_id, $status, array $extra = array() ) {
        global $wpdb;

        $data = array_merge( array( 'status' => $status ), $extra );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return (bool) $wpdb->update(
            $wpdb->prefix . 'aipsc_jobs',
            $data,
            array( 'job_id' => $job_id )
        );
    }
}
