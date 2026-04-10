<?php
/**
 * Logger module – records plugin events to a custom table.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class PWW_Logger
 */
class PWW_Logger {

    /**
     * Log table name (cached).
     *
     * @var string
     */
    private $table;

    /**
     * Constructor.
     */
    public function __construct() {
        global $wpdb;
        $this->table = $wpdb->prefix . 'pww_logs';
    }

    /**
     * Insert a log entry.
     *
     * @param string $event_type Event type identifier.
     * @param string $message    Human-readable message.
     * @param string $severity   info|warning|error|critical.
     * @param array  $context    Additional context data.
     * @return int|false Inserted row ID or false.
     */
    public function log( $event_type, $message, $severity = 'info', $context = array() ) {
        global $wpdb;

        $event_type = sanitize_key( $event_type );
        $severity   = in_array( $severity, array( 'info', 'warning', 'error', 'critical' ), true )
            ? $severity
            : 'info';

        $data = array(
            'event_type'   => $event_type,
            'severity'     => $severity,
            'message'      => sanitize_text_field( $message ),
            'context_json' => ! empty( $context ) ? wp_json_encode( $context ) : null,
            'created_at'   => current_time( 'mysql', true ),
        );

        $format = array( '%s', '%s', '%s', '%s', '%s' );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $result = $wpdb->insert( $this->table, $data, $format );

        return $result ? $wpdb->insert_id : false;
    }

    /**
     * Convenience: log info.
     *
     * @param string $event_type Event type.
     * @param string $message    Message.
     * @param array  $context    Context.
     */
    public function info( $event_type, $message, $context = array() ) {
        $this->log( $event_type, $message, 'info', $context );
    }

    /**
     * Convenience: log warning.
     *
     * @param string $event_type Event type.
     * @param string $message    Message.
     * @param array  $context    Context.
     */
    public function warning( $event_type, $message, $context = array() ) {
        $this->log( $event_type, $message, 'warning', $context );
    }

    /**
     * Convenience: log error.
     *
     * @param string $event_type Event type.
     * @param string $message    Message.
     * @param array  $context    Context.
     */
    public function error( $event_type, $message, $context = array() ) {
        $this->log( $event_type, $message, 'error', $context );
    }

    /**
     * Retrieve log entries with pagination.
     *
     * @param array $args Query arguments.
     * @return array With 'items' and 'total' keys.
     */
    public function get_logs( $args = array() ) {
        global $wpdb;

        $defaults = array(
            'per_page'   => 20,
            'page'       => 1,
            'event_type' => '',
            'severity'   => '',
            'orderby'    => 'created_at',
            'order'      => 'DESC',
        );

        $args   = wp_parse_args( $args, $defaults );
        $where  = array( '1=1' );
        $values = array();

        if ( ! empty( $args['event_type'] ) ) {
            $where[]  = 'event_type = %s';
            $values[] = sanitize_key( $args['event_type'] );
        }

        if ( ! empty( $args['severity'] ) ) {
            $where[]  = 'severity = %s';
            $values[] = sanitize_key( $args['severity'] );
        }

        $where_sql = implode( ' AND ', $where );

        // Sanitize order parameters (allowlist only).
        $allowed_orderby = array( 'id', 'event_type', 'severity', 'created_at' );
        $orderby = in_array( $args['orderby'], $allowed_orderby, true ) ? $args['orderby'] : 'created_at';
        $order   = strtoupper( $args['order'] ) === 'ASC' ? 'ASC' : 'DESC';

        $per_page = absint( $args['per_page'] );
        $offset   = ( absint( $args['page'] ) - 1 ) * $per_page;

        // Table name is safe: $wpdb->prefix (trusted) + hardcoded suffix.
        $table = esc_sql( $this->table );

        // Count total.
        $count_sql = 'SELECT COUNT(*) FROM `' . $table . '` WHERE ' . $where_sql;
        if ( ! empty( $values ) ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
            $total = (int) $wpdb->get_var( $wpdb->prepare( $count_sql, $values ) );
        } else {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
            $total = (int) $wpdb->get_var( $count_sql );
        }

        // Fetch rows.
        $select_sql   = 'SELECT * FROM `' . $table . '` WHERE ' . $where_sql . ' ORDER BY ' . $orderby . ' ' . $order . ' LIMIT %d OFFSET %d';
        $query_values = array_merge( $values, array( $per_page, $offset ) );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
        $items = $wpdb->get_results( $wpdb->prepare( $select_sql, $query_values ) );

        return array(
            'items' => $items ? $items : array(),
            'total' => $total,
        );
    }

    /**
     * Delete logs older than the retention period.
     *
     * @param int $days Number of days to retain.
     * @return int Number of rows deleted.
     */
    public function cleanup( $days = 30 ) {
        global $wpdb;

        $days = absint( $days );
        if ( $days < 1 ) {
            $days = 30;
        }

        $table       = esc_sql( $this->table );
        $cleanup_sql = 'DELETE FROM `' . $table . '` WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
        $deleted = $wpdb->query( $wpdb->prepare( $cleanup_sql, $days ) );

        return $deleted ? $deleted : 0;
    }

    /**
     * Clear all logs.
     *
     * @return int|false
     */
    public function clear_all() {
        global $wpdb;

        $table = esc_sql( $this->table );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
        return $wpdb->query( 'TRUNCATE TABLE `' . $table . '`' );
    }

    /**
     * Get count of logs by severity.
     *
     * @return array
     */
    public function get_counts() {
        global $wpdb;

        $table = esc_sql( $this->table );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
        $results = $wpdb->get_results(
            'SELECT severity, COUNT(*) as count FROM `' . $table . '` GROUP BY severity',
            OBJECT_K
        );

        $counts = array(
            'info'     => 0,
            'warning'  => 0,
            'error'    => 0,
            'critical' => 0,
            'total'    => 0,
        );

        if ( $results ) {
            foreach ( $results as $severity => $row ) {
                $counts[ $severity ] = (int) $row->count;
                $counts['total']    += (int) $row->count;
            }
        }

        return $counts;
    }
}
