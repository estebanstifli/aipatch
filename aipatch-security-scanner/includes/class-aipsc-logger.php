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
 * Class AIPSC_Logger
 */
class AIPSC_Logger {

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
        $this->table = $wpdb->prefix . 'aipsc_logs';
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
     * Log a critical event.
     *
     * @param string $event_type Event type.
     * @param string $message    Message.
     * @param array  $context    Context.
     */
    public function critical( $event_type, $message, $context = array() ) {
        $this->log( $event_type, $message, 'critical', $context );
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

        $args = wp_parse_args( $args, $defaults );

        $per_page = absint( $args['per_page'] );
        $offset   = ( absint( $args['page'] ) - 1 ) * $per_page;
        $event_type = sanitize_key( $args['event_type'] );
        $severity   = sanitize_key( $args['severity'] );

        // Count total.
        if ( '' !== $event_type && '' !== $severity ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $total = (int) $wpdb->get_var(
                $wpdb->prepare(
                    'SELECT COUNT(*) FROM %i WHERE event_type = %s AND severity = %s',
                    $this->table,
                    $event_type,
                    $severity
                )
            );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $items = $wpdb->get_results(
                $wpdb->prepare(
                    'SELECT * FROM %i WHERE event_type = %s AND severity = %s ORDER BY created_at DESC LIMIT %d OFFSET %d',
                    $this->table,
                    $event_type,
                    $severity,
                    $per_page,
                    $offset
                )
            );
        } elseif ( '' !== $event_type ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $total = (int) $wpdb->get_var(
                $wpdb->prepare(
                    'SELECT COUNT(*) FROM %i WHERE event_type = %s',
                    $this->table,
                    $event_type
                )
            );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $items = $wpdb->get_results(
                $wpdb->prepare(
                    'SELECT * FROM %i WHERE event_type = %s ORDER BY created_at DESC LIMIT %d OFFSET %d',
                    $this->table,
                    $event_type,
                    $per_page,
                    $offset
                )
            );
        } elseif ( '' !== $severity ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $total = (int) $wpdb->get_var(
                $wpdb->prepare(
                    'SELECT COUNT(*) FROM %i WHERE severity = %s',
                    $this->table,
                    $severity
                )
            );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $items = $wpdb->get_results(
                $wpdb->prepare(
                    'SELECT * FROM %i WHERE severity = %s ORDER BY created_at DESC LIMIT %d OFFSET %d',
                    $this->table,
                    $severity,
                    $per_page,
                    $offset
                )
            );
        } else {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $total = (int) $wpdb->get_var(
                $wpdb->prepare(
                    'SELECT COUNT(*) FROM %i',
                    $this->table
                )
            );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $items = $wpdb->get_results(
                $wpdb->prepare(
                    'SELECT * FROM %i ORDER BY created_at DESC LIMIT %d OFFSET %d',
                    $this->table,
                    $per_page,
                    $offset
                )
            );
        }

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

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $deleted = $wpdb->query(
            $wpdb->prepare(
                'DELETE FROM %i WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)',
                $this->table,
                $days
            )
        );

        return $deleted ? $deleted : 0;
    }

    /**
     * Clear all logs.
     *
     * @return int|false
     */
    public function clear_all() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return $wpdb->query( $wpdb->prepare( 'TRUNCATE TABLE %i', $this->table ) );
    }

    /**
     * Get count of logs by severity.
     *
     * @return array
     */
    public function get_counts() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $results = $wpdb->get_results(
            $wpdb->prepare( 'SELECT severity, COUNT(*) as count FROM %i GROUP BY severity', $this->table ),
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
