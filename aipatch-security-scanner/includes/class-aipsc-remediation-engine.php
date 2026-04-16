<?php
/**
 * Remediation Engine.
 *
 * Applies, tracks, and rolls back security fixes linked to findings.
 * Each remediation record stores an action type, description, rollback
 * payload, and references the originating finding by fingerprint.
 *
 * @package AipatchSecurityScanner
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class AIPSC_Remediation_Engine
 */
class AIPSC_Remediation_Engine {

    /* ---------------------------------------------------------------
     * Constants
     * ------------------------------------------------------------- */

    const STATUS_APPLIED     = 'applied';
    const STATUS_ROLLED_BACK = 'rolled_back';

    const ACTION_WP_OPTION     = 'wp_option';
    const ACTION_DELETE_FILE    = 'delete_file';
    const ACTION_RENAME_FILE   = 'rename_file';
    const ACTION_FILE_PATCH    = 'file_patch';
    const ACTION_HTACCESS_RULE = 'htaccess_rule';
    const ACTION_MANUAL        = 'manual';

    /** @var AIPSC_Findings_Store|null */
    private $findings_store;

    /** @var AIPSC_Logger */
    private $logger;

    /**
     * Constructor.
     *
     * @param AIPSC_Findings_Store|null $findings_store Findings store.
     * @param AIPSC_Logger              $logger         Logger.
     */
    public function __construct( $findings_store, AIPSC_Logger $logger ) {
        $this->findings_store = $findings_store;
        $this->logger         = $logger;
    }

    /* ---------------------------------------------------------------
     * Dispatch
     * ------------------------------------------------------------- */

    /**
     * Apply a remediation action and persist the record.
     *
     * @param array $args {
     *     @type string $finding_fingerprint Required. Finding to remediate.
     *     @type string $action_type         Required. One of the ACTION_* constants.
     *     @type string $description         Human-readable description of the fix.
     *     @type array  $params              Action-specific parameters.
     * }
     * @return array|WP_Error Remediation record on success.
     */
    public function apply( array $args ) {
        $fp          = isset( $args['finding_fingerprint'] ) ? sanitize_text_field( $args['finding_fingerprint'] ) : '';
        $action_type = isset( $args['action_type'] ) ? sanitize_key( $args['action_type'] ) : '';
        $description = isset( $args['description'] ) ? sanitize_text_field( $args['description'] ) : '';
        $params      = isset( $args['params'] ) && is_array( $args['params'] ) ? $args['params'] : array();

        if ( '' === $fp ) {
            return new WP_Error( 'aipatch_missing_fingerprint', 'finding_fingerprint is required.' );
        }
        if ( '' === $action_type ) {
            return new WP_Error( 'aipatch_missing_action', 'action_type is required.' );
        }

        $allowed = array(
            self::ACTION_WP_OPTION,
            self::ACTION_DELETE_FILE,
            self::ACTION_RENAME_FILE,
            self::ACTION_FILE_PATCH,
            self::ACTION_HTACCESS_RULE,
            self::ACTION_MANUAL,
        );
        if ( ! in_array( $action_type, $allowed, true ) ) {
            return new WP_Error( 'aipatch_invalid_action', "Unknown action_type: {$action_type}" );
        }

        // Verify finding exists.
        if ( $this->findings_store ) {
            $finding = $this->findings_store->get_by_fingerprint( $fp );
            if ( ! $finding ) {
                return new WP_Error( 'aipatch_finding_not_found', 'No finding matches the provided fingerprint.' );
            }
        }

        // Execute the action and collect rollback data.
        $rollback_data = null;
        if ( self::ACTION_MANUAL !== $action_type ) {
            $exec_result = $this->execute_action( $action_type, $params );
            if ( is_wp_error( $exec_result ) ) {
                return $exec_result;
            }
            $rollback_data = $exec_result;
        }

        // Persist.
        $record = $this->insert_record( $fp, $action_type, $description, $rollback_data );
        if ( is_wp_error( $record ) ) {
            return $record;
        }

        // Mark finding as resolved.
        if ( $this->findings_store ) {
            $this->findings_store->resolve( $fp );
        }

        $this->logger->info( 'remediation_applied', sprintf(
            'Remediation #%d applied (action=%s, fingerprint=%s)',
            $record['id'],
            $action_type,
            $fp
        ) );

        return $record;
    }

    /**
     * Rollback a previously applied remediation.
     *
     * @param int $remediation_id Remediation record ID.
     * @return array|WP_Error Updated record on success.
     */
    public function rollback( $remediation_id ) {
        global $wpdb;

        $remediation_id = absint( $remediation_id );
        $table          = $wpdb->prefix . 'aipsc_remediations';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $record = $wpdb->get_row(
            $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d LIMIT 1", $remediation_id ),
            ARRAY_A
        );

        if ( ! $record ) {
            return new WP_Error( 'aipatch_not_found', 'Remediation record not found.' );
        }

        if ( self::STATUS_ROLLED_BACK === $record['status'] ) {
            return new WP_Error( 'aipatch_already_rolled_back', 'This remediation has already been rolled back.' );
        }

        $rollback_data = ! empty( $record['rollback_data'] ) ? json_decode( $record['rollback_data'], true ) : null;

        if ( self::ACTION_MANUAL === $record['action_type'] ) {
            return new WP_Error( 'aipatch_manual_no_rollback', 'Manual remediations cannot be rolled back automatically.' );
        }

        if ( empty( $rollback_data ) ) {
            return new WP_Error( 'aipatch_no_rollback_data', 'No rollback data stored for this remediation.' );
        }

        $result = $this->execute_rollback( $record['action_type'], $rollback_data );
        if ( is_wp_error( $result ) ) {
            return $result;
        }

        $now = current_time( 'mysql', true );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->update(
            $table,
            array(
                'status'         => self::STATUS_ROLLED_BACK,
                'rolled_back_at' => $now,
            ),
            array( 'id' => $remediation_id )
        );

        // Reopen the linked finding.
        if ( $this->findings_store && ! empty( $record['finding_fingerprint'] ) ) {
            $this->reopen_finding( $record['finding_fingerprint'] );
        }

        $this->logger->info( 'remediation_rolled_back', sprintf(
            'Remediation #%d rolled back (action=%s)',
            $remediation_id,
            $record['action_type']
        ) );

        $record['status']         = self::STATUS_ROLLED_BACK;
        $record['rolled_back_at'] = $now;

        return $record;
    }

    /* ---------------------------------------------------------------
     * Query
     * ------------------------------------------------------------- */

    /**
     * List remediations with optional filters.
     *
     * @param array $args {
     *     @type string $finding_fingerprint Filter by fingerprint.
     *     @type string $action_type         Filter by action type.
     *     @type string $status              Filter by status (applied|rolled_back).
     *     @type int    $limit               Max rows (default 50).
     *     @type int    $offset              Offset (default 0).
     * }
     * @return array
     */
    public function list_remediations( array $args = array() ) {
        global $wpdb;

        $defaults = array(
            'finding_fingerprint' => '',
            'action_type'         => '',
            'status'              => '',
            'limit'               => 50,
            'offset'              => 0,
        );
        $args = wp_parse_args( $args, $defaults );

        $where  = array( '1=1' );
        $values = array();

        if ( ! empty( $args['finding_fingerprint'] ) ) {
            $where[]  = 'finding_fingerprint = %s';
            $values[] = sanitize_text_field( $args['finding_fingerprint'] );
        }
        if ( ! empty( $args['action_type'] ) ) {
            $where[]  = 'action_type = %s';
            $values[] = sanitize_key( $args['action_type'] );
        }
        if ( ! empty( $args['status'] ) ) {
            $where[]  = 'status = %s';
            $values[] = sanitize_key( $args['status'] );
        }

        $where_sql = implode( ' AND ', $where );
        $values[]  = absint( $args['limit'] );
        $values[]  = absint( $args['offset'] );

        $table = $wpdb->prefix . 'aipsc_remediations';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY created_at DESC LIMIT %d OFFSET %d",
                $values
            ),
            ARRAY_A
        );
    }

    /**
     * Get a single remediation by ID.
     *
     * @param int $id Remediation ID.
     * @return array|null
     */
    public function get( $id ) {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}aipsc_remediations WHERE id = %d LIMIT 1",
                absint( $id )
            ),
            ARRAY_A
        );
    }

    /**
     * Summary statistics.
     *
     * @return array
     */
    public function stats() {
        global $wpdb;

        $table = $wpdb->prefix . 'aipsc_remediations';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $by_status = $wpdb->get_results(
            "SELECT status, COUNT(*) as cnt FROM {$table} GROUP BY status",
            OBJECT_K
        );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $by_action = $wpdb->get_results(
            "SELECT action_type, COUNT(*) as cnt FROM {$table} GROUP BY action_type",
            OBJECT_K
        );

        $action_counts = array();
        foreach ( $by_action as $key => $row ) {
            $action_counts[ $key ] = (int) $row->cnt;
        }

        return array(
            'total_applied'     => isset( $by_status[ self::STATUS_APPLIED ] ) ? (int) $by_status[ self::STATUS_APPLIED ]->cnt : 0,
            'total_rolled_back' => isset( $by_status[ self::STATUS_ROLLED_BACK ] ) ? (int) $by_status[ self::STATUS_ROLLED_BACK ]->cnt : 0,
            'by_action_type'    => $action_counts,
        );
    }

    /* ---------------------------------------------------------------
     * Action executors
     * ------------------------------------------------------------- */

    /**
     * Execute the specified action and return rollback data.
     *
     * @param string $action_type Action type constant.
     * @param array  $params      Action parameters.
     * @return array|WP_Error     Rollback data or error.
     */
    private function execute_action( $action_type, array $params ) {
        switch ( $action_type ) {
            case self::ACTION_WP_OPTION:
                return $this->action_wp_option( $params );

            case self::ACTION_DELETE_FILE:
                return $this->action_delete_file( $params );

            case self::ACTION_RENAME_FILE:
                return $this->action_rename_file( $params );

            case self::ACTION_FILE_PATCH:
                return $this->action_file_patch( $params );

            case self::ACTION_HTACCESS_RULE:
                return $this->action_htaccess_rule( $params );

            default:
                return new WP_Error( 'aipatch_unhandled_action', "No executor for action: {$action_type}" );
        }
    }

    /**
     * Execute a rollback using stored rollback data.
     *
     * @param string $action_type  Original action type.
     * @param array  $rollback_data Stored rollback payload.
     * @return true|WP_Error
     */
    private function execute_rollback( $action_type, array $rollback_data ) {
        switch ( $action_type ) {
            case self::ACTION_WP_OPTION:
                return $this->rollback_wp_option( $rollback_data );

            case self::ACTION_DELETE_FILE:
                return $this->rollback_delete_file( $rollback_data );

            case self::ACTION_RENAME_FILE:
                return $this->rollback_rename_file( $rollback_data );

            case self::ACTION_FILE_PATCH:
                return $this->rollback_file_patch( $rollback_data );

            case self::ACTION_HTACCESS_RULE:
                return $this->rollback_htaccess_rule( $rollback_data );

            default:
                return new WP_Error( 'aipatch_unhandled_rollback', "No rollback handler for action: {$action_type}" );
        }
    }

    /* -- wp_option ------------------------------------------------- */

    /**
     * Set/update a WordPress option.
     *
     * Params: option_name, new_value.
     *
     * @param array $params Action params.
     * @return array|WP_Error Rollback data.
     */
    private function action_wp_option( array $params ) {
        $option = isset( $params['option_name'] ) ? sanitize_key( $params['option_name'] ) : '';
        if ( '' === $option ) {
            return new WP_Error( 'aipatch_missing_param', 'option_name is required.' );
        }
        if ( ! array_key_exists( 'new_value', $params ) ) {
            return new WP_Error( 'aipatch_missing_param', 'new_value is required.' );
        }

        $old_value = get_option( $option );
        $existed   = false !== $old_value;

        update_option( $option, $params['new_value'] );

        return array(
            'option_name' => $option,
            'old_value'   => $old_value,
            'existed'     => $existed,
        );
    }

    private function rollback_wp_option( array $data ) {
        if ( ! $data['existed'] ) {
            delete_option( $data['option_name'] );
        } else {
            update_option( $data['option_name'], $data['old_value'] );
        }
        return true;
    }

    /* -- delete_file ----------------------------------------------- */

    /**
     * Delete a file (stores content for rollback).
     *
     * Params: path (relative to ABSPATH).
     *
     * @param array $params Action params.
     * @return array|WP_Error Rollback data.
     */
    private function action_delete_file( array $params ) {
        $rel = isset( $params['path'] ) ? $params['path'] : '';
        $abs = $this->resolve_path( $rel );
        if ( is_wp_error( $abs ) ) {
            return $abs;
        }
        if ( ! file_exists( $abs ) ) {
            return new WP_Error( 'aipatch_file_not_found', "File not found: {$rel}" );
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
        $content = file_get_contents( $abs );
        $perms   = fileperms( $abs );

        wp_delete_file( $abs );

        if ( file_exists( $abs ) ) {
            return new WP_Error( 'aipatch_delete_failed', "Could not delete: {$rel}" );
        }

        return array(
            'path'    => $rel,
            'content' => base64_encode( $content ),
            'perms'   => $perms,
        );
    }

    private function rollback_delete_file( array $data ) {
        $abs = $this->resolve_path( $data['path'] );
        if ( is_wp_error( $abs ) ) {
            return $abs;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        $written = file_put_contents( $abs, base64_decode( $data['content'] ) );
        if ( false === $written ) {
            return new WP_Error( 'aipatch_restore_failed', "Could not restore: {$data['path']}" );
        }
        if ( ! empty( $data['perms'] ) ) {
            chmod( $abs, $data['perms'] );
        }
        return true;
    }

    /* -- rename_file ----------------------------------------------- */

    /**
     * Rename/move a file.
     *
     * Params: from (relative), to (relative).
     *
     * @param array $params Action params.
     * @return array|WP_Error Rollback data.
     */
    private function action_rename_file( array $params ) {
        $from = isset( $params['from'] ) ? $params['from'] : '';
        $to   = isset( $params['to'] ) ? $params['to'] : '';

        $abs_from = $this->resolve_path( $from );
        if ( is_wp_error( $abs_from ) ) {
            return $abs_from;
        }
        $abs_to = $this->resolve_path( $to );
        if ( is_wp_error( $abs_to ) ) {
            return $abs_to;
        }

        if ( ! file_exists( $abs_from ) ) {
            return new WP_Error( 'aipatch_file_not_found', "Source not found: {$from}" );
        }
        if ( file_exists( $abs_to ) ) {
            return new WP_Error( 'aipatch_file_exists', "Destination already exists: {$to}" );
        }

        if ( ! rename( $abs_from, $abs_to ) ) {
            return new WP_Error( 'aipatch_rename_failed', "Could not rename {$from} → {$to}" );
        }

        return array( 'from' => $from, 'to' => $to );
    }

    private function rollback_rename_file( array $data ) {
        $abs_from = $this->resolve_path( $data['to'] );
        $abs_to   = $this->resolve_path( $data['from'] );

        if ( is_wp_error( $abs_from ) || is_wp_error( $abs_to ) ) {
            return new WP_Error( 'aipatch_rollback_path', 'Invalid rollback paths.' );
        }

        if ( ! rename( $abs_from, $abs_to ) ) {
            return new WP_Error( 'aipatch_rollback_rename_failed', 'Could not reverse rename.' );
        }
        return true;
    }

    /* -- file_patch ------------------------------------------------ */

    /**
     * Apply a text patch (search & replace) on a file.
     *
     * Params: path (relative), search, replace.
     *
     * @param array $params Action params.
     * @return array|WP_Error Rollback data.
     */
    private function action_file_patch( array $params ) {
        $rel     = isset( $params['path'] ) ? $params['path'] : '';
        $search  = isset( $params['search'] ) ? $params['search'] : '';
        $replace = isset( $params['replace'] ) ? $params['replace'] : '';

        if ( '' === $search ) {
            return new WP_Error( 'aipatch_missing_param', 'search string is required.' );
        }

        $abs = $this->resolve_path( $rel );
        if ( is_wp_error( $abs ) ) {
            return $abs;
        }
        if ( ! file_exists( $abs ) ) {
            return new WP_Error( 'aipatch_file_not_found', "File not found: {$rel}" );
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
        $content = file_get_contents( $abs );
        if ( false === strpos( $content, $search ) ) {
            return new WP_Error( 'aipatch_search_not_found', 'Search string not found in file.' );
        }

        $new_content = str_replace( $search, $replace, $content );

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        if ( false === file_put_contents( $abs, $new_content ) ) {
            return new WP_Error( 'aipatch_patch_failed', "Could not write to: {$rel}" );
        }

        return array(
            'path'    => $rel,
            'search'  => $replace, // For rollback: the new text becomes the search.
            'replace' => $search,  // And the old text becomes the replacement.
        );
    }

    private function rollback_file_patch( array $data ) {
        return $this->action_file_patch( $data );
    }

    /* -- htaccess_rule --------------------------------------------- */

    /**
     * Append a rule block to .htaccess.
     *
     * Params: marker (unique identifier), rules (string).
     *
     * @param array $params Action params.
     * @return array|WP_Error Rollback data.
     */
    private function action_htaccess_rule( array $params ) {
        $marker = isset( $params['marker'] ) ? sanitize_text_field( $params['marker'] ) : '';
        $rules  = isset( $params['rules'] ) ? $params['rules'] : '';

        if ( '' === $marker || '' === $rules ) {
            return new WP_Error( 'aipatch_missing_param', 'marker and rules are required.' );
        }

        $htaccess = ABSPATH . '.htaccess';

        if ( ! function_exists( 'insert_with_markers' ) ) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }

        $result = insert_with_markers( $htaccess, $marker, explode( "\n", $rules ) );
        if ( ! $result ) {
            return new WP_Error( 'aipatch_htaccess_failed', 'Could not write .htaccess rules.' );
        }

        return array( 'marker' => $marker );
    }

    private function rollback_htaccess_rule( array $data ) {
        $htaccess = ABSPATH . '.htaccess';

        if ( ! function_exists( 'insert_with_markers' ) ) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }

        // Empty array removes the marker block.
        insert_with_markers( $htaccess, $data['marker'], array() );
        return true;
    }

    /* ---------------------------------------------------------------
     * Helpers
     * ------------------------------------------------------------- */

    /**
     * Resolve a relative path safely within ABSPATH.
     *
     * @param string $relative Relative path.
     * @return string|WP_Error Absolute path or error.
     */
    private function resolve_path( $relative ) {
        if ( '' === $relative ) {
            return new WP_Error( 'aipatch_empty_path', 'File path is required.' );
        }

        // Normalise separators.
        $relative = str_replace( '\\', '/', $relative );

        // Block directory-traversal attempts.
        if ( false !== strpos( $relative, '..' ) ) {
            return new WP_Error( 'aipatch_path_traversal', 'Path traversal is not allowed.' );
        }

        $abs = realpath( ABSPATH . ltrim( $relative, '/' ) );

        // Ensure the path stays inside ABSPATH.
        if ( false === $abs || 0 !== strpos( $abs, realpath( ABSPATH ) ) ) {
            return new WP_Error( 'aipatch_path_outside', 'Path resolves outside of WordPress root.' );
        }

        return $abs;
    }

    /**
     * Reopen a finding whose remediation was rolled back.
     *
     * @param string $fingerprint Finding fingerprint.
     */
    private function reopen_finding( $fingerprint ) {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->update(
            $wpdb->prefix . 'aipsc_findings',
            array(
                'status'      => 'open',
                'resolved_at' => null,
            ),
            array(
                'fingerprint' => $fingerprint,
                'status'      => 'resolved',
            )
        );
    }

    /**
     * Insert a remediation record.
     *
     * @param string     $fingerprint  Finding fingerprint.
     * @param string     $action_type  Action type.
     * @param string     $description  Human description.
     * @param array|null $rollback_data Rollback payload.
     * @return array|WP_Error
     */
    private function insert_record( $fingerprint, $action_type, $description, $rollback_data ) {
        global $wpdb;

        $table = $wpdb->prefix . 'aipsc_remediations';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $inserted = $wpdb->insert( $table, array(
            'finding_fingerprint' => $fingerprint,
            'action_type'         => $action_type,
            'description'         => $description,
            'rollback_data'       => $rollback_data ? wp_json_encode( $rollback_data ) : null,
            'performed_by'        => get_current_user_id(),
            'status'              => self::STATUS_APPLIED,
            'created_at'          => current_time( 'mysql', true ),
        ) );

        if ( false === $inserted ) {
            return new WP_Error( 'aipatch_db_error', 'Failed to insert remediation record.' );
        }

        return $this->get( $wpdb->insert_id );
    }
}
