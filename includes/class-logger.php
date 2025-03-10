<?php
/**
 * Logger Class.
 *
 * Handles logging for Cloudflare IP Blocker.
 *
 * @author Polar Mass
 * @since 1.0.0
 * @package cloudflare-ip-blocker
 */

namespace Cloudflare_Ip_Blocker;

/**
 * Class Logger
 *
 * Logs blocked IPs and security events.
 */
class Logger {
	/**
	 * Log file path.
	 *
	 * @var string
	 */
	private $log_file;

	/**
	 * Maximum number of log entries to keep.
	 *
	 * @var int Maximum number of log entries to keep
	 */
	private $max_logs = 1000;

	/**
	 * Constructor
	 */
	public function __construct() {
		$upload_dir     = wp_upload_dir();
		$this->log_file = $upload_dir['basedir'] . '/cloudflare-ip-blocker/cloudflare-ip-blocker.log';
		$this->max_logs = get_option( 'cfip_max_logs', 1000 );
	}

	/**
	 * Log a message
	 *
	 * @param string $message Message to log.
	 * @param string $level Log level (info, warning, error).
	 */
	public function log( $message, $level = 'info' ) {
		global $wp_filesystem;

		if ( empty( $wp_filesystem ) ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';

			\WP_Filesystem();
		}

		if ( ! $wp_filesystem->is_writable( dirname( $this->log_file ) ) ) {
			return;
		}

		$timestamp         = current_time( 'mysql' );
		$formatted_message = sprintf(
			'[%s] [%s] %s' . PHP_EOL,
			$timestamp,
			strtoupper( $level ),
			$message
		);

		// Get existing logs.
		$logs = file( $this->log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
		if ( ! is_array( $logs ) ) {
			$logs = array();
		}

		// Add new log entry.
		array_unshift( $logs, $formatted_message );

		// Trim logs if exceeding max limit.
		if ( count( $logs ) > $this->max_logs ) {
			$logs = array_slice( $logs, 0, $this->max_logs );
		}

		// Write logs back to file.
		if ( $wp_filesystem ) {
			$wp_filesystem->put_contents( $this->log_file, implode( PHP_EOL, $logs ), FS_CHMOD_FILE );
		}
	}

	/**
	 * Get log entries
	 *
	 * @param int    $limit Number of entries to return.
	 * @param string $level Filter by log level.
	 * @return array Log entries.
	 */
	public function get_logs( $limit = 100, $level = null ) {
		if ( ! file_exists( $this->log_file ) ) {
			return array();
		}

		$logs  = array();
		$lines = file( $this->log_file );

		if ( false === $lines ) {
			return array();
		}

		foreach ( $lines as $line ) {
			if ( count( $logs ) >= $limit ) {
				break;
			}

			if ( preg_match( '/\[(.*?)\] \[(.*?)\] (.*)/', $line, $matches ) ) {
				if ( $level && strtolower( $matches[2] ) !== strtolower( $level ) ) {
					continue;
				}

				$logs[] = array(
					'timestamp' => $matches[1],
					'level'     => $matches[2],
					'message'   => trim( $matches[3] ),
				);
			}
		}

		return $logs;
	}

	/**
	 * Clear log file
	 */
	public function clear_logs() {
		if ( file_exists( $this->log_file ) ) {
			wp_delete_file( $this->log_file );
		}
	}

	/**
	 * Export logs as CSV
	 *
	 * @return string CSV content.
	 */
	public function export_logs_csv() {
		global $wp_filesystem;

		if ( empty( $wp_filesystem ) ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';

			\WP_Filesystem();
		}

		if ( ! $wp_filesystem ) {
			return '';
		}

		$logs = $this->get_logs( PHP_INT_MAX );
		if ( empty( $logs ) ) {
			return '';
		}

		$csv_file = wp_tempnam(); // Generate a temporary file.

		if ( ! $csv_file ) {
			return '';
		}

		$csv_content = "Timestamp,Level,Message\n";

		foreach ( $logs as $log ) {
			$csv_content .= "{$log['timestamp']},{$log['level']},\"{$log['message']}\"\n";
		}

		$wp_filesystem->put_contents( $csv_file, $csv_content, FS_CHMOD_FILE );

		$content = $wp_filesystem->get_contents( $csv_file );

		$wp_filesystem->delete( $csv_file ); // Clean up temp file.

		return $content;
	}
}
