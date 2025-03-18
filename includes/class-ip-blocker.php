<?php
/**
 * IP Blocker Class
 *
 * Handles blocking of malicious IP addresses using Cloudflare.
 *
 * @author Polar Mass
 * @since 1.0.0
 * @package polar-mass-advanced-ip-blocker
 */

namespace Pm_Ip_Blocker;

/**
 * Class Ip_Blocker
 *
 * Provides functionality to block IPs via Cloudflare.
 */
class Ip_Blocker {
	/**
	 * Logger instance
	 *
	 * @var Logger
	 */
	private $logger;

	/**
	 * Blocked IPs
	 *
	 * @var array
	 */
	private $blocked_ips = array();

	/**
	 * New IPs to block
	 *
	 * @var array
	 */
	private $new_ips_to_block = array();

	/**
	 * Cloudflare API instance
	 *
	 * @var Cloudflare_Api
	 */
	private $cloudflare;

	/**
	 * Constructor
	 *
	 * @param Logger $logger Logger instance.
	 */
	public function __construct( Logger $logger ) {
		$this->logger      = $logger;
		$this->cloudflare  = new Cloudflare_Api( $logger );
		$this->blocked_ips = get_option( 'pmip_blocked_ips', array() );
	}

	/**
	 * Sync blocked IPs from Wordfence.
	 */
	public function sync_from_wordfence() {
		if ( ! class_exists( 'wfActivityReport' ) ) {
			$this->logger->log( '[Wordfence Sync] Wordfence not installed or activated', 'error' );
			return false;
		}

		try {
			$activity_report = new \wfActivityReport();

			// Get blocked IPs from last 24 hours, 7 days, and 30 days.
			$ips24h = (array) $activity_report->getTopIPsBlocked( 100, 1 );
			$ips7d  = (array) $activity_report->getTopIPsBlocked( 100, 7 );
			$ips30d = (array) $activity_report->getTopIPsBlocked( 100, 30 );

			// Process and normalize the data.
			$threshold    = get_option( 'pmip_failed_attempts', 5 );
			$ips_to_block = array();

			foreach ( array( $ips24h, $ips7d, $ips30d ) as $ip_list ) {
				foreach ( $ip_list as $entry ) {
					$entry = (array) $entry;
					if ( $entry['blockCount'] >= $threshold ) {
						$ips_to_block[] = \wfUtils::inet_ntop( $entry['IP'] );
					}
				}
			}

			// Remove duplicates.
			$ips_to_block = array_unique( $ips_to_block );

			if ( empty( $ips_to_block ) ) {
				$this->logger->log( '[Wordfence Sync] No IPs to block', 'info' );
				return true;
			}

			// Block IPs in bulk.
			$result = $this->block_ips( $ips_to_block );

			if ( $result ) {
				$this->logger->log( '[Wordfence Sync] Successfully synced IPs from Wordfence' );
				return true;
			} else {
				$this->logger->log( '[Wordfence Sync] Failed to sync IPs from Wordfence', 'error' );
				return false;
			}
		} catch ( \Exception $e ) {
			$this->logger->log( '[Wordfence Sync] Error syncing IPs from Wordfence: ' . $e->getMessage(), 'error' );
			return false;
		}
	}

	/**
	 * Handle Wordfence security events
	 *
	 * @param string $event Event type.
	 * @param array  $data Event data.
	 */
	public function handle_wordfence_event( $event, $data ) {
		// Validate event and required data.
		if ( ! in_array( $event, array( 'increasedAttackRate', 'loginLockout', 'block' ), true ) || empty( $data['ip'] ) ) {
			return;
		}

		$ip         = $data['ip'];
		$event_text = '';
		if ( 'increasedAttackRate' === $event ) {
			$event_text = 'increased attack rate';
		} elseif ( 'loginLockout' === $event ) {
			$event_text = 'login lockout';
		} elseif ( 'block' === $event ) {
			$event_text = 'block';
		}

		$this->logger->log( "[Wordfence] {$event_text} for IP {$ip}" );
		$threshold = (int) get_option( 'pmip_failed_attempts', 5 ); // Ensure threshold is an integer.

		// If attackCount is set and exceeds the threshold, block immediately.
		if ( ! empty( $data['attackCount'] ) ) {
			if ( (int) $data['attackCount'] >= $threshold ) {
				$result = $this->sync_from_wordfence();
				if ( $result ) {
					$this->logger->log( "[Wordfence] IP {$ip} exceeded threshold, blocked" );
				} else {
					$this->logger->log( '[Wordfence] Failed to sync IPs from Wordfence', 'error' );
				}
			}
			/**
			 * This IP is already blocked by Cloudflare's custom rules, so there's no need for Wordfence to send an alert.  
			 * Since Wordfence still detects and reports it as a threat (causing false positives), we disable its alert callback.  
			 */
			remove_action('wordfence_security_event', 'wfCentral::sendAlertCallback', 10, 3); 
			return false;
		}

		// Retrieve failed attempts safely.
		$failed_attempts_data = $this->get_failed_attempts( $ip );

		if ( $this->is_block_expired( $failed_attempts_data ) ) {
			// Expired, reset to 1.
			$failed_attempts = 1;
		} else {
			// Still valid, increment count.
			$failed_attempts = (int) $failed_attempts_data['count'] + 1;
		}

		// Update the failed attempts count.
		$this->update_failed_attempts( $ip, $failed_attempts );

		// Block if threshold is reached.
		if ( $failed_attempts >= $threshold ) {
			$result = $this->sync_from_wordfence();
			if ( $result ) {
				$this->logger->log( "[Wordfence] IP {$ip} exceeded threshold, blocked" );
			} else {
				$this->logger->log( '[Wordfence] Failed to sync IPs from Wordfence', 'error' );
			}
		}
	}

	/**
	 * Get failed login attempts and block info for an IP.
	 *
	 * @param string $ip The IP address to check.
	 * @return array An array containing 'count' (int), 'timestamp' (int|null), and 'duration' (string|null).
	 */
	private function get_failed_attempts( $ip ) {
		$attempts = get_option( 'pmip_failed_attempts_log', array() );
		return isset( $attempts[ $ip ] ) ? $attempts[ $ip ] : array(
			'count'     => 0,
			'timestamp' => null,
			'duration'  => null,
		);
	}

	/**
	 * Update the failed login attempts for an IP address.
	 * Stores the count, timestamp, and block duration.
	 *
	 * @param string $ip The IP address to track.
	 * @param int    $count The number of failed attempts.
	 */
	private function update_failed_attempts( $ip, $count ) {
		$attempts = get_option( 'pmip_failed_attempts_log', array() );

		if ( 1 === $count ) {
			// If this is the first failure, store the timestamp.
			$attempts[ $ip ] = array(
				'count'     => $count,
				'timestamp' => time(),
				'duration'  => get_option( 'pmip_block_duration', '24h' ),
			);
		} elseif ( isset( $attempts[ $ip ] ) ) {
			// Otherwise, just update the count.
			$attempts[ $ip ]['count'] = $count;
		} else {
			$attempts[ $ip ] = array(
				'count'     => $count,
				'timestamp' => time(),
				'duration'  => get_option( 'pmip_block_duration', '24h' ),
			);
		}

		update_option( 'pmip_failed_attempts_log', $attempts );
	}

	/**
	 * Block multiple IP addresses
	 *
	 * @param array $ips IP addresses to block.
	 * @return bool Success status.
	 */
	public function block_ips( $ips ) {
		try {

			if ( empty( $ips ) ) {
				$this->logger->log( '[IP Blocker] No IPs to block', 'info' );
				return true;
			}

			foreach ( $ips as $ip ) {
				if ( ! isset( $this->blocked_ips[ $ip ] ) ) {
					$this->blocked_ips[ $ip ] = array(
						'timestamp' => time(),
						'duration'  => get_option( 'pmip_block_duration', '24h' ),
					);
					$this->new_ips_to_block[] = $ip;
				}
			}
			update_option( 'pmip_blocked_ips', $this->blocked_ips );
			$result = $this->cloudflare->block_ips( $this->blocked_ips );
			if ( $result ) {
				$count_new = count( $this->new_ips_to_block );
				$count_all = count( $this->blocked_ips );
				if ( $count_new > 0 ) {
					$this->logger->log( "[IP Blocker] Blocked {$count_new} new IPs. Total blocked: {$count_all}" );
				} else {
					$this->logger->log( "[IP Blocker] No new IPs to block. Total blocked: {$count_all}" );
				}
				return true;
			}

			$this->logger->log( '[IP Blocker] Failed to block IPs', 'error' );
			return false;
		} catch ( \Exception $e ) {
			$this->logger->log( '[IP Blocker] Error blocking IPs: ' . $e->getMessage(), 'error' );
			return false;
		}
	}

	/**
	 * Block an IP address
	 *
	 * @param string $ip IP address to block.
	 * @return bool Success status.
	 */
	public function block_ip( $ip ) {
		try {
			if ( $this->is_whitelisted( $ip ) ) {
				$this->logger->log( "[IP Blocker] IP {$ip} is whitelisted, skipping block" );
				return false;
			}

			if ( $this->is_blocked( $ip ) ) {
				$this->logger->log( "[IP Blocker] IP {$ip} is already blocked" );
				return true;
			}

			$result = $this->cloudflare->block_ip( $ip );
			if ( $result ) {
				$this->blocked_ips[ $ip ] = array(
					'timestamp' => time(),
					'duration'  => get_option( 'pmip_block_duration', '24h' ),
				);
				update_option( 'pmip_blocked_ips', $this->blocked_ips );
				$this->logger->log( "[IP Blocker] Blocked IP: {$ip}" );
				return true;
			}

			$this->logger->log( "[IP Blocker] Failed to block IP: {$ip}" );
			return false;
		} catch ( \Exception $e ) {
			$this->logger->log( "[IP Blocker] Error blocking IP {$ip}: " . $e->getMessage(), 'error' );
			return false;
		}
	}

	/**
	 * Unblock an IP address
	 *
	 * @param string $ip IP address to unblock.
	 * @return bool Success status.
	 */
	public function unblock_ip( $ip ) {
		try {
			if ( ! $this->is_blocked( $ip ) ) {
				$this->logger->log( "[IP Blocker] IP {$ip} is not blocked" );
				return true;
			}

			$result = $this->cloudflare->unblock_ip( $ip );
			if ( $result ) {
				unset( $this->blocked_ips[ $ip ] );
				update_option( 'pmip_blocked_ips', $this->blocked_ips );
				$this->logger->log( "[IP Blocker] Unblocked IP: {$ip}" );
				return true;
			}

			$this->logger->log( "[IP Blocker] Failed to unblock IP: {$ip}", 'error' );
			return false;
		} catch ( \Exception $e ) {
			$this->logger->log( "[IP Blocker] Error unblocking IP {$ip}: " . $e->getMessage(), 'error' );
			return false;
		}
	}

	/**
	 * Check if an IP is blocked
	 *
	 * @param string $ip IP address to check.
	 * @return bool Whether IP is blocked.
	 */
	public function is_blocked( $ip ) {
		return isset( $this->blocked_ips[ $ip ] );
	}

	/**
	 * Check if an IP is whitelisted
	 *
	 * @param string $ip IP address to check.
	 * @return bool Whether IP is whitelisted.
	 */
	public function is_whitelisted( $ip ) {
		$whitelist = get_option( 'pmip_ip_whitelist', array() );
		return in_array( $ip, $whitelist, true );
	}

	/**
	 * Check and block IPs based on failed login attempts
	 */
	public function check_and_block_ips() {
		if ( get_option( 'pmip_plugin_status', 'inactive' ) !== 'active' ) {
			return;
		}

		$this->cleanup_blocked_ips();

		$this->sync_from_wordfence();
	}

	/**
	 * Real-time block IPs
	 *
	 * This function is called by a cron job to block IPs in real-time based on Wordfence hits.
	 */
	public function real_time_block_ips() {
		if ( ! class_exists( 'wfDB' ) ) {
			$this->logger->log( '[Real-time] Wordfence not installed or activated', 'error' );
			return false;
		}
		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		global $wpdb;
		$table_wfHits = esc_sql( \wfDB::networkTable( 'wfHits' ) ); // Escape table name manually
		$search_term  = '%block%'; // Add wildcards to the variable

		$sql = "
		SELECT 
		action,
		COUNT(*) AS attack_count,
			CASE 
				WHEN LENGTH(ip) = 16 
				AND SUBSTRING(ip, 1, 12) = UNHEX('00000000000000000000FFFF') 
				THEN INET_NTOA(CONV(HEX(SUBSTRING(ip, 13, 4)), 16, 10))
				ELSE INET6_NTOA(ip)
			END AS ip_text
		FROM $table_wfHits
		WHERE action LIKE %s
		GROUP BY ip_text, action, 
			UNIX_TIMESTAMP(FROM_UNIXTIME(FLOOR(attackLogTime))) DIV 60
		HAVING attack_count > 10
		ORDER BY UNIX_TIMESTAMP(FROM_UNIXTIME(FLOOR(attackLogTime))) DIV 60 DESC";

		// Only prepare the user input (no placeholders for table names)
		$results = $wpdb->get_results( $wpdb->prepare( $sql, $search_term ) );
		// phpcs:enable

		if ( $results ) {
			$ips_to_block = array();
			foreach ( $results as $result ) {
				$ip             = $result->ip_text;
				$ips_to_block[] = $ip;
				if ( ! isset( $this->blocked_ips[ $ip ] ) ) {
					$this->logger->log( "[Real-time] IP {$ip} blocked" );
				}
			}

			if ( ! empty( $ips_to_block ) ) {
				$result = $this->block_ips( $ips_to_block );
				if ( $result ) {
					$this->logger->log( '[Real-time] Successfully checked IPs in real-time' );
				} else {
					$this->logger->log( '[Real-time] Failed to check IPs in real-time', 'error' );
				}
			}
		}
	}

	/**
	 * Clean up expired IP blocks
	 *
	 * @param bool $force Whether to force cleanup.
	 */
	private function cleanup_blocked_ips( $force = false ) {
		if ( $force ) {
			$this->blocked_ips = array();
			update_option( 'pmip_blocked_ips', $this->blocked_ips );
			return;
		}
		$modified = false;
		foreach ( $this->blocked_ips as $ip => $data ) {
			if ( $this->is_block_expired( $data ) ) {
				$this->unblock_ip( $ip );
				$modified = true;
			}
		}

		if ( $modified ) {
			update_option( 'pmip_blocked_ips', $this->blocked_ips );
		}
	}

	/**
	 * Check if an IP block has expired
	 *
	 * @param array $data Block data.
	 * @return bool Whether block has expired.
	 */
	private function is_block_expired( $data ) {
		$duration = $this->parse_duration( $data['duration'] );
		return ( time() - $data['timestamp'] ) > $duration;
	}

	/**
	 * Parse duration string to seconds
	 *
	 * @param string $duration Duration string (e.g., "24h", "7d", "permanent").
	 * @return int Duration in seconds.
	 */
	private function parse_duration( $duration ) {
		if ( 'permanent' === $duration ) {
			return PHP_INT_MAX;
		}

		$unit  = substr( $duration, -1 );
		$value = intval( substr( $duration, 0, -1 ) );

		switch ( $unit ) {
			case 'h':
				return $value * 3600;
			case 'd':
				return $value * 86400;
			default:
				return 86400; // Default to 24 hours.
		}
	}
}
