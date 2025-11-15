<?php
/**
 * Handles communication with Cloudflare's API.
 *
 * @author Polar Mass
 * @since 1.0.0
 * @package polar-mass-advanced-ip-blocker
 */

namespace Pm_Ip_Blocker;

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Cloudflare_Api
 *
 * Provides methods to interact with Cloudflare API.
 */
class Cloudflare_Api {
	/**
	 * Cloudflare API token.
	 *
	 * @var string
	 */
	private $api_token;

	/**
	 * Logger instance.
	 *
	 * @var Logger
	 */
	private $logger;

	/**
	 * Number of retry attempts for API requests.
	 *
	 * @var int
	 */
	private $retry_attempts = 3;

	/**
	 * Maximum expression size allowed by Cloudflare.
	 *
	 * @var int
	 */
	private $max_expression_size = 4096;

	/**
	 * Get unique rule description for this plugin
	 *
	 * @return string Unique rule description.
	 */
	private function get_rule_description() {
		$site_url = get_site_url();
		$domain   = wp_parse_url( $site_url, PHP_URL_HOST );
		if ( ! $domain ) {
			$domain = 'default';
		}
		$domain = strtolower( $domain );
		$domain = preg_replace( '/[^a-z0-9.-]/', '_', $domain );
		return 'MaliciousIPs - Polar Mass Advanced IP Blocker (' . substr( $domain, 0, 40 ) . ')';
	}

	/**
	 * Constructor
	 *
	 * @param Logger $logger Logger instance.
	 */
	public function __construct( Logger $logger ) {
		$this->logger    = $logger;
		$this->api_token = get_option( 'pmip_api_token' );
	}

	/**
	 * Get unique list name for this plugin
	 *
	 * @return string Unique list name.
	 */
	private function get_list_name() {
		$zone_id  = get_option( 'pmip_zone_id' );
		$site_url = get_site_url();
		$domain   = wp_parse_url( $site_url, PHP_URL_HOST );
		if ( ! $domain ) {
			$domain = 'default';
		}
		$domain = strtolower( $domain );
		$domain = preg_replace( '/[^a-z0-9_]/', '_', $domain );
		return 'pmip_' . substr( $domain, 0, 45 );
	}

	/**
	 * Get account ID from zone info
	 *
	 * @return string|false Account ID or false on failure.
	 */
	private function get_account_id() {
		$account_id = get_option( 'pmip_account_id' );
		if ( ! empty( $account_id ) ) {
			return $account_id;
		}

		// Try to get account_id from zone.
		$zone_id = get_option( 'pmip_zone_id' );
		if ( empty( $zone_id ) ) {
			return false;
		}

		try {
			$endpoint = "https://api.cloudflare.com/client/v4/zones/{$zone_id}";
			$response = $this->make_request( 'GET', $endpoint );

			if ( isset( $response['success'] ) && true === $response['success'] && isset( $response['result']['account']['id'] ) ) {
				$account_id = $response['result']['account']['id'];
				update_option( 'pmip_account_id', $account_id );
				return $account_id;
			}
		} catch ( \Exception $e ) {
			$this->logger->log( '[Cloudflare] Failed to get account ID: ' . $e->getMessage(), 'error' );
		}

		return false;
	}

	/**
	 * Get all IP lists from Cloudflare
	 *
	 * @return array Result array with lists and plugin list info.
	 */
	public function get_ip_lists() {
		$account_id = $this->get_account_id();
		if ( ! $account_id ) {
			return array(
				'success' => false,
				'message' => __( 'Account ID not found. Please ensure zone is configured.', 'polar-mass-advanced-ip-blocker' ),
			);
		}

		try {
			$endpoint = "https://api.cloudflare.com/client/v4/accounts/{$account_id}/rules/lists";
			$response = $this->make_request( 'GET', $endpoint );

			if ( isset( $response['success'] ) && true === $response['success'] && isset( $response['result'] ) ) {
				$all_lists   = $response['result'];
				$plugin_list = null;
				$list_name   = $this->get_list_name();

				// Find list created by this plugin.
				foreach ( $all_lists as $list ) {
					if ( isset( $list['name'] ) && $list_name === $list['name'] && isset( $list['kind'] ) && 'ip' === $list['kind'] ) {
						$plugin_list = $list;
						break;
					}
				}

				return array(
					'success'     => true,
					'total_lists' => count( $all_lists ),
					'plugin_list' => $plugin_list,
					'all_lists'   => $all_lists,
				);
			}

			return array(
				'success' => false,
				'message' => __( 'Failed to retrieve IP lists.', 'polar-mass-advanced-ip-blocker' ),
			);
		} catch ( \Exception $e ) {
			$this->logger->log( '[Cloudflare] Failed to get IP lists: ' . $e->getMessage(), 'error' );
			return array(
				'success' => false,
				'message' => $e->getMessage(),
			);
		}
	}

	/**
	 * Create IP list in Cloudflare
	 *
	 * @return array Result array with list_id on success.
	 */
	public function create_ip_list() {
		$account_id = $this->get_account_id();
		if ( ! $account_id ) {
			return array(
				'success' => false,
				'message' => __( 'Account ID not found. Please ensure zone is configured.', 'polar-mass-advanced-ip-blocker' ),
			);
		}

		$list_name = $this->get_list_name();

		try {
			$endpoint = "https://api.cloudflare.com/client/v4/accounts/{$account_id}/rules/lists";
			$data     = array(
				'kind'        => 'ip',
				'name'        => $list_name,
				'description' => 'IP list created by Polar Mass Advanced IP Blocker plugin',
			);

			$response = $this->make_request( 'POST', $endpoint, $data );

			if ( isset( $response['success'] ) && true === $response['success'] && isset( $response['result']['id'] ) ) {
				$list_id = $response['result']['id'];
				update_option( 'pmip_ip_list_id', $list_id );
				return array(
					'success' => true,
					'list_id' => $list_id,
					'message' => __( 'IP list created successfully.', 'polar-mass-advanced-ip-blocker' ),
				);
			}

			$error_message = isset( $response['errors'][0]['message'] ) ? $response['errors'][0]['message'] : __( 'Unknown error', 'polar-mass-advanced-ip-blocker' );
			return array(
				'success' => false,
				'message' => $error_message,
			);
		} catch ( \Exception $e ) {
			$this->logger->log( '[Cloudflare] Failed to create IP list: ' . $e->getMessage(), 'error' );
			return array(
				'success' => false,
				'message' => $e->getMessage(),
			);
		}
	}

	/**
	 * Update IP list items
	 *
	 * @param string $list_id List ID.
	 * @param array  $ip_list Array of IP addresses.
	 * @return bool Success status.
	 */
	private function update_ip_list_items( $list_id, $ip_list ) {
		$account_id = $this->get_account_id();
		if ( ! $account_id ) {
			$this->logger->log( '[Cloudflare] Account ID not found for updating IP list', 'error' );
			return false;
		}

		try {
			$endpoint = "https://api.cloudflare.com/client/v4/accounts/{$account_id}/rules/lists/{$list_id}/items";

			// Prepare items array.
			$items = array();
			foreach ( $ip_list as $ip ) {
				$items[] = array(
					'ip' => $ip,
				);
			}

			// Use PUT to replace all items.
			$response = $this->make_request( 'PUT', $endpoint, $items );

			if ( isset( $response['success'] ) && true === $response['success'] ) {
				// Check operation status if operation_id is returned.
				if ( isset( $response['result']['operation_id'] ) ) {
					return $this->wait_for_bulk_operation( $account_id, $response['result']['operation_id'] );
				}
				return true;
			}

			return false;
		} catch ( \Exception $e ) {
			$this->logger->log( '[Cloudflare] Failed to update IP list items: ' . $e->getMessage(), 'error' );
			return false;
		}
	}

	/**
	 * Wait for bulk operation to complete
	 *
	 * @param string $account_id Account ID.
	 * @param string $operation_id Operation ID.
	 * @param int    $max_wait Maximum wait time in seconds.
	 * @return bool Success status.
	 */
	private function wait_for_bulk_operation( $account_id, $operation_id, $max_wait = 30 ) {
		$endpoint   = "https://api.cloudflare.com/client/v4/accounts/{$account_id}/rules/lists/bulk_operations/{$operation_id}";
		$start_time = time();

		while ( ( time() - $start_time ) < $max_wait ) {
			try {
				$response = $this->make_request( 'GET', $endpoint );

				if ( isset( $response['success'] ) && true === $response['success'] && isset( $response['result']['status'] ) ) {
					$status = $response['result']['status'];

					if ( 'completed' === $status ) {
						return true;
					} elseif ( 'failed' === $status ) {
						$error = isset( $response['result']['error'] ) ? $response['result']['error'] : 'Unknown error';
						$this->logger->log( '[Cloudflare] Bulk operation failed: ' . $error, 'error' );
						return false;
					}
				}

				sleep( 2 ); // Wait 2 seconds before checking again.
			} catch ( \Exception $e ) {
				$this->logger->log( '[Cloudflare] Error checking bulk operation: ' . $e->getMessage(), 'error' );
				return false;
			}
		}

		$this->logger->log( '[Cloudflare] Bulk operation timeout after ' . $max_wait . ' seconds', 'error' );
		return false;
	}

	/**
	 * Build expression with IP list.
	 *
	 * @param array $ip_list Array of IP addresses.
	 * @return array Array with 'expression' and 'truncated_count' keys.
	 */
	private function build_expression_with_limit( $ip_list ) {
		$base_expression = '(ip.src in {';
		$closing         = '})';
		$base_length     = strlen( $base_expression ) + strlen( $closing );
		$max_ip_length   = $this->max_expression_size - $base_length;

		$ip_string   = implode( ' ', $ip_list );
		$full_length = strlen( $ip_string );

		if ( ( $base_length + $full_length ) <= $this->max_expression_size ) {
			return array(
				'expression'      => $base_expression . $ip_string . $closing,
				'truncated_count' => 0,
				'original_count'  => count( $ip_list ),
			);
		}

		$truncated_ips   = array();
		$current_length  = 0;
		$truncated_count = 0;

		foreach ( $ip_list as $ip ) {
			$ip_with_separator = ( $current_length > 0 ? ' ' : '' ) . $ip;
			$ip_length         = strlen( $ip_with_separator );

			if ( ( $base_length + $current_length + $ip_length ) > $this->max_expression_size ) {
				break;
			}

			$truncated_ips[] = $ip;
			$current_length += $ip_length;
		}

		$truncated_count = count( $ip_list ) - count( $truncated_ips );
		$expression      = $base_expression . implode( ' ', $truncated_ips ) . $closing;

		return array(
			'expression'      => $expression,
			'truncated_count' => $truncated_count,
			'original_count'  => count( $ip_list ),
		);
	}

	/**
	 * Block multiple IP addresses
	 *
	 * @param array $blocked_ips Array of IP addresses to block.
	 * @return bool Success status.
	 */
	public function block_ips( $blocked_ips ) {
		$use_ip_list = get_option( 'pmip_use_ip_list', 'false' ) === 'true';

		if ( $use_ip_list ) {
			return $this->block_ips_using_list( $blocked_ips );
		}

		return $this->block_ips_using_expression( $blocked_ips );
	}

	/**
	 * Block IPs using Cloudflare IP list
	 *
	 * @param array $blocked_ips Array of IP addresses to block.
	 * @return bool Success status.
	 */
	private function block_ips_using_list( $blocked_ips ) {
		$zone_id    = get_option( 'pmip_zone_id' );
		$ruleset_id = get_option( 'pmip_ruleset_id' );
		$rule_id    = get_option( 'pmip_rule_id' );
		$list_id    = get_option( 'pmip_ip_list_id' );

		if ( ! $zone_id || ! $ruleset_id || ! $rule_id ) {
			$this->logger->log( '[Cloudflare] Missing required Cloudflare configuration', 'error' );
			return false;
		}

		if ( empty( $list_id ) ) {
			$lists_data = $this->get_ip_lists();
			if ( $lists_data['success'] && ! empty( $lists_data['plugin_list'] ) ) {
				$list_id = $lists_data['plugin_list']['id'];
				update_option( 'pmip_ip_list_id', $list_id );
				$this->logger->log( '[Cloudflare] Found existing IP list: ' . $list_id, 'info' );
			} else {
				$create_result = $this->create_ip_list();
				if ( ! $create_result['success'] ) {
					$this->logger->log( '[Cloudflare] Failed to create IP list: ' . $create_result['message'], 'error' );
					return false;
				}
				$list_id = $create_result['list_id'];
			}
		}

		// Update IP list items.
		$ip_list = array_keys( $blocked_ips );
		if ( ! $this->update_ip_list_items( $list_id, $ip_list ) ) {
			$this->logger->log( '[Cloudflare] Failed to update IP list items', 'error' );
			return false;
		}

		// Get list name.
		$list_name = $this->get_list_name();

		// Update rule expression to use IP list.
		$endpoint   = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/rulesets/{$ruleset_id}/rules/{$rule_id}";
		$expression = "(ip.src in \${$list_name})";

		$data = array(
			'action'      => 'block',
			'description' => $this->get_rule_description(),
			'enabled'     => true,
			'expression'  => $expression,
			'id'          => $rule_id,
			'ref'         => $rule_id,
			'version'     => '7',
		);

		$response = $this->make_request( 'PATCH', $endpoint, $data );

		if ( isset( $response['success'] ) && true === $response['success'] ) {
			return true;
		}

		return false;
	}

	/**
	 * Block IPs using inline expression (original method)
	 *
	 * @param array $blocked_ips Array of IP addresses to block.
	 * @return bool Success status.
	 */
	private function block_ips_using_expression( $blocked_ips ) {
		$zone_id    = get_option( 'pmip_zone_id' );
		$ruleset_id = get_option( 'pmip_ruleset_id' );
		$rule_id    = get_option( 'pmip_rule_id' );

		if ( ! $zone_id || ! $ruleset_id || ! $rule_id ) {
			$this->logger->log( '[Cloudflare] Missing required Cloudflare configuration', 'error' );
			return false;
		}

		$endpoint = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/rulesets/{$ruleset_id}/rules/{$rule_id}";

		// Build expression with all IPs.
		$ip_list    = array_keys( $blocked_ips );
		$result     = $this->build_expression_with_limit( $ip_list );
		$expression = $result['expression'];

		$data     = array(
			'action'      => 'block',
			'description' => $this->rule_name,
			'enabled'     => true,
			'expression'  => $expression,
			'id'          => $rule_id,
			'ref'         => $rule_id,
			'version'     => '7',
		);
		$response = $this->make_request( 'PATCH', $endpoint, $data );

		if ( isset( $response['success'] ) && true === $response['success'] ) {
			return true;
		}

		return false;
	}

	/**
	 * Block an IP address
	 *
	 * @param string $ip IP address to block.
	 * @return bool Success status.
	 */
	public function block_ip( $ip ) {
		return $this->block_ips( array( $ip ) );
	}

	/**
	 * Unblock an IP address
	 *
	 * @param string $ip IP address to unblock.
	 * @return bool Success status.
	 */
	public function unblock_ip( $ip ) {
		$use_ip_list = get_option( 'pmip_use_ip_list', 'false' ) === 'true';

		if ( $use_ip_list ) {
			return $this->unblock_ip_using_list( $ip );
		}

		return $this->unblock_ip_using_expression( $ip );
	}

	/**
	 * Unblock IP using Cloudflare IP list
	 *
	 * @param string $ip IP address to unblock.
	 * @return bool Success status.
	 */
	private function unblock_ip_using_list( $ip ) {
		$zone_id    = get_option( 'pmip_zone_id' );
		$ruleset_id = get_option( 'pmip_ruleset_id' );
		$rule_id    = get_option( 'pmip_rule_id' );
		$list_id    = get_option( 'pmip_ip_list_id' );

		if ( ! $zone_id || ! $ruleset_id || ! $rule_id || ! $list_id ) {
			$this->logger->log( '[Cloudflare] Missing required Cloudflare configuration', 'error' );
			return false;
		}

		// Get blocked IPs from database.
		$blocked_ips = get_option( 'pmip_blocked_ips', array() );

		// Remove IP from list.
		if ( isset( $blocked_ips[ $ip ] ) ) {
			unset( $blocked_ips[ $ip ] );
		}

		// Update IP list items with remaining IPs.
		$ip_list = array_keys( $blocked_ips );
		if ( ! $this->update_ip_list_items( $list_id, $ip_list ) ) {
			$this->logger->log( '[Cloudflare] Failed to update IP list items', 'error' );
			return false;
		}

		update_option( 'pmip_blocked_ips', $blocked_ips );
		return true;
	}

	/**
	 * Unblock IP using inline expression (original method)
	 *
	 * @param string $ip IP address to unblock.
	 * @return bool Success status.
	 */
	private function unblock_ip_using_expression( $ip ) {
		$zone_id    = get_option( 'pmip_zone_id' );
		$ruleset_id = get_option( 'pmip_ruleset_id' );
		$rule_id    = get_option( 'pmip_rule_id' );

		if ( ! $zone_id || ! $ruleset_id || ! $rule_id ) {
			$this->logger->log( '[Cloudflare] Missing required Cloudflare configuration', 'error' );
			return false;
		}

		$endpoint = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/rulesets/{$ruleset_id}/rules/{$rule_id}";

		// Get blocked IPs from database.
		$blocked_ips = get_option( 'pmip_blocked_ips', array() );

		// Remove IP from list.
		if ( isset( $blocked_ips[ $ip ] ) ) {
			unset( $blocked_ips[ $ip ] );
		}

		// Build expression with remaining IPs.
		$ip_list    = array_keys( $blocked_ips );
		$result     = $this->build_expression_with_limit( $ip_list );
		$expression = $result['expression'];

		$data = array(
			'action'      => 'block',
			'description' => $this->get_rule_description(),
			'enabled'     => true,
			'expression'  => $expression,
			'id'          => $rule_id,
			'ref'         => $rule_id,
			'version'     => '7',
		);

		$response = $this->make_request( 'PATCH', $endpoint, $data );

		if ( isset( $response['success'] ) && true === $response['success'] ) {
			update_option( 'pmip_blocked_ips', $blocked_ips );
			return true;
		}

		return false;
	}

	/**
	 * Make an API request with exponential backoff retry
	 *
	 * @param string $method HTTP method.
	 * @param string $endpoint API endpoint.
	 * @param array  $data Request data.
	 * @param int    $attempt Current attempt number.
	 * @return array Response data.
	 * @throws \Exception If request fails after all attempts.
	 */
	private function make_request( $method, $endpoint, $data = array(), $attempt = 1 ) {
		if ( empty( $this->api_token ) ) {
			throw new \Exception( 'Cloudflare API token not configured' );
		}

		$args = array(
			'method'  => $method,
			'headers' => array(
				'Authorization' => 'Bearer ' . $this->api_token,
				'Content-Type'  => 'application/json',
			),
			'timeout' => 30,
		);

		if ( ! empty( $data ) ) {
			if ( 'GET' === $method ) {
				$endpoint = add_query_arg( $data, $endpoint );
			} else {
				$args['body'] = wp_json_encode( $data );
			}
		}

		$response = wp_remote_request( $endpoint, $args );

		if ( is_wp_error( $response ) ) {
			$this->logger->log( '[Cloudflare] API request failed: ' . $response->get_error_message(), 'error' );

			if ( $attempt < $this->retry_attempts ) {
				sleep( pow( 2, $attempt - 1 ) ); // Exponential backoff.
				return $this->make_request( $method, $endpoint, $data, $attempt + 1 );
			}

			throw new \Exception( esc_html( 'API request failed after ' . $this->retry_attempts . ' attempts' ) );
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( json_last_error() !== JSON_ERROR_NONE ) {
			throw new \Exception( 'Invalid JSON response from API' );
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		if ( 429 === $status_code ) { // Rate limit hit.
			if ( $attempt < $this->retry_attempts ) {
				$retry_after = wp_remote_retrieve_header( $response, 'retry-after' );
				sleep( $retry_after ? intval( $retry_after ) : pow( 2, $attempt - 1 ) );
				return $this->make_request( $method, $endpoint, $data, $attempt + 1 );
			}
			throw new \Exception( 'Rate limit exceeded' );
		}

		if ( $status_code >= 400 ) {
			$error_message = isset( $data['errors'][0]['message'] ) ? $data['errors'][0]['message'] : 'Unknown error';
			throw new \Exception( esc_html( 'API error: ' . $error_message ) );
		}

		return $data;
	}
}
