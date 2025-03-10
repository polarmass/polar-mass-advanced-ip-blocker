<?php
/**
 * Handles communication with Cloudflare's API.
 *
 * @author Polar Mass
 * @since 1.0.0
 * @package cloudflare-ip-blocker
 */

namespace Cloudflare_Ip_Blocker;

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
	 * Rule name for IP blocking.
	 *
	 * @var string
	 */
	private $rule_name = 'MaliciousIPs - Polar Mass Advanced IP Blocker';

	/**
	 * Constructor
	 *
	 * @param Logger $logger Logger instance.
	 */
	public function __construct( Logger $logger ) {
		$this->logger    = $logger;
		$this->api_token = get_option( 'cfip_api_token' );
	}

	/**
	 * Block multiple IP addresses
	 *
	 * @param array $ips Array of IP addresses to block.
	 * @return bool Success status.
	 */
	public function block_ips( $ips ) {
		$zone_id    = get_option( 'cfip_zone_id' );
		$ruleset_id = get_option( 'cfip_ruleset_id' );
		$rule_id    = get_option( 'cfip_rule_id' );

		if ( ! $zone_id || ! $ruleset_id || ! $rule_id ) {
			$this->logger->log( 'Missing required Cloudflare configuration', 'error' );
			return false;
		}

		$endpoint = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/rulesets/{$ruleset_id}/rules/{$rule_id}";

		// Get blocked IPs from database.
		$blocked_ips = get_option( 'cfip_blocked_ips', array() );

		// Add new IPs if not already blocked.
		foreach ( $ips as $ip ) {
			if ( ! isset( $blocked_ips[ $ip ] ) ) {
				$blocked_ips[ $ip ] = array(
					'timestamp' => time(),
					'duration'  => get_option( 'cfip_block_duration', '24h' ),
				);
			}
		}

		// Build expression with all IPs.
		$ip_list    = array_keys( $blocked_ips );
		$expression = '(ip.src in {' . implode( ' ', $ip_list ) . '})';

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
			update_option( 'cfip_blocked_ips', $blocked_ips );
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
		$zone_id    = get_option( 'cfip_zone_id' );
		$ruleset_id = get_option( 'cfip_ruleset_id' );
		$rule_id    = get_option( 'cfip_rule_id' );

		if ( ! $zone_id || ! $ruleset_id || ! $rule_id ) {
			$this->logger->log( 'Missing required Cloudflare configuration', 'error' );
			return false;
		}

		$endpoint = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/rulesets/{$ruleset_id}/rules/{$rule_id}";

		// Get blocked IPs from database.
		$blocked_ips = get_option( 'cfip_blocked_ips', array() );

		// Remove IP from list.
		if ( isset( $blocked_ips[ $ip ] ) ) {
			unset( $blocked_ips[ $ip ] );
		}

		// Build expression with remaining IPs.
		$ip_list    = array_keys( $blocked_ips );
		$expression = '(ip.src in {' . implode( ' ', $ip_list ) . '})';

		$data = array(
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
			update_option( 'cfip_blocked_ips', $blocked_ips );
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
			$this->logger->log( 'API request failed: ' . $response->get_error_message(), 'error' );

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
