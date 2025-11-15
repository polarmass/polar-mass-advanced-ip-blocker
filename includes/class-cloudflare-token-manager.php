<?php
/**
 * Handles Cloudflare token management and auto-connect functionality.
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
 * Class Cloudflare_Token_Manager
 *
 * Provides methods for auto-connecting to Cloudflare via API token generation.
 */
class Cloudflare_Token_Manager {
	/**
	 * Logger instance.
	 *
	 * @var Logger
	 */
	private $logger;

	/**
	 * Cloudflare API instance (temporary, for master token operations).
	 *
	 * @var Cloudflare_Api
	 */
	private $api;

	/**
	 * Constructor
	 *
	 * @param Logger $logger Logger instance.
	 */
	public function __construct( Logger $logger ) {
		$this->logger = $logger;
	}

	/**
	 * Auto-connect to Cloudflare: Save master token, reuse or generate scoped token, fetch zones list.
	 *
	 * @param string $master_token Master token with "Create Additional Tokens" permission.
	 * @return array Result array with success status, messages, and zones list.
	 */
	public function auto_connect( $master_token ) {
		update_option( 'pmip_master_token', $master_token );

		try {
			$existing_token = get_option( 'pmip_api_token', '' );

			if ( ! empty( $existing_token ) ) {
				$zones_test = $this->get_zones_list( $existing_token );
				if ( ! empty( $zones_test['zones'] ) ) {
					update_option( 'pmip_auto_connected', true );
					return array(
						'success' => true,
						'message' => __( 'Successfully connected to Cloudflare using existing token! Please select a zone from the list below.', 'polar-mass-advanced-ip-blocker' ),
						'zones'   => $zones_test['zones'],
					);
				}
			}

			$existing_token_id = $this->find_existing_polar_mass_token( $master_token );
			if ( ! empty( $existing_token_id ) ) {
				$stored_token = get_option( 'pmip_api_token', '' );
				if ( ! empty( $stored_token ) ) {
					$zones_test = $this->get_zones_list( $stored_token );
					if ( ! empty( $zones_test['zones'] ) ) {
						update_option( 'pmip_auto_connected', true );
						return array(
							'success' => true,
							'message' => __( 'Successfully connected to Cloudflare using existing token for this domain! Please select a zone from the list below.', 'polar-mass-advanced-ip-blocker' ),
							'zones'   => $zones_test['zones'],
						);
					}
				}
				$this->logger->log( '[Auto-Connect] Existing token found but stored token is invalid. Deleting old token and creating new one.', 'info' );
				$this->delete_token_by_id( $master_token, $existing_token_id );
			}

			$permissions = $this->get_required_permissions( $master_token );

			if ( empty( $permissions ) ) {
				return array(
					'success' => false,
					'message' => __( 'Failed to fetch required permissions. Please ensure your master token has API Tokens Write permission.', 'polar-mass-advanced-ip-blocker' ),
				);
			}

			$scoped_token_data = $this->generate_scoped_token( $master_token, $permissions );

			if ( ! $scoped_token_data || empty( $scoped_token_data['token'] ) ) {
				return array(
					'success' => false,
					'message' => __( 'Failed to generate scoped token. Please check your master token permissions.', 'polar-mass-advanced-ip-blocker' ),
				);
			}

			$scoped_token = $scoped_token_data['token'];
			update_option( 'pmip_api_token', $scoped_token );

			$zones_data = $this->get_zones_list( $scoped_token );

			if ( empty( $zones_data['zones'] ) ) {
				return array(
					'success' => false,
					'message' => __( 'No zones found in your Cloudflare account. Please check your master token permissions.', 'polar-mass-advanced-ip-blocker' ),
				);
			}

			update_option( 'pmip_auto_connected', true );

			return array(
				'success' => true,
				'message' => __( 'Successfully connected to Cloudflare! Please select a zone from the list below.', 'polar-mass-advanced-ip-blocker' ),
				'zones'   => $zones_data['zones'],
			);

		} catch ( \Exception $e ) {
			$this->logger->log( '[Auto-Connect] Error: ' . $e->getMessage(), 'error' );
			return array(
				'success' => false,
				/* translators: %s: Error message */
				'message' => sprintf( __( 'Auto-connect failed: %s', 'polar-mass-advanced-ip-blocker' ), $e->getMessage() ),
			);
		}
	}

	/**
	 * Get list of all zones in the Cloudflare account.
	 *
	 * @param string $token API token (master token or zone read token).
	 * @return array Array with zones list or empty array on failure.
	 */
	public function get_zones_list( $token ) {
		try {
			$endpoint = 'https://api.cloudflare.com/client/v4/zones';

			$args = array(
				'method'  => 'GET',
				'headers' => array(
					'Authorization' => 'Bearer ' . $token,
					'Content-Type'  => 'application/json',
				),
				'timeout' => 30,
			);

			$response = wp_remote_request( $endpoint, $args );

			if ( is_wp_error( $response ) ) {
				$this->logger->log( '[Auto-Connect] Failed to get zones list: ' . $response->get_error_message(), 'error' );
				return array( 'zones' => array() );
			}

			$body = wp_remote_retrieve_body( $response );
			$data = json_decode( $body, true );

			if ( json_last_error() !== JSON_ERROR_NONE ) {
				$this->logger->log( '[Auto-Connect] Invalid JSON response for zones list', 'error' );
				return array( 'zones' => array() );
			}

			$status_code = wp_remote_retrieve_response_code( $response );
			if ( $status_code >= 400 ) {
				$error_message = isset( $data['errors'][0]['message'] ) ? $data['errors'][0]['message'] : 'Unknown error';
				$this->logger->log( '[Auto-Connect] API error getting zones: ' . $error_message, 'error' );
				return array( 'zones' => array() );
			}

			if ( isset( $data['result'] ) && is_array( $data['result'] ) ) {
				return array( 'zones' => $data['result'] );
			}

			return array( 'zones' => array() );
		} catch ( \Exception $e ) {
			$this->logger->log( '[Auto-Connect] Exception getting zones list: ' . $e->getMessage(), 'error' );
			return array( 'zones' => array() );
		}
	}

	/**
	 * Get required permission group IDs for the scoped token.
	 *
	 * @param string $token Master token.
	 * @return array Array of permission group IDs with their names.
	 */
	private function get_required_permissions( $token ) {
		$required_permission_names = array(
			'Zone Read',
			'Zone WAF Write',
			'Account Rule Lists Read',
			'Account Rule Lists Write',
			'Billing Read',
		);

		try {
			$endpoint = 'https://api.cloudflare.com/client/v4/user/tokens/permission_groups';

			$args = array(
				'method'  => 'GET',
				'headers' => array(
					'Authorization' => 'Bearer ' . $token,
					'Content-Type'  => 'application/json',
				),
				'timeout' => 30,
			);

			$response = wp_remote_request( $endpoint, $args );

			if ( is_wp_error( $response ) ) {
				$this->logger->log( '[Auto-Connect] Failed to get permission groups: ' . $response->get_error_message(), 'error' );
				return array();
			}

			$body = wp_remote_retrieve_body( $response );
			$data = json_decode( $body, true );

			if ( json_last_error() !== JSON_ERROR_NONE ) {
				$this->logger->log( '[Auto-Connect] Invalid JSON response for permission groups', 'error' );
				return array();
			}

			$status_code = wp_remote_retrieve_response_code( $response );
			if ( $status_code >= 400 ) {
				$error_message = isset( $data['errors'][0]['message'] ) ? $data['errors'][0]['message'] : 'Unknown error';
				$this->logger->log( '[Auto-Connect] API error getting permissions: ' . $error_message, 'error' );
				return array();
			}

			$permissions = array();
			if ( isset( $data['result'] ) && is_array( $data['result'] ) ) {
				foreach ( $data['result'] as $group ) {
					if ( in_array( $group['name'], $required_permission_names, true ) ) {
						$permissions[] = array(
							'id'   => $group['id'],
							'name' => $group['name'],
						);
					}
				}
			}

			return $permissions;
		} catch ( \Exception $e ) {
			$this->logger->log( '[Auto-Connect] Exception getting permissions: ' . $e->getMessage(), 'error' );
			return array();
		}
	}

	/**
	 * Find existing Polar Mass token in Cloudflare account.
	 *
	 * @param string $master_token Master token.
	 * @return string Empty string.
	 */
	private function find_existing_polar_mass_token( $master_token ) {
		try {
			$endpoint = 'https://api.cloudflare.com/client/v4/user/tokens';
			$token_name = $this->get_token_name();

			$args = array(
				'method'  => 'GET',
				'headers' => array(
					'Authorization' => 'Bearer ' . $master_token,
					'Content-Type'  => 'application/json',
				),
				'timeout' => 30,
			);

			$response = wp_remote_request( $endpoint, $args );

			if ( is_wp_error( $response ) ) {
				return '';
			}

			$body = wp_remote_retrieve_body( $response );
			$data = json_decode( $body, true );

			if ( json_last_error() !== JSON_ERROR_NONE ) {
				return '';
			}

			$status_code = wp_remote_retrieve_response_code( $response );
			if ( $status_code >= 400 ) {
				return '';
			}

			if ( isset( $data['result'] ) && is_array( $data['result'] ) ) {
				foreach ( $data['result'] as $token ) {
					if ( isset( $token['name'] ) && $token['name'] === $token_name ) {
						$this->logger->log( '[Auto-Connect] Found existing token for this domain: ' . $token_name, 'info' );
						if ( isset( $token['id'] ) ) {
							return $token['id'];
						}
					}
				}
			}

			return '';
		} catch ( \Exception $e ) {
			$this->logger->log( '[Auto-Connect] Exception finding existing token: ' . $e->getMessage(), 'error' );
			return '';
		}
	}

	/**
	 * Delete token by ID
	 *
	 * @param string $master_token Master token.
	 * @param string $token_id Token ID to delete.
	 * @return bool Success status.
	 */
	private function delete_token_by_id( $master_token, $token_id ) {
		try {
			$delete_endpoint = 'https://api.cloudflare.com/client/v4/user/tokens/' . $token_id;
			
			$delete_args = array(
				'method'  => 'DELETE',
				'headers' => array(
					'Authorization' => 'Bearer ' . $master_token,
					'Content-Type'  => 'application/json',
				),
				'timeout' => 30,
			);

			$delete_response = wp_remote_request( $delete_endpoint, $delete_args );

			if ( is_wp_error( $delete_response ) ) {
				$this->logger->log( '[Auto-Connect] Failed to delete token: ' . $delete_response->get_error_message(), 'error' );
				return false;
			}

			$delete_status = wp_remote_retrieve_response_code( $delete_response );
			if ( 200 === $delete_status || 404 === $delete_status ) {
				$this->logger->log( '[Auto-Connect] Successfully deleted old token', 'info' );
				return true;
			} else {
				$delete_body = wp_remote_retrieve_body( $delete_response );
				$delete_data = json_decode( $delete_body, true );
				$error_message = isset( $delete_data['errors'][0]['message'] ) ? $delete_data['errors'][0]['message'] : 'Unknown error';
				$this->logger->log( '[Auto-Connect] Failed to delete token (HTTP ' . $delete_status . '): ' . $error_message, 'error' );
				return false;
			}
		} catch ( \Exception $e ) {
			$this->logger->log( '[Auto-Connect] Exception deleting token: ' . $e->getMessage(), 'error' );
			return false;
		}
	}

	/**
	 * Delete scoped token from Cloudflare account
	 *
	 * @param string $master_token Master token.
	 * @return bool Success status.
	 */
	public function delete_scoped_token( $master_token ) {
		try {
			$endpoint = 'https://api.cloudflare.com/client/v4/user/tokens';

			$args = array(
				'method'  => 'GET',
				'headers' => array(
					'Authorization' => 'Bearer ' . $master_token,
					'Content-Type'  => 'application/json',
				),
				'timeout' => 30,
			);

			$response = wp_remote_request( $endpoint, $args );

			if ( is_wp_error( $response ) ) {
				$this->logger->log( '[Reset] Failed to get token list: ' . $response->get_error_message(), 'error' );
				return false;
			}

			$body = wp_remote_retrieve_body( $response );
			$data = json_decode( $body, true );

			if ( json_last_error() !== JSON_ERROR_NONE ) {
				$this->logger->log( '[Reset] Invalid JSON response when getting token list', 'error' );
				return false;
			}

			$status_code = wp_remote_retrieve_response_code( $response );
			if ( $status_code >= 400 ) {
				$error_message = isset( $data['errors'][0]['message'] ) ? $data['errors'][0]['message'] : 'Unknown error';
				$this->logger->log( '[Reset] API error getting token list: ' . $error_message, 'error' );
				return false;
			}

			$token_name = $this->get_token_name();
			
			if ( isset( $data['result'] ) && is_array( $data['result'] ) ) {
				foreach ( $data['result'] as $token ) {
					if ( isset( $token['name'] ) && isset( $token['id'] ) && $token['name'] === $token_name ) {
						if ( $this->delete_token_by_id( $master_token, $token['id'] ) ) {
							$this->logger->log( '[Reset] Successfully deleted scoped token from Cloudflare', 'info' );
							return true;
						}
					}
				}
			}

			return true;
		} catch ( \Exception $e ) {
			$this->logger->log( '[Reset] Exception deleting scoped token: ' . $e->getMessage(), 'error' );
			return false;
		}
	}

	/**
	 * Get master token condition (Client IP restrictions) from token list.
	 *
	 * @param string $master_token Master token.
	 * @return array|false Condition array or false on failure.
	 */
	private function get_master_token_condition( $master_token ) {
		try {
			$verify_endpoint = 'https://api.cloudflare.com/client/v4/user/tokens/verify';

			$args = array(
				'method'  => 'GET',
				'headers' => array(
					'Authorization' => 'Bearer ' . $master_token,
					'Content-Type'  => 'application/json',
				),
				'timeout' => 30,
			);

			$verify_response = wp_remote_request( $verify_endpoint, $args );

			if ( is_wp_error( $verify_response ) ) {
				return false;
			}

			$verify_body = wp_remote_retrieve_body( $verify_response );
			$verify_data = json_decode( $verify_body, true );

			if ( json_last_error() !== JSON_ERROR_NONE || ! isset( $verify_data['result']['id'] ) ) {
				return false;
			}

			$token_id = $verify_data['result']['id'];

			$list_endpoint = 'https://api.cloudflare.com/client/v4/user/tokens';

			$list_response = wp_remote_request( $list_endpoint, $args );

			if ( is_wp_error( $list_response ) ) {
				return false;
			}

			$list_body = wp_remote_retrieve_body( $list_response );
			$list_data = json_decode( $list_body, true );

			if ( json_last_error() !== JSON_ERROR_NONE ) {
				return false;
			}

			$status_code = wp_remote_retrieve_response_code( $list_response );
			if ( $status_code >= 400 ) {
				return false;
			}

			if ( isset( $list_data['result'] ) && is_array( $list_data['result'] ) ) {
				foreach ( $list_data['result'] as $token ) {
					if ( isset( $token['id'] ) && $token['id'] === $token_id ) {
						if ( isset( $token['condition'] ) && ! empty( $token['condition'] ) ) {
							return $token['condition'];
						}
						break;
					}
				}
			}

			return false;
		} catch ( \Exception $e ) {
			$this->logger->log( '[Auto-Connect] Exception getting master token condition: ' . $e->getMessage(), 'error' );
			return false;
		}
	}

	/**
	 * Generate a scoped API token with only necessary permissions.
	 *
	 * @param string $master_token Master token with "Create Additional Tokens" permission.
	 * @param array  $permissions Permission groups array.
	 * @return array|false Token data with 'token' and 'id', or false on failure.
	 */
	private function generate_scoped_token( $master_token, $permissions ) {
		try {
			$token_name = $this->get_token_name();

			$permission_groups = array();
			foreach ( $permissions as $perm ) {
				$permission_groups[] = array(
					'id'   => $perm['id'],
					'meta' => array(),
				);
			}

			$condition = $this->get_master_token_condition( $master_token );

			$policies = array(
				array(
					'effect'            => 'allow',
					'permission_groups' => $permission_groups,
					'resources'         => array(
						'com.cloudflare.api.account.*' => '*',
					),
				),
			);

			$endpoint = 'https://api.cloudflare.com/client/v4/user/tokens';

			$data = array(
				'name'     => $token_name,
				'policies' => $policies,
			);

			if ( ! empty( $condition ) ) {
				$data['condition'] = $condition;
			}

			$args = array(
				'method'  => 'POST',
				'headers' => array(
					'Authorization' => 'Bearer ' . $master_token,
					'Content-Type'  => 'application/json',
				),
				'body'    => wp_json_encode( $data ),
				'timeout' => 30,
			);

			$response = wp_remote_request( $endpoint, $args );

			if ( is_wp_error( $response ) ) {
				$this->logger->log( '[Auto-Connect] Failed to create token: ' . $response->get_error_message(), 'error' );
				return false;
			}

			$body = wp_remote_retrieve_body( $response );
			$data = json_decode( $body, true );

			if ( json_last_error() !== JSON_ERROR_NONE ) {
				$this->logger->log( '[Auto-Connect] Invalid JSON response for token creation', 'error' );
				return false;
			}

			$status_code = wp_remote_retrieve_response_code( $response );
			if ( $status_code >= 400 ) {
				$error_message = isset( $data['errors'][0]['message'] ) ? $data['errors'][0]['message'] : 'Unknown error';
				$error_code    = isset( $data['errors'][0]['code'] ) ? $data['errors'][0]['code'] : '';
				$this->logger->log( '[Auto-Connect] API error creating token: ' . $error_message . ' (Code: ' . $error_code . ')', 'error' );
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					$this->logger->log( '[Auto-Connect] Full error response: ' . wp_json_encode( $data ), 'error' );
				}
				return false;
			}

			if ( isset( $data['result']['value'] ) && isset( $data['result']['id'] ) ) {
				return array(
					'token' => $data['result']['value'],
					'id'    => $data['result']['id'],
				);
			}

			return false;
		} catch ( \Exception $e ) {
			$this->logger->log( '[Auto-Connect] Exception generating token: ' . $e->getMessage(), 'error' );
			return false;
		}
	}

	/**
	 * Get zone name from zone ID.
	 *
	 * @param string $zone_id Zone ID.
	 * @param string $token API token.
	 * @return string|false Zone name or false.
	 */
	public function get_zone_name( $zone_id, $token ) {
		try {
			$endpoint = "https://api.cloudflare.com/client/v4/zones/{$zone_id}";

			$args = array(
				'method'  => 'GET',
				'headers' => array(
					'Authorization' => 'Bearer ' . $token,
					'Content-Type'  => 'application/json',
				),
				'timeout' => 30,
			);

			$response = wp_remote_request( $endpoint, $args );

			if ( is_wp_error( $response ) ) {
				return false;
			}

			$body = wp_remote_retrieve_body( $response );
			$data = json_decode( $body, true );

			if ( isset( $data['result']['name'] ) ) {
				return $data['result']['name'];
			}

			return false;
		} catch ( \Exception $e ) {
			return false;
		}
	}

	/**
	 * Get rule name and details from Cloudflare API.
	 *
	 * @param string $zone_id Zone ID.
	 * @param string $ruleset_id Ruleset ID.
	 * @param string $rule_id Rule ID.
	 * @param string $token API token.
	 * @return array|false Array with 'description' (rule name) and 'enabled' status, or false on failure.
	 */
	public function get_rule_details( $zone_id, $ruleset_id, $rule_id, $token ) {
		try {
			$ruleset_endpoint = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/rulesets/{$ruleset_id}";

			$args = array(
				'method'  => 'GET',
				'headers' => array(
					'Authorization' => 'Bearer ' . $token,
					'Content-Type'  => 'application/json',
				),
				'timeout' => 30,
			);

			$response = wp_remote_request( $ruleset_endpoint, $args );

			if ( is_wp_error( $response ) ) {
				$this->logger->log( '[Cloudflare] Error getting ruleset: ' . $response->get_error_message(), 'error' );
				return false;
			}

			$status_code = wp_remote_retrieve_response_code( $response );
			if ( $status_code >= 400 ) {
				$body = wp_remote_retrieve_body( $response );
				$data = json_decode( $body, true );
				$error_msg = isset( $data['errors'][0]['message'] ) ? $data['errors'][0]['message'] : 'HTTP ' . $status_code;
				$this->logger->log( '[Cloudflare] Failed to get ruleset (HTTP ' . $status_code . '): ' . $error_msg, 'error' );
				return false;
			}

			$body = wp_remote_retrieve_body( $response );
			$data = json_decode( $body, true );

			if ( json_last_error() !== JSON_ERROR_NONE || ! isset( $data['result'] ) ) {
				$this->logger->log( '[Cloudflare] Invalid response when getting ruleset', 'error' );
				return false;
			}

			$ruleset = $data['result'];

			if ( ! isset( $ruleset['rules'] ) || ! is_array( $ruleset['rules'] ) ) {
				$this->logger->log( '[Cloudflare] Ruleset has no rules array', 'error' );
				return false;
			}

			foreach ( $ruleset['rules'] as $rule ) {
				if ( isset( $rule['id'] ) && $rule['id'] === $rule_id ) {
					return array(
						'description' => isset( $rule['description'] ) ? $rule['description'] : '',
						'enabled'     => isset( $rule['enabled'] ) ? $rule['enabled'] : false,
						'action'      => isset( $rule['action'] ) ? $rule['action'] : '',
					);
				}
			}

			$available_ids = array();
			foreach ( $ruleset['rules'] as $rule ) {
				if ( isset( $rule['id'] ) ) {
					$available_ids[] = $rule['id'];
				}
			}
			$this->logger->log( '[Cloudflare] Rule ID ' . $rule_id . ' not found in ruleset ' . $ruleset_id . '. Available rule IDs: ' . ( ! empty( $available_ids ) ? implode( ', ', $available_ids ) : 'none' ), 'error' );
			return false;

		} catch ( \Exception $e ) {
			$this->logger->log( '[Cloudflare] Exception getting rule details: ' . $e->getMessage(), 'error' );
			return false;
		}
	}

	/**
	 * Get domain name for token/ruleset naming
	 *
	 * @return string Sanitized domain name.
	 */
	private function get_domain_name() {
		$site_url = get_site_url();
		$domain   = wp_parse_url( $site_url, PHP_URL_HOST );
		if ( ! $domain ) {
			$domain = 'default';
		}
		$domain = strtolower( $domain );
		$domain = preg_replace( '/[^a-z0-9_]/', '_', $domain );
		return substr( $domain, 0, 30 );
	}

	/**
	 * Get unique ruleset name for this plugin
	 *
	 * @return string Unique ruleset name.
	 */
	private function get_ruleset_name() {
		$domain = $this->get_domain_name();
		return 'Polar Mass IP Blocker - ' . $domain;
	}

	/**
	 * Get unique token name for this plugin
	 *
	 * @return string Unique token name.
	 */
	private function get_token_name() {
		$domain = $this->get_domain_name();
		return 'Polar Mass IP Blocker (' . $domain . ') - Zone Read & WAF Edit & IP Lists & Billing Read';
	}

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
	 * Find existing ruleset for this plugin
	 *
	 * @param string $zone_id Zone ID.
	 * @param string $token API token.
	 * @return array|false Array with 'ruleset_id' and 'rule_id', or false if not found.
	 */
	private function find_existing_ruleset( $zone_id, $token ) {
		try {
			$ruleset_endpoint = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/rulesets";
			$ruleset_name     = $this->get_ruleset_name();

			$args = array(
				'method'  => 'GET',
				'headers' => array(
					'Authorization' => 'Bearer ' . $token,
					'Content-Type'  => 'application/json',
				),
				'timeout' => 30,
			);

			$response = wp_remote_request( $ruleset_endpoint, $args );

			if ( is_wp_error( $response ) ) {
				return false;
			}

			$body        = wp_remote_retrieve_body( $response );
			$data        = json_decode( $body, true );
			$status_code = wp_remote_retrieve_response_code( $response );

			if ( 200 !== $status_code || ! isset( $data['result'] ) ) {
				return false;
			}

			$old_ruleset_name = 'Polar Mass IP Blocker';
			foreach ( $data['result'] as $ruleset ) {
				if ( isset( $ruleset['name'] ) && 
					 ( $ruleset['name'] === $ruleset_name || $ruleset['name'] === $old_ruleset_name ) &&
					 isset( $ruleset['phase'] ) && 
					 $ruleset['phase'] === 'http_request_firewall_custom' &&
					 isset( $ruleset['id'] ) ) {
					
					$ruleset_id = $ruleset['id'];
					$rules_endpoint = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/rulesets/{$ruleset_id}";
					$rules_response = wp_remote_request( $rules_endpoint, $args );
					
					if ( ! is_wp_error( $rules_response ) ) {
						$rules_body = wp_remote_retrieve_body( $rules_response );
						$rules_data  = json_decode( $rules_body, true );
						
						if ( isset( $rules_data['result']['rules'] ) && is_array( $rules_data['result']['rules'] ) ) {
							$rule_description = $this->get_rule_description();
							$old_rule_description = 'MaliciousIPs - Polar Mass Advanced IP Blocker';
							
							foreach ( $rules_data['result']['rules'] as $rule ) {
								if ( isset( $rule['id'] ) && isset( $rule['description'] ) ) {
									if ( $rule['description'] === $rule_description || 
										 $rule['description'] === $old_rule_description ||
										 ( stripos( $rule['description'], 'MaliciousIPs' ) !== false &&
										   stripos( $rule['description'], 'Polar Mass' ) !== false ) ) {
										return array(
											'ruleset_id' => $ruleset_id,
											'rule_id'    => $rule['id'],
										);
									}
								}
							}
						}
					}
				}
			}

			return false;
		} catch ( \Exception $e ) {
			$this->logger->log( '[Auto-Connect] Error finding existing ruleset: ' . $e->getMessage(), 'error' );
			return false;
		}
	}

	/**
	 * Auto-create custom rule for IP blocking.
	 *
	 * @param string $zone_id Zone ID.
	 * @param string $token Scoped API token.
	 * @return array|false Array with 'ruleset_id' and 'rule_id', or false on failure.
	 */
	private function auto_create_rule( $zone_id, $token ) {
		try {
			$existing = $this->find_existing_ruleset( $zone_id, $token );
			if ( false !== $existing ) {
				$this->logger->log( '[Auto-Connect] Found existing ruleset: ' . $existing['ruleset_id'] . ' with rule: ' . $existing['rule_id'], 'info' );
				return $existing;
			}

			$entrypoint_endpoint = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint";

			$args = array(
				'method'  => 'GET',
				'headers' => array(
					'Authorization' => 'Bearer ' . $token,
					'Content-Type'  => 'application/json',
				),
				'timeout' => 30,
			);

			$response   = wp_remote_request( $entrypoint_endpoint, $args );
			$ruleset_id = null;

			if ( ! is_wp_error( $response ) ) {
				$body        = wp_remote_retrieve_body( $response );
				$data        = json_decode( $body, true );
				$status_code = wp_remote_retrieve_response_code( $response );

				if ( 200 === $status_code && isset( $data['result']['id'] ) ) {
					$ruleset_id = $data['result']['id'];
				}
			}

			if ( ! $ruleset_id ) {
				$ruleset_endpoint = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/rulesets";
				$ruleset_name     = $this->get_ruleset_name();

				$rule_description = $this->get_rule_description();
				$ruleset_data = array(
					'name'        => $ruleset_name,
					'description' => 'Custom ruleset for Polar Mass Advanced IP Blocker',
					'kind'        => 'zone',
					'phase'       => 'http_request_firewall_custom',
					'rules'       => array(
						array(
							'description' => $rule_description,
							'expression'  => '(ip.src in {})',
							'action'      => 'block',
							'enabled'     => true,
						),
					),
				);

				$args['method'] = 'POST';
				$args['body']   = wp_json_encode( $ruleset_data );

				$response = wp_remote_request( $ruleset_endpoint, $args );

				if ( is_wp_error( $response ) ) {
					$this->logger->log( '[Auto-Connect] Failed to create ruleset: ' . $response->get_error_message(), 'error' );
					return false;
				}

				$body        = wp_remote_retrieve_body( $response );
				$data        = json_decode( $body, true );
				$status_code = wp_remote_retrieve_response_code( $response );

				if ( $status_code >= 400 ) {
					$error_message = isset( $data['errors'][0]['message'] ) ? $data['errors'][0]['message'] : 'Unknown error';
					$this->logger->log( '[Auto-Connect] API error creating ruleset: ' . $error_message, 'error' );
					return false;
				}

				if ( isset( $data['result']['id'] ) ) {
					$ruleset_id_value = trim( $data['result']['id'] );
					$rule_id_value    = null;

					if ( isset( $data['result']['rules'] ) && is_array( $data['result']['rules'] ) && ! empty( $data['result']['rules'] ) ) {
						foreach ( $data['result']['rules'] as $rule ) {
							if ( isset( $rule['id'] ) && isset( $rule['description'] ) &&
								( stripos( $rule['description'], 'MaliciousIPs' ) !== false ||
									stripos( $rule['description'], 'Polar Mass' ) !== false ) ) {
								$rule_id_value = trim( $rule['id'] );
								break;
							}
						}

						if ( ! $rule_id_value && isset( $data['result']['rules'][0]['id'] ) ) {
							$rule_id_value = trim( $data['result']['rules'][0]['id'] );
						}
					}

					if ( ! $rule_id_value ) {
						$this->logger->log( '[Auto-Connect] Failed to find rule ID in ruleset creation response.', 'error' );
						if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
							$this->logger->log( '[Auto-Connect] Full response: ' . wp_json_encode( $data ), 'error' );
						}
						return false;
					}

					$ruleset_trimmed = trim( (string) $ruleset_id_value );
					$rule_trimmed    = trim( (string) $rule_id_value );

					if ( $ruleset_trimmed === $rule_trimmed ) {
						$this->logger->log( "[Auto-Connect] ERROR: Ruleset ID and Rule ID are the same! Ruleset: '{$ruleset_trimmed}' (length: " . strlen( $ruleset_trimmed ) . "), Rule: '{$rule_trimmed}' (length: " . strlen( $rule_trimmed ) . ')', 'error' );
						$this->logger->log( '[Auto-Connect] Full response: ' . wp_json_encode( $data ), 'error' );
					}

					return array(
						'ruleset_id' => $ruleset_id_value,
						'rule_id'    => $rule_id_value,
					);
				}

				$this->logger->log( '[Auto-Connect] Failed to parse ruleset creation response. Missing ruleset ID.', 'error' );
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					$this->logger->log( '[Auto-Connect] Full response: ' . wp_json_encode( $data ), 'error' );
				}
				return false;
			} else {
				$rules_endpoint = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/rulesets/{$ruleset_id}";
				$rules_response  = wp_remote_request( $rules_endpoint, $args );

				if ( ! is_wp_error( $rules_response ) ) {
					$rules_body = wp_remote_retrieve_body( $rules_response );
					$rules_data = json_decode( $rules_body, true );

					if ( isset( $rules_data['result']['rules'] ) && is_array( $rules_data['result']['rules'] ) ) {
						$rule_description = $this->get_rule_description();
						$old_rule_description = 'MaliciousIPs - Polar Mass Advanced IP Blocker';
						
						foreach ( $rules_data['result']['rules'] as $rule ) {
							if ( isset( $rule['id'] ) && isset( $rule['description'] ) ) {
								if ( $rule['description'] === $rule_description || 
									 $rule['description'] === $old_rule_description ||
									 ( stripos( $rule['description'], 'MaliciousIPs' ) !== false &&
									   stripos( $rule['description'], 'Polar Mass' ) !== false ) ) {
									$this->logger->log( '[Auto-Connect] Found existing rule in entrypoint ruleset: ' . $rule['id'], 'info' );
									return array(
										'ruleset_id' => $ruleset_id,
										'rule_id'    => $rule['id'],
									);
								}
							}
						}
					}
				}

				$rule_endpoint = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/rulesets/{$ruleset_id}/rules";
				$rule_description = $this->get_rule_description();

				$rule_data = array(
					'description' => $rule_description,
					'expression'  => '(ip.src in {})',
					'action'      => 'block',
				);

				$args['method'] = 'POST';
				$args['body']   = wp_json_encode( $rule_data );

				$response = wp_remote_request( $rule_endpoint, $args );

				if ( is_wp_error( $response ) ) {
					$this->logger->log( '[Auto-Connect] Failed to create rule: ' . $response->get_error_message(), 'error' );
					return false;
				}

				$body        = wp_remote_retrieve_body( $response );
				$data        = json_decode( $body, true );
				$status_code = wp_remote_retrieve_response_code( $response );

				if ( $status_code >= 400 ) {
					$error_message = isset( $data['errors'][0]['message'] ) ? $data['errors'][0]['message'] : 'Unknown error';
					$this->logger->log( '[Auto-Connect] API error creating rule: ' . $error_message, 'error' );
					return false;
				}

				$rule_id_value = null;

				if ( isset( $data['result']['rules'] ) && is_array( $data['result']['rules'] ) && ! empty( $data['result']['rules'] ) ) {
					$matching_rules = array();
					foreach ( $data['result']['rules'] as $rule ) {
						if ( isset( $rule['id'] ) && isset( $rule['description'] ) &&
							( stripos( $rule['description'], 'MaliciousIPs' ) !== false ||
								stripos( $rule['description'], 'Polar Mass' ) !== false ) ) {
							$matching_rules[] = $rule;
						}
					}

					if ( ! empty( $matching_rules ) ) {
						usort(
							$matching_rules,
							function ( $a, $b ) {
								$a_time = isset( $a['last_updated'] ) ? strtotime( $a['last_updated'] ) : 0;
								$b_time = isset( $b['last_updated'] ) ? strtotime( $b['last_updated'] ) : 0;
								return $b_time - $a_time;
							}
						);
						$rule_id_value = trim( $matching_rules[0]['id'] );
					}

					if ( ! $rule_id_value ) {
						$last_rule = end( $data['result']['rules'] );
						reset( $data['result']['rules'] );
						if ( isset( $last_rule['id'] ) ) {
							$rule_id_value = trim( $last_rule['id'] );
						}
					}
				} else {
					$this->logger->log( '[Auto-Connect] No rules array found in response!', 'error' );
				}

				if ( ! $rule_id_value ) {
					$this->logger->log( '[Auto-Connect] CRITICAL: Failed to find rule ID in add-rule response!', 'error' );
					$this->logger->log( '[Auto-Connect] Full response: ' . wp_json_encode( $data ), 'error' );
					return false;
				}

				$ruleset_trimmed = trim( (string) $ruleset_id );
				$rule_trimmed    = trim( (string) $rule_id_value );

				if ( $ruleset_trimmed === $rule_trimmed ) {
					$this->logger->log( '[Auto-Connect] CRITICAL ERROR: Extracted rule ID is the same as ruleset ID! This is wrong!', 'error' );
					$this->logger->log( "[Auto-Connect] Ruleset ID: '{$ruleset_trimmed}'", 'error' );
					$this->logger->log( "[Auto-Connect] Rule ID extracted: '{$rule_trimmed}'", 'error' );
					$this->logger->log( '[Auto-Connect] Full response: ' . wp_json_encode( $data ), 'error' );
					return false;
				}

				return array(
					'ruleset_id' => $ruleset_id,
					'rule_id'    => $rule_id_value,
				);
			}
		} catch ( \Exception $e ) {
			$this->logger->log( '[Auto-Connect] Exception creating rule: ' . $e->getMessage(), 'error' );
			return false;
		}
	}

	/**
	 * Create rule for selected zone (public method for zone selection).
	 *
	 * @param string $zone_id Zone ID.
	 * @param string $token Scoped API token.
	 * @return array Result array with success status, ruleset_id, and rule_id.
	 */
	public function create_rule_for_zone( $zone_id, $token ) {
		$rule_data = $this->auto_create_rule( $zone_id, $token );

		if ( ! $rule_data ) {
			return array(
				'success' => false,
				'message' => __( 'Failed to create custom rule. Please check your token permissions.', 'polar-mass-advanced-ip-blocker' ),
			);
		}

		return array(
			'success'    => true,
			'ruleset_id' => $rule_data['ruleset_id'],
			'rule_id'    => $rule_data['rule_id'],
		);
	}
}
