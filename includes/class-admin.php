<?php
/**
 * Admin class for managing plugin settings and UI.
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
 * Handles the Admin settings and UI for the plugin.
 */
class Admin {
	/**
	 * Logger instance
	 *
	 * @var Logger
	 */
	private $logger;

	/**
	 * Constructor
	 *
	 * @param Logger $logger Logger instance.
	 */
	public function __construct( Logger $logger ) {
		$this->logger = $logger;
	}

	/**
	 * Initialize admin functionality
	 */
	public function init() {
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
		add_action( 'wp_ajax_pmip_register_cron', array( $this, 'ajax_register_cron' ) );
		add_action( 'wp_ajax_pmip_block_ip', array( $this, 'ajax_block_ip' ) );
		add_action( 'wp_ajax_pmip_unblock_ip', array( $this, 'ajax_unblock_ip' ) );
		add_action( 'wp_ajax_pmip_sync_wordfence', array( $this, 'ajax_sync_wordfence' ) );
		add_action( 'wp_ajax_pmip_update_newsletter_status', array( $this, 'ajax_update_newsletter_status' ) );
		add_action( 'wp_ajax_pmip_export_logs', array( $this, 'ajax_export_logs' ) );
		add_action( 'wp_ajax_pmip_auto_connect', array( $this, 'ajax_auto_connect' ) );
		add_action( 'wp_ajax_pmip_select_zone', array( $this, 'ajax_select_zone' ) );
	}

	/**
	 * Add admin menu items
	 */
	public function add_admin_menu() {
		add_menu_page(
			__( 'Polar Mass Advanced IP Blocker', 'polar-mass-advanced-ip-blocker' ),
			__( 'PM IP Blocker', 'polar-mass-advanced-ip-blocker' ),
			'manage_options',
			'polar-mass-advanced-ip-blocker',
			array( $this, 'render_admin_page' ),
			'dashicons-shield',
			100
		);
	}

	/**
	 * Register plugin settings
	 */
	public function register_settings() {
		// phpcs:disable PluginCheck.CodeAnalysis.SettingSanitization.register_settingDynamic
		register_setting(
			'pmip_settings',
			'pmip_api_token',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '',
			)
		);

		register_setting(
			'pmip_settings',
			'pmip_zone_id',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '',
			)
		);

		register_setting(
			'pmip_settings',
			'pmip_ruleset_id',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '',
			)
		);

		register_setting(
			'pmip_settings',
			'pmip_rule_id',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '',
			)
		);

		register_setting(
			'pmip_settings',
			'pmip_plugin_status',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => 'inactive',
			)
		);

		register_setting(
			'pmip_settings',
			'pmip_scan_interval',
			array(
				'type'              => 'integer',
				'sanitize_callback' => 'absint',
				'default'           => 15,
			)
		);

		register_setting(
			'pmip_settings',
			'pmip_failed_attempts',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_failed_attempts' ),
				'default'           => 5,
			)
		);

		register_setting(
			'pmip_settings',
			'pmip_block_duration',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '24h',
			)
		);

		register_setting(
			'pmip_settings',
			'pmip_max_logs',
			array(
				'type'              => 'integer',
				'sanitize_callback' => 'absint',
				'default'           => 1000,
			)
		);
		// phpcs:enable
	}

	/**
	 * Sanitize failed attempts setting
	 *
	 * @param mixed $value Value to sanitize.
	 * @return int Sanitized value.
	 */
	public function sanitize_failed_attempts( $value ) {
		$value = absint( $value );
		return max( 3, min( 10, $value ) );
	}

	/**
	 * Enqueue admin assets
	 *
	 * @param string $hook Current admin page.
	 */
	public function enqueue_admin_assets( $hook ) {
		if ( 'toplevel_page_polar-mass-advanced-ip-blocker' !== $hook ) {
			return;
		}

		wp_enqueue_style(
			'pmip-admin-styles',
			PMIP_BLOCKER_PLUGIN_URL . 'assets/css/admin.min.css',
			array(),
			PMIP_BLOCKER_VERSION
		);

		wp_enqueue_script(
			'pmip-admin-script',
			PMIP_BLOCKER_PLUGIN_URL . 'assets/js/admin.min.js',
			array( 'jquery' ),
			PMIP_BLOCKER_VERSION,
			true
		);

		wp_localize_script(
			'pmip-admin-script',
			'pmipAdmin',
			array(
				'ajaxUrl'      => admin_url( 'admin-ajax.php' ),
				'nonce'        => wp_create_nonce( 'pmip-admin-nonce' ),
				'isSubscribed' => get_option( 'pmip_newsletter_subscribed', 0 ) === 1,
				'i18n'         => array(
					'confirmCron'    => __( 'Are you sure you want to run the cron job?', 'polar-mass-advanced-ip-blocker' ),
					'confirmBlock'   => __( 'Are you sure you want to block this IP?', 'polar-mass-advanced-ip-blocker' ),
					'confirmUnblock' => __( 'Are you sure you want to unblock this IP?', 'polar-mass-advanced-ip-blocker' ),
					'confirmSync'    => __( 'Are you sure you want to sync blocked IPs from Wordfence?', 'polar-mass-advanced-ip-blocker' ),
					'success'        => __( 'Operation completed successfully.', 'polar-mass-advanced-ip-blocker' ),
					'error'          => __( 'An error occurred. Please try again.', 'polar-mass-advanced-ip-blocker' ),
					'enterIp'        => __( 'Please enter an IP address.', 'polar-mass-advanced-ip-blocker' ),
				),
			)
		);
	}

	/**
	 * Render admin page
	 */
	public function render_admin_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// Check nonce for form submissions.
		if ( isset( $_POST['_wpnonce'] ) ) {
			$nonce = sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) );

			if ( wp_verify_nonce( $nonce, 'pmip_settings' ) ) {
				if ( isset( $_POST['pmip_save_manual_config'] ) ) {
					update_option( 'pmip_auto_connected', false );
				}
				$this->save_settings();
			}
		}

		$server_ip      = false;
		$server_ip_type = false;
		try {
			$server_ip_data = $this->get_server_ip();
			if ( is_array( $server_ip_data ) ) {
				$server_ip      = isset( $server_ip_data['ip'] ) ? $server_ip_data['ip'] : false;
				$server_ip_type = isset( $server_ip_data['type'] ) ? $server_ip_data['type'] : false;
			}
		} catch ( \Exception $e ) {
			$this->logger->log( '[Admin] Error detecting server IP: ' . $e->getMessage(), 'error' );
		}

		include PMIP_BLOCKER_PLUGIN_DIR . 'views/admin-page.php';
	}

	/**
	 * Save plugin settings.
	 */
	private function save_settings() {
		if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'pmip_settings' ) ) {
			wp_die( esc_html__( 'Security check failed. Please try again.', 'polar-mass-advanced-ip-blocker' ) );
		}

		// Sanitize and update each field.
		$fields = array(
			'pmip_api_token'      => 'sanitize_text_field',
			'pmip_zone_id'        => 'sanitize_text_field',
			'pmip_ruleset_id'     => 'sanitize_text_field',
			'pmip_rule_id'        => 'sanitize_text_field',
			'pmip_plugin_status'  => 'sanitize_text_field',
			'pmip_block_duration' => 'sanitize_text_field',
			'pmip_max_logs'       => 'absint',
		);

		foreach ( $fields as $field => $sanitizer ) {
			if ( isset( $_POST[ $field ] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				update_option( $field, call_user_func( $sanitizer, wp_unslash( $_POST[ $field ] ) ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			}
		}

		// Handle scan interval separately since it's an integer.
		if ( isset( $_POST['pmip_scan_interval'] ) ) {
			$scan_interval = sanitize_text_field( wp_unslash( $_POST['pmip_scan_interval'] ) );
			update_option( 'pmip_scan_interval', absint( $scan_interval ) );
			wp_clear_scheduled_hook( 'pmip_check_ips' );
			wp_schedule_event( time(), 'pmip_custom_interval', 'pmip_check_ips' );
		}

		// Handle failed attempts with custom sanitizer.
		if ( isset( $_POST['pmip_failed_attempts'] ) ) {
			$failed_attempts = sanitize_text_field( wp_unslash( $_POST['pmip_failed_attempts'] ) );
			update_option( 'pmip_failed_attempts', $this->sanitize_failed_attempts( $failed_attempts ) );
		}

		add_settings_error(
			'pmip_settings',
			'settings_updated',
			__( 'Settings saved successfully.', 'polar-mass-advanced-ip-blocker' ),
			'updated'
		);
	}

	/**
	 * Handle AJAX request to register cron jobs
	 */
	public function ajax_register_cron() {
		try {
			check_ajax_referer( 'pmip-admin-nonce', 'nonce' );

			if ( ! current_user_can( 'manage_options' ) ) {
				wp_send_json_error( array( 'message' => __( 'Unauthorized access.', 'polar-mass-advanced-ip-blocker' ) ) );
			}

			// Register cron jobs.
			if ( ! wp_next_scheduled( 'pmip_check_ips' ) ) {
				wp_schedule_event( time(), 'pmip_custom_interval', 'pmip_check_ips' );
			}

			if ( ! wp_next_scheduled( 'pmip_realtime_check_ips' ) ) {
				wp_schedule_event( time(), 'pmip_realtime_interval', 'pmip_realtime_check_ips' );
			}

			wp_send_json_success( array( 'message' => __( 'Cron jobs registered successfully.', 'polar-mass-advanced-ip-blocker' ) ) );
		} catch ( \Exception $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
	}

	/**
	 * Handle AJAX request to block IP
	 */
	public function ajax_block_ip() {
		check_ajax_referer( 'pmip-admin-nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized access.', 'polar-mass-advanced-ip-blocker' ) ) );
		}

		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid IP address.', 'polar-mass-advanced-ip-blocker' ) ) );
		}

		try {
			$ip_blocker = new Ip_Blocker( $this->logger );
			$result     = $ip_blocker->block_ip( $ip );

			if ( $result ) {
				/* translators: %s: success message */
				wp_send_json_success( array( 'message' => sprintf( __( 'IP %s blocked successfully.', 'polar-mass-advanced-ip-blocker' ), $ip ) ) );
			} else {
				/* translators: %s: error message */
				wp_send_json_error( array( 'message' => sprintf( __( 'Failed to block IP %s.', 'polar-mass-advanced-ip-blocker' ), $ip ) ) );
			}
		} catch ( \Exception $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
	}

	/**
	 * Handle AJAX request to update newsletter status
	 */
	public function ajax_update_newsletter_status() {
		check_ajax_referer( 'pmip-admin-nonce', 'nonce' );

		update_option( 'pmip_newsletter_subscribed', 1 );
		wp_send_json_success();
	}

	/**
	 * Handle exporting logs as CSV.
	 */
	public function ajax_export_logs() {
		// Check nonce for security.
		if ( ! isset( $_GET['nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['nonce'] ) ), 'pmip-admin-nonce' ) ) {
			wp_die( esc_html__( 'Invalid nonce.', 'polar-mass-advanced-ip-blocker' ) );
		}

		// Call the logger to get CSV content.
		$csv_content = $this->logger->export_logs_csv();

		if ( empty( $csv_content ) ) {
			wp_die( esc_html__( 'No logs available.', 'polar-mass-advanced-ip-blocker' ) );
		}

		// Set headers for CSV download.
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="pmip-logs.csv"' );

		// Escape output before printing.
		echo $csv_content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV output needs raw data.
		exit;
	}

	/**
	 * Handle AJAX request to unblock IP
	 */
	public function ajax_unblock_ip() {
		check_ajax_referer( 'pmip-admin-nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized access.', 'polar-mass-advanced-ip-blocker' ) ) );
		}

		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid IP address.', 'polar-mass-advanced-ip-blocker' ) ) );
		}

		try {
			$ip_blocker = new Ip_Blocker( $this->logger );
			$result     = $ip_blocker->unblock_ip( $ip );

			if ( $result ) {
				/* translators: %s: success message */
				wp_send_json_success( array( 'message' => sprintf( __( 'IP %s unblocked successfully.', 'polar-mass-advanced-ip-blocker' ), $ip ) ) );
			} else {
				/* translators: %s: error message */
				wp_send_json_error( array( 'message' => sprintf( __( 'Failed to unblock IP %s.', 'polar-mass-advanced-ip-blocker' ), $ip ) ) );
			}
		} catch ( \Exception $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
	}

	/**
	 * Handle AJAX request to sync with Wordfence
	 */
	public function ajax_sync_wordfence() {
		check_ajax_referer( 'pmip-admin-nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized access.', 'polar-mass-advanced-ip-blocker' ) ) );
		}

		try {
			$ip_blocker = new Ip_Blocker( $this->logger );
			$result     = $ip_blocker->sync_from_wordfence();

			if ( $result ) {
				wp_send_json_success( array( 'message' => __( 'Successfully synced IPs from Wordfence.', 'polar-mass-advanced-ip-blocker' ) ) );
			} else {
				wp_send_json_error( array( 'message' => __( 'Failed to sync IPs from Wordfence.', 'polar-mass-advanced-ip-blocker' ) ) );
			}
		} catch ( \Exception $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
	}

	/**
	 * Handle newsletter subscription
	 */
	public function ajax_subscribe_newsletter() {
		check_ajax_referer( 'pmip-admin-nonce', 'nonce' );

		$email = isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '';
		if ( ! is_email( $email ) ) {
			wp_send_json_error( array( 'message' => __( 'Please enter a valid email address.', 'polar-mass-advanced-ip-blocker' ) ) );
		}

		// Add subscriber to the database.
		$subscribers = get_option( 'pmip_newsletter_subscribers', array() );
		if ( in_array( $email, $subscribers, true ) ) {
			wp_send_json_error( array( 'message' => __( 'You are already subscribed!', 'polar-mass-advanced-ip-blocker' ) ) );
		}

		$subscribers[] = $email;
		update_option( 'pmip_newsletter_subscribers', $subscribers );

		wp_send_json_success( array( 'message' => __( 'Thank you for subscribing!', 'polar-mass-advanced-ip-blocker' ) ) );
	}

	/**
	 * Get website server IP address.
	 *
	 * @return array Array with 'ip' and 'type' (public, private, or false).
	 */
	public function get_server_ip() {
		$result = array(
			'ip'   => false,
			'type' => false,
		);

		if ( ! isset( $_SERVER ) || ! is_array( $_SERVER ) ) {
			return $result;
		}

		if ( ! empty( $_SERVER['SERVER_ADDR'] ) && filter_var( $_SERVER['SERVER_ADDR'], FILTER_VALIDATE_IP ) ) {
			$server_addr = sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) );
			if ( $this->is_private_ip( $server_addr ) ) {
				$result['ip']   = $server_addr;
				$result['type'] = 'private';
				return $result;
			} else {
				$result['ip']   = $server_addr;
				$result['type'] = 'public';
				return $result;
			}
		}

		if ( ! empty( $_SERVER['LOCAL_ADDR'] ) && filter_var( $_SERVER['LOCAL_ADDR'], FILTER_VALIDATE_IP ) ) {
			$local_addr = sanitize_text_field( wp_unslash( $_SERVER['LOCAL_ADDR'] ) );
			if ( $this->is_private_ip( $local_addr ) ) {
				$result['ip']   = $local_addr;
				$result['type'] = 'private';
				return $result;
			} else {
				$result['ip']   = $local_addr;
				$result['type'] = 'public';
				return $result;
			}
		}

		if ( ! empty( $_SERVER['HTTP_HOST'] ) ) {
			$host = sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) );
			if ( false !== strpos( $host, ':' ) ) {
				$host = strtok( $host, ':' );
			}

			if ( ! empty( $host ) && is_string( $host ) ) {
				$ip = gethostbyname( $host );

				if ( $ip && $ip !== $host && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					if ( $this->is_private_ip( $ip ) ) {
						$result['ip']   = $ip;
						$result['type'] = 'private';
						return $result;
					} else {
						$result['ip']   = $ip;
						$result['type'] = 'public';
						return $result;
					}
				}
			}
		}

		return $result;
	}

	/**
	 * Check if an IP address is private/local.
	 *
	 * @param string $ip IP address to check.
	 * @return bool True if private, false if public.
	 */
	private function is_private_ip( $ip ) {
		if ( empty( $ip ) || ! is_string( $ip ) ) {
			return false;
		}

		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		// Check if it's a private IP range.
		$private_ranges = array(
			'10.0.0.0/8',          // Private network.
			'172.16.0.0/12',       // Private network (172.16.0.0 - 172.31.255.255).
			'192.168.0.0/16',      // Private network.
			'127.0.0.0/8',         // Loopback.
			'169.254.0.0/16',      // Link-local.
			'::1',                 // IPv6 loopback.
			'fc00::/7',            // IPv6 private.
		);

		foreach ( $private_ranges as $range ) {
			if ( $this->ip_in_range( $ip, $range ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if IP is in CIDR range.
	 *
	 * @param string $ip IP address.
	 * @param string $range CIDR range (e.g., "172.16.0.0/12").
	 * @return bool True if IP is in range.
	 */
	private function ip_in_range( $ip, $range ) {
		if ( empty( $ip ) || empty( $range ) || ! is_string( $ip ) || ! is_string( $range ) ) {
			return false;
		}

		if ( strpos( $range, '/' ) === false ) {
			return $ip === $range;
		}

		$range_parts = explode( '/', $range );
		if ( count( $range_parts ) !== 2 ) {
			return false;
		}

		list( $subnet, $mask ) = $range_parts;

		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return false;
		}

		$ip_long     = ip2long( $ip );
		$subnet_long = ip2long( $subnet );

		if ( false === $ip_long || false === $subnet_long ) {
			return false;
		}

		$mask_int = (int) $mask;
		if ( $mask_int < 0 || $mask_int > 32 ) {
			return false;
		}

		$mask_long = -1 << ( 32 - $mask_int );

		return ( $ip_long & $mask_long ) === ( $subnet_long & $mask_long );
	}

	/**
	 * Handle AJAX request for auto-connect to Cloudflare
	 */
	public function ajax_auto_connect() {
		check_ajax_referer( 'pmip-admin-nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized access.', 'polar-mass-advanced-ip-blocker' ) ) );
		}

		$master_token = isset( $_POST['master_token'] ) ? sanitize_text_field( wp_unslash( $_POST['master_token'] ) ) : '';

		if ( empty( $master_token ) ) {
			wp_send_json_error( array( 'message' => __( 'Please enter your master token.', 'polar-mass-advanced-ip-blocker' ) ) );
		}

		try {
			$token_manager = new Cloudflare_Token_Manager( $this->logger );
			$result        = $token_manager->auto_connect( $master_token );

			if ( $result['success'] ) {
				wp_send_json_success(
					array(
						'message' => $result['message'],
						'zones'   => isset( $result['zones'] ) ? $result['zones'] : array(),
					)
				);
			} else {
				wp_send_json_error( array( 'message' => $result['message'] ) );
			}
		} catch ( \Exception $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
	}

	/**
	 * Handle AJAX request for zone selection and rule creation
	 */
	public function ajax_select_zone() {
		check_ajax_referer( 'pmip-admin-nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized access.', 'polar-mass-advanced-ip-blocker' ) ) );
		}

		$zone_id = isset( $_POST['zone_id'] ) ? sanitize_text_field( wp_unslash( $_POST['zone_id'] ) ) : '';

		if ( empty( $zone_id ) ) {
			wp_send_json_error( array( 'message' => __( 'Please select a zone.', 'polar-mass-advanced-ip-blocker' ) ) );
		}

		try {
			$token_manager = new Cloudflare_Token_Manager( $this->logger );
			$scoped_token  = get_option( 'pmip_api_token', '' );

			if ( empty( $scoped_token ) ) {
				wp_send_json_error( array( 'message' => __( 'No API token found. Please connect first.', 'polar-mass-advanced-ip-blocker' ) ) );
			}

			$result = $token_manager->create_rule_for_zone( $zone_id, $scoped_token );

			if ( $result['success'] ) {
				update_option( 'pmip_zone_id', $zone_id );
				update_option( 'pmip_ruleset_id', $result['ruleset_id'] );
				update_option( 'pmip_rule_id', $result['rule_id'] );
				update_option( 'pmip_auto_connected', true );

				delete_transient( 'pmip_connection_status' );

				wp_send_json_success(
					array(
						'message' => __( 'Zone configured successfully! Rule created and ready to use.', 'polar-mass-advanced-ip-blocker' ),
					)
				);
			} else {
				wp_send_json_error( array( 'message' => $result['message'] ) );
			}
		} catch ( \Exception $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
	}
}
