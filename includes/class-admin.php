<?php
/**
 * Admin class for managing plugin settings and UI.
 *
 * @author Polar Mass
 * @since 1.0.0
 * @package cloudflare-ip-blocker
 */

namespace Cloudflare_Ip_Blocker;

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
		add_action( 'wp_ajax_cfip_block_ip', array( $this, 'ajax_block_ip' ) );
		add_action( 'wp_ajax_cfip_unblock_ip', array( $this, 'ajax_unblock_ip' ) );
		add_action( 'wp_ajax_cfip_sync_wordfence', array( $this, 'ajax_sync_wordfence' ) );
		add_action( 'wp_ajax_cfip_update_newsletter_status', array( $this, 'ajax_update_newsletter_status' ) );
		add_action( 'wp_ajax_cfip_export_logs', array( $this, 'ajax_export_logs' ) );
	}

	/**
	 * Add admin menu items
	 */
	public function add_admin_menu() {
		add_menu_page(
			__( 'Polar Mass Advanced IP Blocker', 'cloudflare-ip-blocker' ),
			__( 'PM IP Blocker', 'cloudflare-ip-blocker' ),
			'manage_options',
			'cloudflare-ip-blocker',
			array( $this, 'render_admin_page' ),
			'dashicons-shield',
			100
		);
	}

	/**
	 * Register plugin settings
	 */
	public function register_settings() {
		register_setting(
			'cfip_settings',
			'cfip_api_token',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '',
			)
		);

		register_setting(
			'cfip_settings',
			'cfip_zone_id',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '',
			)
		);

		register_setting(
			'cfip_settings',
			'cfip_ruleset_id',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '',
			)
		);

		register_setting(
			'cfip_settings',
			'cfip_rule_id',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '',
			)
		);

		register_setting(
			'cfip_settings',
			'cfip_plugin_status',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => 'inactive',
			)
		);

		register_setting(
			'cfip_settings',
			'cfip_scan_interval',
			array(
				'type'              => 'integer',
				'sanitize_callback' => 'absint',
				'default'           => 15,
			)
		);

		register_setting(
			'cfip_settings',
			'cfip_failed_attempts',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_failed_attempts' ),
				'default'           => 5,
			)
		);

		register_setting(
			'cfip_settings',
			'cfip_block_duration',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '24h',
			)
		);

		register_setting(
			'cfip_settings',
			'cfip_max_logs',
			array(
				'type'              => 'integer',
				'sanitize_callback' => 'absint',
				'default'           => 1000,
			)
		);
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
		if ( 'toplevel_page_cloudflare-ip-blocker' !== $hook ) {
			return;
		}

		wp_enqueue_style(
			'cfip-admin-styles',
			CFIP_BLOCKER_PLUGIN_URL . 'assets/css/admin.min.css',
			array(),
			CFIP_BLOCKER_VERSION
		);

		wp_enqueue_script(
			'cfip-admin-script',
			CFIP_BLOCKER_PLUGIN_URL . 'assets/js/admin.min.js',
			array( 'jquery' ),
			CFIP_BLOCKER_VERSION,
			true
		);

		wp_localize_script(
			'cfip-admin-script',
			'cfipAdmin',
			array(
				'ajaxUrl'      => admin_url( 'admin-ajax.php' ),
				'nonce'        => wp_create_nonce( 'cfip-admin-nonce' ),
				'isSubscribed' => get_option( 'cfip_newsletter_subscribed', 0 ) === 1,
				'i18n'         => array(
					'confirmBlock'   => __( 'Are you sure you want to block this IP?', 'cloudflare-ip-blocker' ),
					'confirmUnblock' => __( 'Are you sure you want to unblock this IP?', 'cloudflare-ip-blocker' ),
					'confirmSync'    => __( 'Are you sure you want to sync blocked IPs from Wordfence?', 'cloudflare-ip-blocker' ),
					'success'        => __( 'Operation completed successfully.', 'cloudflare-ip-blocker' ),
					'error'          => __( 'An error occurred. Please try again.', 'cloudflare-ip-blocker' ),
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

			if ( wp_verify_nonce( $nonce, 'cfip_settings' ) ) {
				$this->save_settings();
			}
		}

		include CFIP_BLOCKER_PLUGIN_DIR . 'views/admin-page.php';
	}

	/**
	 * Save plugin settings securely.
	 */
	private function save_settings() {
		if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'cfip_settings' ) ) {
			wp_die( esc_html__( 'Security check failed. Please try again.', 'cloudflare-ip-blocker' ) );
		}

		// Sanitize and update each field.
		$fields = array(
			'cfip_api_token'      => 'sanitize_text_field',
			'cfip_zone_id'        => 'sanitize_text_field',
			'cfip_ruleset_id'     => 'sanitize_text_field',
			'cfip_rule_id'        => 'sanitize_text_field',
			'cfip_plugin_status'  => 'sanitize_text_field',
			'cfip_block_duration' => 'sanitize_text_field',
			'cfip_max_logs'       => 'absint',
		);

		foreach ( $fields as $field => $sanitizer ) {
			if ( isset( $_POST[ $field ] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				update_option( $field, call_user_func( $sanitizer, wp_unslash( $_POST[ $field ] ) ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			}
		}

		// Handle scan interval separately since it's an integer.
		if ( isset( $_POST['cfip_scan_interval'] ) ) {
			$scan_interval = sanitize_text_field( wp_unslash( $_POST['cfip_scan_interval'] ) );
			update_option( 'cfip_scan_interval', absint( $scan_interval ) );
			wp_clear_scheduled_hook( 'cfip_check_ips' );
			wp_schedule_event( time(), 'cfip_custom_interval', 'cfip_check_ips' );
		}

		// Handle failed attempts with custom sanitizer.
		if ( isset( $_POST['cfip_failed_attempts'] ) ) {
			$failed_attempts = sanitize_text_field( wp_unslash( $_POST['cfip_failed_attempts'] ) );
			update_option( 'cfip_failed_attempts', $this->sanitize_failed_attempts( $failed_attempts ) );
		}

		add_settings_error(
			'cfip_settings',
			'settings_updated',
			__( 'Settings saved successfully.', 'cloudflare-ip-blocker' ),
			'updated'
		);
	}

	/**
	 * Handle AJAX request to block IP
	 */
	public function ajax_block_ip() {
		check_ajax_referer( 'cfip-admin-nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized access.', 'cloudflare-ip-blocker' ) ) );
		}

		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid IP address.', 'cloudflare-ip-blocker' ) ) );
		}

		try {
			$ip_blocker = new Ip_Blocker( $this->logger );
			$result     = $ip_blocker->block_ip( $ip );

			if ( $result ) {
				/* translators: %s: success message */
				wp_send_json_success( array( 'message' => sprintf( __( 'IP %s blocked successfully.', 'cloudflare-ip-blocker' ), $ip ) ) );
			} else {
				/* translators: %s: error message */
				wp_send_json_error( array( 'message' => sprintf( __( 'Failed to block IP %s.', 'cloudflare-ip-blocker' ), $ip ) ) );
			}
		} catch ( \Exception $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
	}

	/**
	 * Handle AJAX request to update newsletter status
	 */
	public function ajax_update_newsletter_status() {
		check_ajax_referer( 'cfip-admin-nonce', 'nonce' );

		update_option( 'cfip_newsletter_subscribed', 1 );
		wp_send_json_success();
	}

	/**
	 * Handle exporting logs as CSV.
	 */
	public function ajax_export_logs() {
		// Check nonce for security.
		if ( ! isset( $_GET['nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['nonce'] ) ), 'cfip-admin-nonce' ) ) {
			wp_die( esc_html__( 'Invalid nonce.', 'cloudflare-ip-blocker' ) );
		}

		// Call the logger to get CSV content.
		$csv_content = $this->logger->export_logs_csv();

		if ( empty( $csv_content ) ) {
			wp_die( esc_html__( 'No logs available.', 'cloudflare-ip-blocker' ) );
		}

		// Set headers for CSV download.
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="cfip-logs.csv"' );

		// Escape output before printing.
		echo $csv_content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV output needs raw data.
		exit;
	}

	/**
	 * Handle AJAX request to unblock IP
	 */
	public function ajax_unblock_ip() {
		check_ajax_referer( 'cfip-admin-nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized access.', 'cloudflare-ip-blocker' ) ) );
		}

		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid IP address.', 'cloudflare-ip-blocker' ) ) );
		}

		try {
			$ip_blocker = new Ip_Blocker( $this->logger );
			$result     = $ip_blocker->unblock_ip( $ip );

			if ( $result ) {
				/* translators: %s: success message */
				wp_send_json_success( array( 'message' => sprintf( __( 'IP %s unblocked successfully.', 'cloudflare-ip-blocker' ), $ip ) ) );
			} else {
				/* translators: %s: error message */
				wp_send_json_error( array( 'message' => sprintf( __( 'Failed to unblock IP %s.', 'cloudflare-ip-blocker' ), $ip ) ) );
			}
		} catch ( \Exception $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
	}

	/**
	 * Handle AJAX request to sync with Wordfence
	 */
	public function ajax_sync_wordfence() {
		check_ajax_referer( 'cfip-admin-nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized access.', 'cloudflare-ip-blocker' ) ) );
		}

		try {
			$ip_blocker = new Ip_Blocker( $this->logger );
			$result     = $ip_blocker->sync_from_wordfence();

			if ( $result ) {
				wp_send_json_success( array( 'message' => __( 'Successfully synced IPs from Wordfence.', 'cloudflare-ip-blocker' ) ) );
			} else {
				wp_send_json_error( array( 'message' => __( 'Failed to sync IPs from Wordfence.', 'cloudflare-ip-blocker' ) ) );
			}
		} catch ( \Exception $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
	}

	/**
	 * Handle newsletter subscription
	 */
	public function ajax_subscribe_newsletter() {
		check_ajax_referer( 'cfip-admin-nonce', 'nonce' );

		$email = isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '';
		if ( ! is_email( $email ) ) {
			wp_send_json_error( array( 'message' => __( 'Please enter a valid email address.', 'cloudflare-ip-blocker' ) ) );
		}

		// Add subscriber to the database.
		$subscribers = get_option( 'cfip_newsletter_subscribers', array() );
		if ( in_array( $email, $subscribers, true ) ) {
			wp_send_json_error( array( 'message' => __( 'You are already subscribed!', 'cloudflare-ip-blocker' ) ) );
		}

		$subscribers[] = $email;
		update_option( 'cfip_newsletter_subscribers', $subscribers );

		// Log the subscription.
		$this->logger->log( "New newsletter subscription: {$email}" );

		// You can add additional integration here (e.g., with a newsletter service).

		wp_send_json_success( array( 'message' => __( 'Thank you for subscribing!', 'cloudflare-ip-blocker' ) ) );
	}
}
