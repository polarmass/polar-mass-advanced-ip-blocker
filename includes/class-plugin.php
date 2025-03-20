<?php
/**
 * Main plugin class for Cloudflare IP Blocker.
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
 * Handles the core functionality of the Cloudflare IP Blocker plugin.
 */
class Plugin {
	/**
	 * Admin instance
	 *
	 * @var Admin
	 */
	private $admin;

	/**
	 * IP Blocker instance
	 *
	 * @var Ip_Blocker
	 */
	private $ip_blocker;

	/**
	 * Logger instance
	 *
	 * @var Logger
	 */
	private $logger;

	/**
	 * Initialize the plugin
	 */
	public function init() {
		// Initialize components.
		$this->logger     = new Logger();
		$this->admin      = new Admin( $this->logger );
		$this->ip_blocker = new Ip_Blocker( $this->logger );

		// Set up hooks.
		$this->setup_hooks();

		// Initialize admin if in admin area.
		if ( is_admin() ) {
			$this->admin->init();
		}
	}

	/**
	 * Set up WordPress hooks
	 */
	private function setup_hooks() {
		// Add custom cron intervals.
		add_filter( 'cron_schedules', array( $this, 'add_cron_intervals' ) );

		// Schedule IP check cron job.
		if ( ! wp_next_scheduled( 'pmip_check_ips' ) ) {
			wp_schedule_event( time(), 'pmip_custom_interval', 'pmip_check_ips' );
		}

		// Schedule Real - Time IP check cron job.
		if ( ! wp_next_scheduled( 'pmip_realtime_check_ips' ) ) {
			wp_schedule_event( time(), 'pmip_realtime_interval', 'pmip_realtime_check_ips' );
		}

		// Hook into IP check cron job.
		add_action( 'pmip_check_ips', array( $this->ip_blocker, 'check_and_block_ips' ) );

		// Hook into Real - Time IP check cron job.
		add_action( 'pmip_realtime_check_ips', array( $this->ip_blocker, 'real_time_block_ips' ) );

		// Hook into Wordfence failed login attempts.
		add_action( 'wordfence_security_event', array( $this->ip_blocker, 'handle_wordfence_event' ), 8, 2 );

		// admin_notices hook.
		add_action( 'admin_notices', array( $this, 'check_requirements' ) );
	}

	/**
	 * Check if plugin requirements are met
	 *
	 * @return bool Whether requirements are met.
	 */
	public function check_requirements() {
		$requirements_met = true;
		$screen           = get_current_screen();

		// Check if Wordfence is active.
		if ( ! is_plugin_active( 'wordfence/wordfence.php' ) ) {
			echo '<div class="notice notice-error is-dismissible"><p>' .
					esc_html__( 'Polar Mass Advanced IP Blocker requires Wordfence to be installed and activated.', 'polar-mass-advanced-ip-blocker' ) .
					'</p></div>';
			$requirements_met = false;
		}

		// Check if Cron is registered.
		if ( ! wp_next_scheduled( 'pmip_check_ips' ) || ! wp_next_scheduled( 'pmip_realtime_check_ips' ) ) {
			ob_start();
			wp_nonce_field( 'pmip-admin-nonce', 'pmip-admin-nonce' );
			$nonce_field = ob_get_clean(); // Capture output safely

			echo '<div class="notice notice-error pmip-register-cron is-dismissible">
				<p>' . esc_html__( 'Polar Mass Advanced IP Blocker requires cron jobs to be registered. Please click the button below to register the cron jobs.', 'polar-mass-advanced-ip-blocker' ) . '</p>
				<form method="post" action="options-general.php?page=polar-mass-advanced-ip-blocker" style="margin-bottom: 10px;">
					' .
					$nonce_field // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					. '
					<input type="submit" class="button button-primary" value="' . esc_html__( 'Register Cron Jobs', 'polar-mass-advanced-ip-blocker' ) . '" />
				</form>
			</div>';

			$requirements_met = false;
		}

		if ( $screen && $screen->id !== 'toplevel_page_polar-mass-advanced-ip-blocker' ) {
			return $requirements_met;
		}
		// Check PHP version.
		if ( version_compare( PHP_VERSION, '7.4', '<' ) ) {
			echo '<div class="notice notice-error"><p>' .
				sprintf(
					/* translators: 1: Required PHP version, 2: Current PHP version */
					esc_html__( 'Polar Mass Advanced IP Blocker requires PHP %1$s or higher. Your current PHP version is %2$s.', 'polar-mass-advanced-ip-blocker' ),
					'7.4',
					esc_html( PHP_VERSION )
				) .
			'</p></div>';
			$requirements_met = false;
		}

		// Check WordPress version.
		global $wp_version;
		if ( version_compare( $wp_version, '5.8', '<' ) ) {
			echo '<div class="notice notice-error"><p>' .
				sprintf(
					/* translators: 1: Required WordPress version, 2: Current WordPress version */
					esc_html__( 'Polar Mass Advanced IP Blocker requires WordPress %1$s or higher. Your current WordPress version is %2$s.', 'polar-mass-advanced-ip-blocker' ),
					'5.8',
					esc_html( $wp_version )
				) .
			'</p></div>';
			$requirements_met = false;
		}

		// Check if uploads directory is writable.
		$upload_dir = wp_upload_dir();
		if ( ! wp_is_writable( $upload_dir['basedir'] ) ) {
			echo '<div class="notice notice-error"><p>' .
				sprintf(
					/* translators: %s: Uploads directory path */
					esc_html__( 'Polar Mass Advanced IP Blocker requires write access to the uploads directory: %s', 'polar-mass-advanced-ip-blocker' ),
					esc_html( $upload_dir['basedir'] )
				) .
			'</p></div>';
			$requirements_met = false;
		}

		return $requirements_met;
	}

	/**
	 * Add custom cron intervals
	 *
	 * @param array $schedules Existing cron schedules.
	 * @return array Modified cron schedules.
	 */
	public function add_cron_intervals( $schedules ) {
		$interval = get_option( 'pmip_scan_interval', 15 ) * 60; // Convert minutes to seconds.

		$schedules['pmip_custom_interval'] = array(
			'interval' => $interval,
			/* translators: %d: Interval in minutes. */
			'display'  => sprintf( esc_html__( 'Every %d minutes', 'polar-mass-advanced-ip-blocker' ), $interval / 60 ),
		);

		// Real-time IP check interval.
		$schedules['pmip_realtime_interval'] = array(
			'interval' => 60,
			'display'  => esc_html__( 'Every minute', 'polar-mass-advanced-ip-blocker' ),
		);

		return $schedules;
	}
}
