<?php
/**
 * Handles plugin installation tasks.
 *
 * @author Polar Mass
 * @since 1.0.0
 * @package cloudflare-ip-blocker
 */

namespace Cloudflare_Ip_Blocker;

/**
 * Handles the installation process for the plugin.
 */
class Installer {
	/**
	 * Plugin activation
	 */
	public function activate() {

		// Check and create required directories.
		$this->check_directories();

		// Create default options.
		$this->create_options();

		// Create log file.
		$this->create_log_file();

		// Schedule cron job.
		if ( ! wp_next_scheduled( 'cfip_check_ips' ) ) {
			wp_schedule_event( time(), 'cfip_custom_interval', 'cfip_check_ips' );
		}

		// Add custom cron interval.
		add_filter(
			'cron_schedules',
			function( $schedules ) {
				$interval                          = get_option( 'cfip_scan_interval', 15 ) * 60;
				$schedules['cfip_custom_interval'] = array(
					'interval' => $interval,
					/* translators: %d: interval in minutes */
					'display'  => sprintf( esc_html__( 'Every %d minutes', 'cloudflare-ip-blocker' ), $interval / 60 ),
				);
				return $schedules;
			}
		);

		// Flush rewrite rules.
		flush_rewrite_rules();
	}

	/**
	 * Plugin deactivation
	 */
	public function deactivate() {
		// Clear scheduled hooks.
		wp_clear_scheduled_hook( 'cfip_check_ips' );

		// Flush rewrite rules.
		flush_rewrite_rules();
	}

	/**
	 * Plugin uninstallation
	 */
	public static function uninstall() {
		// Remove all plugin options.
		delete_option( 'cfip_api_token' );
		delete_option( 'cfip_plugin_status' );
		delete_option( 'cfip_scan_interval' );
		delete_option( 'cfip_failed_attempts' );
		delete_option( 'cfip_block_duration' );
		delete_option( 'cfip_blocked_ips' );
		delete_option( 'cfip_failed_attempts_log' );
		delete_option( 'cfip_ip_whitelist' );

		// Remove log file and plugin directory.
		$upload_dir = wp_upload_dir();
		$plugin_dir = $upload_dir['basedir'] . '/cloudflare-ip-blocker';

		if ( file_exists( $plugin_dir ) ) {
			self::recursive_remove_directory( $plugin_dir );
		}
	}

	/**
	 * Create default options
	 */
	private function create_options() {
		add_option( 'cfip_api_token', '' );
		add_option( 'cfip_plugin_status', 'inactive' );
		add_option( 'cfip_scan_interval', 15 );
		add_option( 'cfip_failed_attempts', 5 );
		add_option( 'cfip_block_duration', '24h' );
		add_option( 'cfip_max_logs', 1000 );
		add_option( 'cfip_blocked_ips', array() );
		add_option( 'cfip_failed_attempts_log', array() );
		add_option( 'cfip_ip_whitelist', array() );
		add_option( 'cfip_newsletter_subscribed', '0', '', 'yes' ); // Add newsletter subscription flag.
	}

	/**
	 * Create log file using WP_Filesystem.
	 */
	private function create_log_file() {
		global $wp_filesystem;
		if ( empty( $wp_filesystem ) ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';

			\WP_Filesystem();
		}

		$upload_dir = wp_upload_dir();
		$log_dir    = $upload_dir['basedir'] . '/cloudflare-ip-blocker';
		$log_file   = $log_dir . '/cloudflare-ip-blocker.log';

		// Create log directory if it doesn't exist.
		if ( ! $wp_filesystem->is_dir( $log_dir ) ) {
			$wp_filesystem->mkdir( $log_dir );
		}

		// Create log file if it doesn't exist.
		if ( ! $wp_filesystem->exists( $log_file ) ) {
			$wp_filesystem->put_contents( $log_file, '', FS_CHMOD_FILE );
		}
	}

	/**
	 * Check and create required directories using WP_Filesystem.
	 */
	private function check_directories() {
		global $wp_filesystem;
		if ( empty( $wp_filesystem ) ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';

			\WP_Filesystem();
		}

		$upload_dir = wp_upload_dir();
		$plugin_dir = $upload_dir['basedir'] . '/cloudflare-ip-blocker';

		// Create main plugin directory.
		if ( ! $wp_filesystem->is_dir( $plugin_dir ) ) {
			$wp_filesystem->mkdir( $plugin_dir );
		}

		// Create .htaccess to prevent direct access.
		$htaccess = $plugin_dir . '/.htaccess';
		if ( ! $wp_filesystem->exists( $htaccess ) ) {
			$content = "Order deny,allow\nDeny from all";
			$wp_filesystem->put_contents( $htaccess, $content, FS_CHMOD_FILE );
		}

		// Create index.php to prevent directory listing.
		$index = $plugin_dir . '/index.php';
		if ( ! $wp_filesystem->exists( $index ) ) {
			$wp_filesystem->put_contents( $index, '<?php // Silence is golden', FS_CHMOD_FILE );
		}
	}

	/**
	 * Recursively remove a directory and its contents using WP_Filesystem.
	 *
	 * @param string $dir Directory path.
	 */
	private static function recursive_remove_directory( $dir ) {
		global $wp_filesystem;
		if ( empty( $wp_filesystem ) ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';

			\WP_Filesystem();
		}

		if ( $wp_filesystem->is_dir( $dir ) ) {
			$files = $wp_filesystem->dirlist( $dir );
			if ( $files ) {
				foreach ( $files as $file => $file_info ) {
					$path = trailingslashit( $dir ) . $file;
					if ( 'd' === $file_info['type'] ) {
						self::recursive_remove_directory( $path );
					} else {
						$wp_filesystem->delete( $path );
					}
				}
			}
			$wp_filesystem->rmdir( $dir );
		}
	}
}
