<?php
/**
 * Plugin Name: Polar Mass Advanced IP Blocker
 * Plugin URI: https://polarmass.com/polar-mass-advanced-ip-blocker
 * Description: Automatically blocks malicious IP addresses through Cloudflare integration based on Wordfence failed login attempts.
 * Version: 1.0.1
 * Author: Polar Mass
 * Author URI: https://polarmass.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: cloudflare-ip-blocker
 * Domain Path: /languages
 * Requires at least: 5.8
 * Requires PHP: 7.4
 *
 * @author Polar Mass
 * @since 1.0.0
 * @package cloudflare-ip-blocker
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Plugin constants.
define( 'CFIP_BLOCKER_VERSION', '1.0.1' );
define( 'CFIP_BLOCKER_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'CFIP_BLOCKER_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

require_once CFIP_BLOCKER_PLUGIN_DIR . 'autoload.php';

/**
 * Initialize the plugin.
 */
function cfip_blocker_init() {
	// Load text domain for translations.
	load_plugin_textdomain( 'cloudflare-ip-blocker', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );

	// Initialize main plugin class.
	$plugin = new Cloudflare_Ip_Blocker\Plugin();
	$plugin->init();
}
add_action( 'plugins_loaded', 'cfip_blocker_init' );

// Activation hook.
register_activation_hook(
	__FILE__,
	function() {
		$installer = new Cloudflare_Ip_Blocker\Installer();
		$installer->activate();
	}
);

// Deactivation hook.
register_deactivation_hook(
	__FILE__,
	function() {
		$installer = new Cloudflare_Ip_Blocker\Installer();
		$installer->deactivate();
	}
);

// Uninstall hook.
register_uninstall_hook( __FILE__, array( 'Cloudflare_Ip_Blocker\Installer', 'uninstall' ) );
