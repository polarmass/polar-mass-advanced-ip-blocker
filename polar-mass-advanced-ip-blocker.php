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
 * Text Domain: polar-mass-advanced-ip-blocker
 * Domain Path: /languages
 * Requires at least: 5.8
 * Requires PHP: 7.4
 *
 * @author Polar Mass
 * @since 1.0.1
 * @package polar-mass-advanced-ip-blocker
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Plugin constants.
define( 'PMIP_BLOCKER_VERSION', '1.0.1' );
define( 'PMIP_BLOCKER_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'PMIP_BLOCKER_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

require_once PMIP_BLOCKER_PLUGIN_DIR . 'autoload.php';

/**
 * Initialize the plugin.
 */
function pmip_blocker_init() {
	// Initialize main plugin class.
	$plugin = new Pm_Ip_Blocker\Plugin();
	$plugin->init();
}
add_action( 'plugins_loaded', 'pmip_blocker_init' );

/**
 * Load the plugin text domain.
 */
function pmip_blocker_load_textdomain() {
	// Load text domain for translations.
	load_plugin_textdomain( 'polar-mass-advanced-ip-blocker', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
}

add_action( 'init', 'pmip_blocker_load_textdomain' );

// Activation hook.
register_activation_hook(
	__FILE__,
	function() {
		$installer = new Pm_Ip_Blocker\Installer();
		$installer->activate();
	}
);

// Deactivation hook.
register_deactivation_hook(
	__FILE__,
	function() {
		$installer = new Pm_Ip_Blocker\Installer();
		$installer->deactivate();
	}
);

// Uninstall hook.
register_uninstall_hook( __FILE__, array( 'Pm_Ip_Blocker\Installer', 'uninstall' ) );
