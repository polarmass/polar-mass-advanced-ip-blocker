<?php
/**
 * Autoloader
 *
 * @author Polar Mass
 * @since 1.0.0
 * @package polar-mass-advanced-ip-blocker
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

spl_autoload_register(
	function ( $class ) {
		$prefix   = 'Pm_Ip_Blocker\\';
		$base_dir = PMIP_BLOCKER_PLUGIN_DIR . 'includes/';

		// Check if the class belongs to our namespace.
		$len = strlen( $prefix );
		if ( strncmp( $prefix, $class, $len ) !== 0 ) {
			return;
		}

		// Remove the namespace.
		$relative_class = substr( $class, $len );

		// Convert PascalCase and underscores into kebab-case.
		$relative_class = strtolower(
			preg_replace( array( '/([a-z])([A-Z])/', '/_/' ), array( '$1-$2', '-' ), $relative_class )
		);

		$file = $base_dir . 'class-' . $relative_class . '.php';

		if ( file_exists( $file ) ) {
			require $file;
		}
	}
);
