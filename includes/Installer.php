<?php
namespace CloudflareIpBlocker;

class Installer {
    /**
     * Plugin activation
     */
    public function activate() {

        // Check and create required directories
        $this->check_directories();

        // Create default options
        $this->create_options();

        // Create log file
        $this->create_log_file();

        // Schedule cron job
        if (!wp_next_scheduled('cfip_check_ips')) {
            wp_schedule_event(time(), 'cfip_custom_interval', 'cfip_check_ips');
        }

        // Add custom cron interval
        add_filter('cron_schedules', function($schedules) {
            $interval = get_option('cfip_scan_interval', 15) * 60;
            $schedules['cfip_custom_interval'] = [
                'interval' => $interval,
                'display' => sprintf(__('Every %d minutes', 'cloudflare-ip-blocker'), $interval / 60)
            ];
            return $schedules;
        });

        // Flush rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Plugin deactivation
     */
    public function deactivate() {
        // Clear scheduled hooks
        wp_clear_scheduled_hook('cfip_check_ips');

        // Flush rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Plugin uninstallation
     */
    public static function uninstall() {
        // Remove all plugin options
        delete_option('cfip_api_token');
        delete_option('cfip_plugin_status');
        delete_option('cfip_scan_interval');
        delete_option('cfip_failed_attempts');
        delete_option('cfip_block_duration');
        delete_option('cfip_blocked_ips');
        delete_option('cfip_failed_attempts_log');
        delete_option('cfip_ip_whitelist');

        // Remove log file and plugin directory
        $upload_dir = wp_upload_dir();
        $plugin_dir = $upload_dir['basedir'] . '/cloudflare-ip-blocker';
        
        if (file_exists($plugin_dir)) {
            $this->recursive_remove_directory($plugin_dir);
        }
    }

    /**
     * Create default options
     */
    private function create_options() {
        add_option('cfip_api_token', '');
        add_option('cfip_plugin_status', 'inactive');
        add_option('cfip_scan_interval', 15);
        add_option('cfip_failed_attempts', 5);
        add_option('cfip_block_duration', '24h');
        add_option('cfip_blocked_ips', []);
        add_option('cfip_failed_attempts_log', []);
        add_option('cfip_ip_whitelist', []);
        add_option('cfip_newsletter_subscribed', '0', '', 'yes'); // Add newsletter subscription flag
    }

    /**
     * Create log file
     */
    private function create_log_file() {
        $upload_dir = wp_upload_dir();
        $log_file = $upload_dir['basedir'] . '/cloudflare-ip-blocker/cloudflare-ip-blocker.log';

        if (!file_exists($log_file)) {
            $handle = fopen($log_file, 'w');
            if ($handle) {
                fclose($handle);
                chmod($log_file, 0644);
            }
        }
    }

    /**
     * Check and create required directories
     */
    private function check_directories() {
        $upload_dir = wp_upload_dir();
        $plugin_dir = $upload_dir['basedir'] . '/cloudflare-ip-blocker';

        // Create main plugin directory
        if (!file_exists($plugin_dir)) {
            wp_mkdir_p($plugin_dir);
        }

        // Create .htaccess to prevent direct access
        $directories = [$plugin_dir];
        foreach ($directories as $dir) {
            $htaccess = $dir . '/.htaccess';
            if (!file_exists($htaccess)) {
                $content = "Order deny,allow\nDeny from all";
                file_put_contents($htaccess, $content);
            }

            // Create index.php to prevent directory listing
            $index = $dir . '/index.php';
            if (!file_exists($index)) {
                file_put_contents($index, '<?php // Silence is golden');
            }

            // Set proper permissions
            $this->set_directory_permissions($dir);
        }
    }

    /**
     * Set proper directory permissions
     *
     * @param string $dir Directory path
     */
    private function set_directory_permissions($dir) {
        // Set directory permissions to 755
        chmod($dir, 0755);

        // Set file permissions to 644
        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            if (is_file($path)) {
                chmod($path, 0644);
            }
        }
    }

    /**
     * Recursively remove a directory and its contents
     *
     * @param string $dir Directory path
     */
    private static function recursive_remove_directory($dir) {
        if (is_dir($dir)) {
            $files = array_diff(scandir($dir), ['.', '..']);
            foreach ($files as $file) {
                $path = $dir . '/' . $file;
                if (is_dir($path)) {
                    self::recursive_remove_directory($path);
                } else {
                    unlink($path);
                }
            }
            rmdir($dir);
        }
    }

    // Rest of the existing methods...
}