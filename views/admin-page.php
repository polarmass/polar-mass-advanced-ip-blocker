<?php
if (!defined('ABSPATH')) {
    exit;
}

use CloudflareIpBlocker\Logger;
?>
<div class="wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

    <?php settings_errors('cfip_settings'); ?>

    <div class="cfip-admin-grid">
        <div class="cfip-main-settings">
            <form method="post" action="">
                <?php wp_nonce_field('cfip_settings'); ?>
                
                <h2><?php _e('General Settings', 'cloudflare-ip-blocker'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <label for="cfip_plugin_status"><?php _e('Plugin Status', 'cloudflare-ip-blocker'); ?></label>
                        </th>
                        <td>
                            <select id="cfip_plugin_status" name="cfip_plugin_status">
                                <option value="active" <?php selected(get_option('cfip_plugin_status'), 'active'); ?>>
                                    <?php _e('Active', 'cloudflare-ip-blocker'); ?>
                                </option>
                                <option value="inactive" <?php selected(get_option('cfip_plugin_status'), 'inactive'); ?>>
                                    <?php _e('Inactive', 'cloudflare-ip-blocker'); ?>
                                </option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="cfip_api_token"><?php _e('Cloudflare API Token', 'cloudflare-ip-blocker'); ?></label>
                        </th>
                        <td>
                            <input type="password" 
                                   id="cfip_api_token" 
                                   name="cfip_api_token" 
                                   value="<?php echo esc_attr(get_option('cfip_api_token')); ?>" 
                                   class="regular-text">
                            <p class="description">
                                <?php _e('Enter your Cloudflare API token. <a href="#" class="cfip-show-token-instructions">How to get your API token?</a>', 'cloudflare-ip-blocker'); ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="cfip_zone_id"><?php _e('Zone ID', 'cloudflare-ip-blocker'); ?></label>
                        </th>
                        <td>
                            <input type="text" 
                                   id="cfip_zone_id" 
                                   name="cfip_zone_id" 
                                   value="<?php echo esc_attr(get_option('cfip_zone_id')); ?>" 
                                   class="regular-text">
                            <p class="description">
                                <?php _e('Enter your Cloudflare Zone ID. Found in the Overview tab of your domain.', 'cloudflare-ip-blocker'); ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="cfip_ruleset_id"><?php _e('Ruleset ID', 'cloudflare-ip-blocker'); ?></label>
                        </th>
                        <td>
                            <input type="text" 
                                   id="cfip_ruleset_id" 
                                   name="cfip_ruleset_id" 
                                   value="<?php echo esc_attr(get_option('cfip_ruleset_id')); ?>" 
                                   class="regular-text">
                            <p class="description">
                                <?php _e('Enter your Cloudflare Ruleset ID. Found in the WAF > Custom Rules section.', 'cloudflare-ip-blocker'); ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="cfip_rule_id"><?php _e('Rule ID', 'cloudflare-ip-blocker'); ?></label>
                        </th>
                        <td>
                            <input type="text" 
                                   id="cfip_rule_id" 
                                   name="cfip_rule_id" 
                                   value="<?php echo esc_attr(get_option('cfip_rule_id')); ?>" 
                                   class="regular-text">
                            <p class="description">
                                <?php _e('Enter your Cloudflare Rule ID. Found in the specific rule settings under WAF > Custom Rules.', 'cloudflare-ip-blocker'); ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="cfip_scan_interval"><?php _e('Scan Interval', 'cloudflare-ip-blocker'); ?></label>
                        </th>
                        <td>
                            <select id="cfip_scan_interval" name="cfip_scan_interval">
                                <option value="5" <?php selected(get_option('cfip_scan_interval'), 5); ?>>
                                    <?php _e('5 minutes', 'cloudflare-ip-blocker'); ?>
                                </option>
                                <option value="15" <?php selected(get_option('cfip_scan_interval'), 15); ?>>
                                    <?php _e('15 minutes', 'cloudflare-ip-blocker'); ?>
                                </option>
                                <option value="30" <?php selected(get_option('cfip_scan_interval'), 30); ?>>
                                    <?php _e('30 minutes', 'cloudflare-ip-blocker'); ?>
                                </option>
                                <option value="60" <?php selected(get_option('cfip_scan_interval'), 60); ?>>
                                    <?php _e('60 minutes', 'cloudflare-ip-blocker'); ?>
                                </option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="cfip_failed_attempts"><?php _e('Failed Attempts Threshold', 'cloudflare-ip-blocker'); ?></label>
                        </th>
                        <td>
                            <input type="number" 
                                   id="cfip_failed_attempts" 
                                   name="cfip_failed_attempts" 
                                   value="<?php echo esc_attr(get_option('cfip_failed_attempts', 5)); ?>" 
                                   min="3" 
                                   max="10" 
                                   class="small-text">
                            <p class="description">
                                <?php _e('Number of failed login attempts before blocking (3-10)', 'cloudflare-ip-blocker'); ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="cfip_block_duration"><?php _e('Block Duration', 'cloudflare-ip-blocker'); ?></label>
                        </th>
                        <td>
                            <select id="cfip_block_duration" name="cfip_block_duration">
                                <option value="24h" <?php selected(get_option('cfip_block_duration'), '24h'); ?>>
                                    <?php _e('24 Hours', 'cloudflare-ip-blocker'); ?>
                                </option>
                                <option value="7d" <?php selected(get_option('cfip_block_duration'), '7d'); ?>>
                                    <?php _e('7 Days', 'cloudflare-ip-blocker'); ?>
                                </option>
                                <option value="permanent" <?php selected(get_option('cfip_block_duration'), 'permanent'); ?>>
                                    <?php _e('Permanent', 'cloudflare-ip-blocker'); ?>
                                </option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="cfip_max_logs"><?php _e('Maximum Log Entries', 'cloudflare-ip-blocker'); ?></label>
                        </th>
                        <td>
                            <input type="number" 
                                   id="cfip_max_logs" 
                                   name="cfip_max_logs" 
                                   value="<?php echo esc_attr(get_option('cfip_max_logs', 1000)); ?>" 
                                   min="100" 
                                   class="small-text">
                            <p class="description">
                                <?php _e('Maximum number of log entries to keep', 'cloudflare-ip-blocker'); ?>
                            </p>
                        </td>
                    </tr>
                </table>

                <?php submit_button(); ?>
            </form>
        </div>

        <div class="cfip-side-panel">
            <div class="cfip-manual-block">
                <h3><?php _e('Manual IP Management', 'cloudflare-ip-blocker'); ?></h3>
                <div class="cfip-manual-block-form">
                    <input type="text" id="cfip-ip-input" placeholder="<?php esc_attr_e('Enter IP address', 'cloudflare-ip-blocker'); ?>">
                    <button class="button button-primary" id="cfip-block-ip">
                        <?php _e('Block IP', 'cloudflare-ip-blocker'); ?>
                    </button>
                    <button class="button" id="cfip-unblock-ip">
                        <?php _e('Unblock IP', 'cloudflare-ip-blocker'); ?>
                    </button>
                </div>
                <div class="cfip-manual-sync">
                    <button class="button button-secondary" id="cfip-sync-wordfence">
                        <?php _e('Sync from Wordfence', 'cloudflare-ip-blocker'); ?>
                    </button>
                    <p class="description">
                        <?php _e('Manually sync blocked IPs from Wordfence', 'cloudflare-ip-blocker'); ?>
                    </p>
                </div>
            </div>

            <div class="cfip-logs">
                <h3><?php _e('Recent Activity Logs', 'cloudflare-ip-blocker'); ?></h3>
                <div class="cfip-log-filters">
                    <select id="cfip-log-level">
                        <option value=""><?php _e('All Levels', 'cloudflare-ip-blocker'); ?></option>
                        <option value="info"><?php _e('Info', 'cloudflare-ip-blocker'); ?></option>
                        <option value="warning"><?php _e('Warning', 'cloudflare-ip-blocker'); ?></option>
                        <option value="error"><?php _e('Error', 'cloudflare-ip-blocker'); ?></option>
                    </select>
                    <button class="button" id="cfip-export-logs">
                        <?php _e('Export Logs', 'cloudflare-ip-blocker'); ?>
                    </button>
                </div>
                <div class="cfip-log-entries">
                    <?php
                    $logger = new Logger();
                    $logs = $logger->get_logs(10);
                    if (empty($logs)): ?>
                        <p><?php _e('No logs available', 'cloudflare-ip-blocker'); ?></p>
                    <?php else: ?>
                        <table class="widefat">
                            <thead>
                                <tr>
                                    <th><?php _e('Time', 'cloudflare-ip-blocker'); ?></th>
                                    <th><?php _e('Level', 'cloudflare-ip-blocker'); ?></th>
                                    <th><?php _e('Message', 'cloudflare-ip-blocker'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($logs as $log): ?>
                                    <tr>
                                        <td><?php echo esc_html($log['timestamp']); ?></td>
                                        <td><?php echo esc_html($log['level']); ?></td>
                                        <td><?php echo esc_html($log['message']); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <div id="cfip-token-instructions" style="display: none;">
        <div id="cfip-token-instructions--content">
            <button id="cfip-close">X</button> <!-- Close button -->
            <h3><?php _e('How to Configure Cloudflare Integration', 'cloudflare-ip-blocker'); ?></h3>
            
            <h4><?php _e('Getting Your API Token', 'cloudflare-ip-blocker'); ?></h4>
            <ol>
                <li><?php _e('Log in to your Cloudflare dashboard', 'cloudflare-ip-blocker'); ?></li>
                <li><?php _e('Click on "My Profile" in the top right corner', 'cloudflare-ip-blocker'); ?></li>
                <li><?php _e('Select "API Tokens" from the left menu', 'cloudflare-ip-blocker'); ?></li>
                <li><?php _e('Click "Create Token"', 'cloudflare-ip-blocker'); ?></li>
                <li><?php _e('Use the "Create Custom Token" option', 'cloudflare-ip-blocker'); ?></li>
                <li><?php _e('Set the following permissions:', 'cloudflare-ip-blocker'); ?>
                    <ul>
                        <li><?php _e('Zone - Zone WAF - Edit', 'cloudflare-ip-blocker'); ?></li>
                    </ul>
                </li>
                <li><?php _e('Set Zone Resources to "All Zones"', 'cloudflare-ip-blocker'); ?></li>
                <li><?php _e('Click "Continue to Summary" and then "Create Token"', 'cloudflare-ip-blocker'); ?></li>
                <li><?php _e('Copy the generated token and paste it in the field above', 'cloudflare-ip-blocker'); ?></li>
            </ol>

            <h4><?php _e('Finding Your Zone ID', 'cloudflare-ip-blocker'); ?></h4>
            <ol>
                <li><?php _e('Log in to your Cloudflare dashboard', 'cloudflare-ip-blocker'); ?></li>
                <li><?php _e('Select your domain/website', 'cloudflare-ip-blocker'); ?></li>
                <li><?php _e('Go to the "Overview" tab', 'cloudflare-ip-blocker'); ?></li>
                <li><?php _e('Scroll down to "API" section', 'cloudflare-ip-blocker'); ?></li>
                <li><?php _e('Your Zone ID will be displayed there', 'cloudflare-ip-blocker'); ?></li>
            </ol>

            <h4><?php _e('Setting Up Custom Rules', 'cloudflare-ip-blocker'); ?></h4>
            <ol>
                <li><?php _e('In your Cloudflare dashboard, go to Security > WAF > Custom Rules', 'cloudflare-ip-blocker'); ?></li>
                <li><?php _e('Click "Create Rule"', 'cloudflare-ip-blocker'); ?></li>
                <li><?php _e('Configure the rule:', 'cloudflare-ip-blocker'); ?>
                    <ul>
                        <li><?php _e('Rule name: "Block Malicious IPs"', 'cloudflare-ip-blocker'); ?></li>
                        <li><?php _e('Expression: (ip.src in {})', 'cloudflare-ip-blocker'); ?></li>
                        <li><?php _e('Action: Block', 'cloudflare-ip-blocker'); ?></li>
                    </ul>
                </li>
                <li><?php _e('After creating the rule:', 'cloudflare-ip-blocker'); ?>
                    <ul>
                        <li><?php _e('The Ruleset ID is shown in the URL when editing the ruleset', 'cloudflare-ip-blocker'); ?></li>
                        <li><?php _e('The Rule ID is shown in the rule details or API response', 'cloudflare-ip-blocker'); ?></li>
                    </ul>
                </li>
            </ol>

            <p class="description">
                <?php _e('Note: Make sure to keep these IDs secure and never share them publicly.', 'cloudflare-ip-blocker'); ?>
            </p>
        </div>
    </div>
</div>