<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Pm_Ip_Blocker\Logger;


$is_subscribed = get_option( 'pmip_newsletter_subscribed' ) === '1';
?>
<div class="wrap">
	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

	<?php settings_errors( 'pmip_settings' ); ?>

	<div class="pmip-admin-grid">
		<div class="pmip-main-settings">
			<form method="post" action="">
				<?php wp_nonce_field( 'pmip_settings' ); ?>
				
				<h2><?php esc_attr_e( 'General Settings', 'polar-mass-advanced-ip-blocker' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row">
							<label for="pmip_plugin_status"><?php esc_attr_e( 'Plugin Status', 'polar-mass-advanced-ip-blocker' ); ?></label>
						</th>
						<td>
							<select id="pmip_plugin_status" name="pmip_plugin_status">
								<option value="active" <?php selected( get_option( 'pmip_plugin_status' ), 'active' ); ?>>
									<?php esc_attr_e( 'Active', 'polar-mass-advanced-ip-blocker' ); ?>
								</option>
								<option value="inactive" <?php selected( get_option( 'pmip_plugin_status' ), 'inactive' ); ?>>
									<?php esc_attr_e( 'Inactive', 'polar-mass-advanced-ip-blocker' ); ?>
								</option>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="pmip_api_token"><?php esc_attr_e( 'Cloudflare API Token', 'polar-mass-advanced-ip-blocker' ); ?></label>
						</th>
						<td>
							<input type="password" 
									id="pmip_api_token" 
									name="pmip_api_token" 
									value="<?php echo esc_attr( get_option( 'pmip_api_token' ) ); ?>" 
									class="regular-text">
							<p class="description">
							<?php
							printf(
								/* translators: %s: link to instructions */
								esc_html__( 'Enter your Cloudflare API token. %s', 'polar-mass-advanced-ip-blocker' ),
								'<a href="#" class="pmip-show-token-instructions">' . esc_html__( 'How to get your API token?', 'polar-mass-advanced-ip-blocker' ) . '</a>'
							);
							?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="pmip_zone_id"><?php esc_attr_e( 'Zone ID', 'polar-mass-advanced-ip-blocker' ); ?></label>
						</th>
						<td>
							<input type="text" 
									id="pmip_zone_id" 
									name="pmip_zone_id" 
									value="<?php echo esc_attr( get_option( 'pmip_zone_id' ) ); ?>" 
									class="regular-text">
							<p class="description">
								<?php esc_attr_e( 'Enter your Cloudflare Zone ID. Found in the Overview tab of your domain.', 'polar-mass-advanced-ip-blocker' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="pmip_ruleset_id"><?php esc_attr_e( 'Ruleset ID', 'polar-mass-advanced-ip-blocker' ); ?></label>
						</th>
						<td>
							<input type="text" 
									id="pmip_ruleset_id" 
									name="pmip_ruleset_id" 
									value="<?php echo esc_attr( get_option( 'pmip_ruleset_id' ) ); ?>" 
									class="regular-text">
							<p class="description">
								<?php esc_attr_e( 'Enter your Cloudflare Ruleset ID. Found in the WAF > Custom Rules section.', 'polar-mass-advanced-ip-blocker' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="pmip_rule_id"><?php esc_attr_e( 'Rule ID', 'polar-mass-advanced-ip-blocker' ); ?></label>
						</th>
						<td>
							<input type="text" 
									id="pmip_rule_id" 
									name="pmip_rule_id" 
									value="<?php echo esc_attr( get_option( 'pmip_rule_id' ) ); ?>" 
									class="regular-text">
							<p class="description">
								<?php esc_attr_e( 'Enter your Cloudflare Rule ID. Found in the specific rule settings under WAF > Custom Rules.', 'polar-mass-advanced-ip-blocker' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="pmip_scan_interval"><?php esc_attr_e( 'Scan Interval', 'polar-mass-advanced-ip-blocker' ); ?></label>
						</th>
						<td>
							<select id="pmip_scan_interval" name="pmip_scan_interval">
								<option value="5" <?php selected( get_option( 'pmip_scan_interval' ), 5 ); ?>>
									<?php esc_attr_e( '5 minutes', 'polar-mass-advanced-ip-blocker' ); ?>
								</option>
								<option value="15" <?php selected( get_option( 'pmip_scan_interval' ), 15 ); ?>>
									<?php esc_attr_e( '15 minutes', 'polar-mass-advanced-ip-blocker' ); ?>
								</option>
								<option value="30" <?php selected( get_option( 'pmip_scan_interval' ), 30 ); ?>>
									<?php esc_attr_e( '30 minutes', 'polar-mass-advanced-ip-blocker' ); ?>
								</option>
								<option value="60" <?php selected( get_option( 'pmip_scan_interval' ), 60 ); ?>>
									<?php esc_attr_e( '60 minutes', 'polar-mass-advanced-ip-blocker' ); ?>
								</option>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="pmip_failed_attempts"><?php esc_attr_e( 'Failed Attempts Threshold', 'polar-mass-advanced-ip-blocker' ); ?></label>
						</th>
						<td>
							<input type="number" 
									id="pmip_failed_attempts" 
									name="pmip_failed_attempts" 
									value="<?php echo esc_attr( get_option( 'pmip_failed_attempts', 5 ) ); ?>" 
									min="3" 
									max="10" 
									class="small-text">
							<p class="description">
								<?php esc_attr_e( 'Number of failed login attempts before blocking (3-10)', 'polar-mass-advanced-ip-blocker' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="pmip_block_duration"><?php esc_attr_e( 'Block Duration', 'polar-mass-advanced-ip-blocker' ); ?></label>
						</th>
						<td>
							<select id="pmip_block_duration" name="pmip_block_duration">
								<option value="24h" <?php selected( get_option( 'pmip_block_duration' ), '24h' ); ?>>
									<?php esc_attr_e( '24 Hours', 'polar-mass-advanced-ip-blocker' ); ?>
								</option>
								<option value="7d" <?php selected( get_option( 'pmip_block_duration' ), '7d' ); ?>>
									<?php esc_attr_e( '7 Days', 'polar-mass-advanced-ip-blocker' ); ?>
								</option>
								<option value="permanent" <?php selected( get_option( 'pmip_block_duration' ), 'permanent' ); ?>>
									<?php esc_attr_e( 'Permanent', 'polar-mass-advanced-ip-blocker' ); ?>
								</option>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="pmip_max_logs"><?php esc_attr_e( 'Maximum Log Entries', 'polar-mass-advanced-ip-blocker' ); ?></label>
						</th>
						<td>
							<input type="number" 
									id="pmip_max_logs" 
									name="pmip_max_logs" 
									value="<?php echo esc_attr( get_option( 'pmip_max_logs', 1000 ) ); ?>" 
									min="100" 
									class="small-text">
							<p class="description">
								<?php esc_attr_e( 'Maximum number of log entries to keep', 'polar-mass-advanced-ip-blocker' ); ?>
							</p>
						</td>
					</tr>
				</table>

				<?php submit_button(); ?>
			</form>

			<div class="pmip-support-section">
				<h2><?php esc_attr_e( 'Support Our Development', 'polar-mass-advanced-ip-blocker' ); ?></h2>
				<p><?php esc_attr_e( 'Help us continue improving and maintaining this plugin for the WordPress community.', 'polar-mass-advanced-ip-blocker' ); ?></p>
				
				<div class="pmip-buymeacoffee">
					<a href="https://www.buymeacoffee.com/polarmass" target="_blank">
						<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/buymeacoffee-blue.png' ); ?>" alt="Buy Me A Coffee" style="height: 60px !important; width: 217px !important;">
					</a>
				</div>

				<div class="pmip-contact-info">
					<h3><?php esc_attr_e( 'Get in Touch', 'polar-mass-advanced-ip-blocker' ); ?></h3>
					<p><?php esc_attr_e( 'Have questions or need assistance? We\'re here to help!', 'polar-mass-advanced-ip-blocker' ); ?></p>
					
					<div class="pmip-contact-methods">
						<div class="pmip-contact-method">
							<i class="dashicons dashicons-email"></i>
							<h4><?php esc_attr_e( 'Email Support', 'polar-mass-advanced-ip-blocker' ); ?></h4>
							<p><?php esc_attr_e( 'For technical issues and general inquiries', 'polar-mass-advanced-ip-blocker' ); ?></p>
							<a href="mailto:contact@polarmass.com">contact@polarmass.com</a>
						</div>
						
						<div class="pmip-contact-method">
							<i class="dashicons dashicons-admin-site"></i>
							<h4><?php esc_attr_e( 'Visit Website', 'polar-mass-advanced-ip-blocker' ); ?></h4>
							<p><?php esc_attr_e( 'Documentation and resources', 'polar-mass-advanced-ip-blocker' ); ?></p>
							<a href="https://polarmass.com/" target="_blank">polarmass.com</a>
						</div>
					</div>
				</div>
			</div>

			<div class="pmip-newsletter">
				<?php if ( ! $is_subscribed ) : ?>
					<h3><?php esc_attr_e( 'Stay Updated', 'polar-mass-advanced-ip-blocker' ); ?></h3>
					<p><?php esc_attr_e( 'Subscribe to our newsletter for security tips, updates, and special offers.', 'polar-mass-advanced-ip-blocker' ); ?></p>
					<form class="pmip-newsletter-form">
						<input type="email" placeholder="<?php esc_attr_e( 'Enter your email address', 'polar-mass-advanced-ip-blocker' ); ?>" required>
						<button type="submit"><?php esc_attr_e( 'Subscribe', 'polar-mass-advanced-ip-blocker' ); ?></button>
					</form>
					<div class="pmip-newsletter-message"></div>
				<?php else : ?>
					<div class="pmip-newsletter-success">
						<p><?php esc_attr_e( 'Thank you for subscribing to our newsletter!', 'polar-mass-advanced-ip-blocker' ); ?></p>
						<p><?php esc_attr_e( 'You\'ll receive updates and security tips directly in your inbox.', 'polar-mass-advanced-ip-blocker' ); ?></p>
					</div>
				<?php endif; ?>
			</div>
		</div>

		<div class="pmip-side-panel">
			<div class="pmip-manual-block">
				<h3><?php esc_attr_e( 'Manual IP Management', 'polar-mass-advanced-ip-blocker' ); ?></h3>
				<div class="pmip-manual-block-form">
					<input type="text" id="pmip-ip-input" placeholder="<?php esc_attr_e( 'Enter IP address', 'polar-mass-advanced-ip-blocker' ); ?>">
					<button class="button button-primary" id="pmip-block-ip">
						<?php esc_attr_e( 'Block IP', 'polar-mass-advanced-ip-blocker' ); ?>
					</button>
					<button class="button" id="pmip-unblock-ip">
						<?php esc_attr_e( 'Unblock IP', 'polar-mass-advanced-ip-blocker' ); ?>
					</button>
				</div>
				<div class="pmip-manual-sync">
					<button class="button button-secondary" id="pmip-sync-wordfence">
						<?php esc_attr_e( 'Sync from Wordfence', 'polar-mass-advanced-ip-blocker' ); ?>
					</button>
					<p class="description">
						<?php esc_attr_e( 'Manually sync blocked IPs from Wordfence', 'polar-mass-advanced-ip-blocker' ); ?>
					</p>
				</div>
			</div>

			<div class="pmip-logs">
				<h3><?php esc_attr_e( 'Recent Activity Logs', 'polar-mass-advanced-ip-blocker' ); ?></h3>
				<div class="pmip-log-filters">
					<select id="pmip-log-level">
						<option value=""><?php esc_attr_e( 'All Levels', 'polar-mass-advanced-ip-blocker' ); ?></option>
						<option value="info"><?php esc_attr_e( 'Info', 'polar-mass-advanced-ip-blocker' ); ?></option>
						<option value="warning"><?php esc_attr_e( 'Warning', 'polar-mass-advanced-ip-blocker' ); ?></option>
						<option value="error"><?php esc_attr_e( 'Error', 'polar-mass-advanced-ip-blocker' ); ?></option>
					</select>
					<button class="button" id="pmip-export-logs">
						<?php esc_attr_e( 'Export Logs', 'polar-mass-advanced-ip-blocker' ); ?>
					</button>
				</div>
				<div class="pmip-log-entries">
					<?php
					$logger = new Logger();
					$logs   = $logger->get_logs( 10 );
					if ( empty( $logs ) ) :
						?>
						<p><?php esc_attr_e( 'No logs available', 'polar-mass-advanced-ip-blocker' ); ?></p>
					<?php else : ?>
						<table class="widefat">
							<thead>
								<tr>
									<th><?php esc_attr_e( 'Time', 'polar-mass-advanced-ip-blocker' ); ?></th>
									<th><?php esc_attr_e( 'Level', 'polar-mass-advanced-ip-blocker' ); ?></th>
									<th><?php esc_attr_e( 'Message', 'polar-mass-advanced-ip-blocker' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $logs as $log ) : ?>
									<tr>
										<td><?php echo esc_html( $log['timestamp'] ); ?></td>
										<td><?php echo esc_html( $log['level'] ); ?></td>
										<td><?php echo esc_html( $log['message'] ); ?></td>
									</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
					<?php endif; ?>
				</div>
			</div>
		</div>
	</div>

	<div id="pmip-token-instructions" style="display: none;">
		<div id="pmip-token-instructions--content">
			<button id="pmip-close">X</button>
			<h3><?php esc_attr_e( 'How to Configure Cloudflare Integration', 'polar-mass-advanced-ip-blocker' ); ?></h3>
			
			<h4><?php esc_attr_e( 'Getting Your API Token', 'polar-mass-advanced-ip-blocker' ); ?></h4>
			<ol>
				<li><?php esc_attr_e( 'Log in to your Cloudflare dashboard', 'polar-mass-advanced-ip-blocker' ); ?></li>
				<li><?php esc_attr_e( 'Click on "My Profile" in the top right corner', 'polar-mass-advanced-ip-blocker' ); ?></li>
				<li><?php esc_attr_e( 'Select "API Tokens" from the left menu', 'polar-mass-advanced-ip-blocker' ); ?></li>
				<li><?php esc_attr_e( 'Click "Create Token"', 'polar-mass-advanced-ip-blocker' ); ?></li>
				<li><?php esc_attr_e( 'Use the "Create Custom Token" option', 'polar-mass-advanced-ip-blocker' ); ?></li>
				<li><?php esc_attr_e( 'Set the following permissions:', 'polar-mass-advanced-ip-blocker' ); ?>
					<ul>
						<li><?php esc_attr_e( 'Zone - Zone WAF - Edit', 'polar-mass-advanced-ip-blocker' ); ?></li>
					</ul>
				</li>
				<li><?php esc_attr_e( 'Set Zone Resources to "All Zones"', 'polar-mass-advanced-ip-blocker' ); ?></li>
				<li><?php esc_attr_e( 'Click "Continue to Summary" and then "Create Token"', 'polar-mass-advanced-ip-blocker' ); ?></li>
				<li><?php esc_attr_e( 'Copy the generated token and paste it in the field above', 'polar-mass-advanced-ip-blocker' ); ?></li>
			</ol>

			<h4><?php esc_attr_e( 'Finding Your Zone ID', 'polar-mass-advanced-ip-blocker' ); ?></h4>
			<ol>
				<li><?php esc_attr_e( 'Log in to your Cloudflare dashboard', 'polar-mass-advanced-ip-blocker' ); ?></li>
				<li><?php esc_attr_e( 'Select your domain/website', 'polar-mass-advanced-ip-blocker' ); ?></li>
				<li><?php esc_attr_e( 'Go to the "Overview" tab', 'polar-mass-advanced-ip-blocker' ); ?></li>
				<li><?php esc_attr_e( 'Scroll down to "API" section', 'polar-mass-advanced-ip-blocker' ); ?></li>
				<li><?php esc_attr_e( 'Your Zone ID will be displayed there', 'polar-mass-advanced-ip-blocker' ); ?></li>
			</ol>

			<h4><?php esc_attr_e( 'Setting Up Custom Rules', 'polar-mass-advanced-ip-blocker' ); ?></h4>
			<ol>
				<li><?php esc_attr_e( 'In your Cloudflare dashboard, go to Security > WAF > Custom Rules', 'polar-mass-advanced-ip-blocker' ); ?></li>
				<li><?php esc_attr_e( 'Click "Create Rule"', 'polar-mass-advanced-ip-blocker' ); ?></li>
				<li><?php esc_attr_e( 'Configure the rule:', 'polar-mass-advanced-ip-blocker' ); ?>
					<ul>
						<li><?php esc_attr_e( 'Rule name: "Block Malicious IPs"', 'polar-mass-advanced-ip-blocker' ); ?></li>
						<li><?php esc_attr_e( 'Expression: (ip.src in {})', 'polar-mass-advanced-ip-blocker' ); ?></li>
						<li><?php esc_attr_e( 'Action: Block', 'polar-mass-advanced-ip-blocker' ); ?></li>
					</ul>
				</li>
				<li><?php esc_attr_e( 'After creating the rule:', 'polar-mass-advanced-ip-blocker' ); ?>
					<ul>
						<li><?php esc_attr_e( 'The Ruleset ID is shown in the URL when editing the ruleset', 'polar-mass-advanced-ip-blocker' ); ?></li>
						<li><?php esc_attr_e( 'The Rule ID is shown in the rule details or API response', 'polar-mass-advanced-ip-blocker' ); ?></li>
					</ul>
				</li>
			</ol>

			<p class="description">
				<?php esc_attr_e( 'Note: Make sure to keep these IDs secure and never share them publicly.', 'polar-mass-advanced-ip-blocker' ); ?>
			</p>
		</div>
	</div>
</div>