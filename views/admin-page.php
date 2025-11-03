<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Pm_Ip_Blocker\Logger;


$is_subscribed  = get_option( 'pmip_newsletter_subscribed' ) === '1';
$server_ip      = isset( $server_ip ) ? $server_ip : false;
$server_ip_type = isset( $server_ip_type ) ? $server_ip_type : false;
?>
<div class="wrap">
	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

	<?php settings_errors( 'pmip_settings' ); ?>

	<div class="pmip-admin-grid">
		<div class="pmip-main-settings">
			<div class="pmip-main-settings-section" style="padding: 0; border: unset;">
				<?php
				$is_configured       = ! empty( get_option( 'pmip_api_token' ) ) && ! empty( get_option( 'pmip_zone_id' ) ) && ! empty( get_option( 'pmip_ruleset_id' ) ) && ! empty( get_option( 'pmip_rule_id' ) );
				$auto_connected      = get_option( 'pmip_auto_connected', false );
				$master_token_stored = get_option( 'pmip_master_token', '' );
				$scoped_token_stored = get_option( 'pmip_api_token', '' );

				$zone_id             = get_option( 'pmip_zone_id', '' );
				$ruleset_id          = get_option( 'pmip_ruleset_id', '' );
				$rule_id             = get_option( 'pmip_rule_id', '' );
				$zone_name           = '';
				$rule_details        = false;
				$connection_verified = false;

				if ( $is_configured && ! empty( $zone_id ) && ! empty( $ruleset_id ) && ! empty( $rule_id ) && ! empty( $scoped_token_stored ) ) {
					$token_manager = new \Pm_Ip_Blocker\Cloudflare_Token_Manager( new \Pm_Ip_Blocker\Logger() );

					if ( ! empty( $zone_id ) && ! empty( $scoped_token_stored ) ) {
						$zone_name = $token_manager->get_zone_name( $zone_id, $scoped_token_stored );
					}

					if ( ! empty( $ruleset_id ) && ! empty( $rule_id ) ) {
						$rule_details = $token_manager->get_rule_details( $zone_id, $ruleset_id, $rule_id, $scoped_token_stored );
					}

					$connection_verified = ( false !== $rule_details );

					if ( ! $connection_verified ) {
						$zones_data          = $token_manager->get_zones_list( $scoped_token_stored );
						$connection_verified = ! empty( $zones_data['zones'] );
					}
				}
				?>

				<?php if ( $is_configured ) : ?>
					<?php if ( ! $connection_verified ) : ?>
						<div class="notice notice-warning" style="margin-bottom: 20px; padding: 15px;">
							<h3 style="margin-top: 0; margin-bottom: 10px;">
								<?php esc_attr_e( 'Connection Warning', 'polar-mass-advanced-ip-blocker' ); ?>
							</h3>
							<p style="margin-bottom: 0;">
								<?php esc_attr_e( 'Unable to verify connection to Cloudflare. This may be a temporary network issue. If problems persist, please reconnect below.', 'polar-mass-advanced-ip-blocker' ); ?>
							</p>
						</div>
					<?php endif; ?>
					<div class="notice notice-success" style="margin-bottom: 20px; padding: 15px;">
						<h3 style="margin-top: 0; margin-bottom: 15px;">
							<?php esc_attr_e( 'Connected!', 'polar-mass-advanced-ip-blocker' ); ?>
						</h3>
						<p style="margin-bottom: 15px;">
							<?php esc_attr_e( 'Your Cloudflare connection was configured automatically.', 'polar-mass-advanced-ip-blocker' ); ?>
						</p>
						
						<div style="background: #f0f0f1; border: 1px solid #c3c4c7; border-radius: 4px; padding: 15px; margin-top: 15px;">
							<h4 style="margin-top: 0; margin-bottom: 12px; font-size: 14px;">
								<?php esc_attr_e( 'Connection Details:', 'polar-mass-advanced-ip-blocker' ); ?>
							</h4>
							
							<table style="width: 100%; border-collapse: collapse;">
								<tr style="border-bottom: 1px solid #dcdcde;">
									<td style="padding: 8px 0; font-weight: 600; width: 150px;">
										<?php esc_attr_e( 'API Token:', 'polar-mass-advanced-ip-blocker' ); ?>
									</td>
									<td style="padding: 8px 0;">
										<?php if ( ! empty( $scoped_token_stored ) ) : ?>
											<code style="font-size: 12px; padding: 4px 8px; background: #fff; border: 1px solid #ddd; border-radius: 3px;">
												<?php echo esc_html( substr( $scoped_token_stored, 0, 20 ) . '...' . substr( $scoped_token_stored, -10 ) ); ?>
											</code>
										<?php else : ?>
											<span style="color: #d63638;"><?php esc_attr_e( 'Not set', 'polar-mass-advanced-ip-blocker' ); ?></span>
										<?php endif; ?>
									</td>
								</tr>
								<?php if ( ! empty( $zone_id ) ) : ?>
									<tr style="border-bottom: 1px solid #dcdcde;">
										<td style="padding: 8px 0; font-weight: 600;">
											<?php esc_attr_e( 'Zone:', 'polar-mass-advanced-ip-blocker' ); ?>
										</td>
										<td style="padding: 8px 0;">
											<?php if ( ! empty( $zone_name ) ) : ?>
												<strong><?php echo esc_html( $zone_name ); ?></strong>
												<span style="color: #646970; font-size: 12px;">(<?php echo esc_html( $zone_id ); ?>)</span>
											<?php else : ?>
												<code style="font-size: 12px; padding: 4px 8px; background: #fff; border: 1px solid #ddd; border-radius: 3px;">
													<?php echo esc_html( $zone_id ); ?>
												</code>
											<?php endif; ?>
										</td>
									</tr>
								<?php endif; ?>
								<?php if ( ! empty( $ruleset_id ) ) : ?>
									<tr style="border-bottom: 1px solid #dcdcde;">
										<td style="padding: 8px 0; font-weight: 600;">
											<?php esc_attr_e( 'Ruleset ID:', 'polar-mass-advanced-ip-blocker' ); ?>
										</td>
										<td style="padding: 8px 0;">
											<code style="font-size: 12px; padding: 4px 8px; background: #fff; border: 1px solid #ddd; border-radius: 3px;">
												<?php echo esc_html( $ruleset_id ); ?>
											</code>
										</td>
									</tr>
								<?php endif; ?>
								<?php if ( ! empty( $rule_id ) ) : ?>
									<tr style="border-bottom: 1px solid #dcdcde;">
										<td style="padding: 8px 0; font-weight: 600;">
											<?php esc_attr_e( 'Rule:', 'polar-mass-advanced-ip-blocker' ); ?>
										</td>
										<td style="padding: 8px 0;">
											<?php if ( $rule_details && ! empty( $rule_details['description'] ) ) : ?>
												<strong><?php echo esc_html( $rule_details['description'] ); ?></strong>
												<span style="color: #646970; font-size: 12px; margin-left: 8px;">
													(<?php echo esc_html( $rule_id ); ?>)
												</span>
												<?php if ( isset( $rule_details['enabled'] ) ) : ?>
													<span style="margin-left: 8px; padding: 2px 8px; background: <?php echo $rule_details['enabled'] ? '#d4edda' : '#f8d7da'; ?>; color: <?php echo $rule_details['enabled'] ? '#155724' : '#721c24'; ?>; border-radius: 3px; font-size: 11px;">
														<?php echo $rule_details['enabled'] ? esc_attr__( 'Enabled', 'polar-mass-advanced-ip-blocker' ) : esc_attr__( 'Disabled', 'polar-mass-advanced-ip-blocker' ); ?>
													</span>
												<?php endif; ?>
											<?php else : ?>
												<strong><?php esc_attr_e( 'MaliciousIPs - Polar Mass Advanced IP Blocker', 'polar-mass-advanced-ip-blocker' ); ?></strong>
												<span style="color: #646970; font-size: 12px; margin-left: 8px;">
													(<?php echo esc_html( $rule_id ); ?>)
												</span>
											<?php endif; ?>
										</td>
									</tr>
								<?php endif; ?>
							</table>
						</div>
					</div>
				<?php endif; ?>

				<!-- Tabbed Interface -->
				<div class="pmip-connect-tabs" style="background: #fff; border: 1px solid #ccd0d4; padding: 0; margin-bottom: 20px; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
					<!-- Tab Headers -->
					<div class="pmip-tab-headers" style="border-bottom: 1px solid #ccd0d4; display: flex; margin: 0;">
						<button type="button" class="pmip-tab-header active" data-tab="auto-connect" style="flex: 1; padding: 15px 20px; background: none; border: none; border-bottom: 3px solid #2271b1; cursor: pointer; font-size: 14px; font-weight: 600; color: #2271b1;">
							<?php esc_attr_e( 'Auto Connect', 'polar-mass-advanced-ip-blocker' ); ?>
							<span style="font-size: 11px; font-weight: normal; color: #646970; margin-left: 5px;">(Recommended)</span>
						</button>
						<button type="button" class="pmip-tab-header" data-tab="manual-connect" style="flex: 1; padding: 15px 20px; background: none; border: none; border-bottom: 3px solid transparent; cursor: pointer; font-size: 14px; font-weight: 600; color: #646970;">
							<?php esc_attr_e( 'Manual Connect', 'polar-mass-advanced-ip-blocker' ); ?>
						</button>
					</div>

					<!-- Auto Connect Tab -->
					<div id="pmip-tab-auto-connect" class="pmip-tab-content" style="padding: 20px; display: block;">
						<h3 style="margin-top: 0;"><?php esc_attr_e( 'Auto Connect to Cloudflare', 'polar-mass-advanced-ip-blocker' ); ?></h3>
						<p><?php esc_attr_e( 'Automatically configure your Cloudflare connection. Just enter your master token and select a zone!', 'polar-mass-advanced-ip-blocker' ); ?></p>
						
						<?php if ( ! empty( $scoped_token_stored ) ) : ?>
							<div style="background: #d1ecf1; border-left: 4px solid #0c5460; padding: 12px; margin: 15px 0;">
								<p style="margin: 0;">
									<strong><?php esc_attr_e( 'Generated API Token:', 'polar-mass-advanced-ip-blocker' ); ?></strong>
									<code style="font-size: 12px; padding: 5px 10px; background: #fff; border: 1px solid #ddd; display: inline-block; margin-left: 10px;"><?php echo esc_html( substr( $scoped_token_stored, 0, 20 ) . '...' ); ?></code>
								</p>
							</div>
						<?php endif; ?>

						<div class="pmip-auto-connect-form" style="margin-top: 15px;">
							<p>
								<strong><?php esc_attr_e( 'Step 1:', 'polar-mass-advanced-ip-blocker' ); ?></strong>
								<?php esc_attr_e( 'Create a master token in Cloudflare with "Create Additional Tokens" template.', 'polar-mass-advanced-ip-blocker' ); ?>
								<a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank"><?php esc_attr_e( 'Go to Cloudflare Dashboard', 'polar-mass-advanced-ip-blocker' ); ?></a>
							</p>
							
							<p>
								<label for="pmip_master_token" style="display: block; margin-bottom: 5px;">
									<strong><?php esc_attr_e( 'Master Token:', 'polar-mass-advanced-ip-blocker' ); ?></strong>
								</label>
								<input type="password" 
										id="pmip_master_token" 
										value="<?php echo ! empty( $master_token_stored ) ? esc_attr( $master_token_stored ) : ''; ?>"
										placeholder="<?php esc_attr_e( 'Enter your master token', 'polar-mass-advanced-ip-blocker' ); ?>"
										class="regular-text" 
										style="width: 100%; max-width: 500px;">
								<span class="description"><?php esc_attr_e( 'Token with "Create Additional Tokens" permission', 'polar-mass-advanced-ip-blocker' ); ?></span>
							</p>

							<?php if ( $server_ip ) : ?>
								<p style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin: 15px 0;">
									<strong><?php esc_attr_e( 'Your Server IP:', 'polar-mass-advanced-ip-blocker' ); ?></strong>
									<code style="font-size: 14px; padding: 5px 10px; background: #fff; border: 1px solid #ddd; display: inline-block; margin-left: 10px;"><?php echo esc_html( $server_ip ); ?></code>
									<?php if ( 'private' === $server_ip_type ) : ?>
										<span style="color: #d63638; margin-left: 10px;">
											<?php esc_attr_e( '(Private IP detected)', 'polar-mass-advanced-ip-blocker' ); ?>
										</span>
									<?php endif; ?>
									<br>
									<span style="font-size: 12px; color: #646970;"><?php esc_attr_e( 'Use this IP in "Client IP Address Filtering" when creating your master token for extra security.', 'polar-mass-advanced-ip-blocker' ); ?></span>
								</p>
							<?php endif; ?>
							
							<p>
								<button type="button" 
										id="pmip-auto-connect-btn" 
										class="button button-primary button-large"
										style="margin-top: 10px;">
									<?php esc_attr_e( 'Connect to Cloudflare', 'polar-mass-advanced-ip-blocker' ); ?>
								</button>
								<span id="pmip-auto-connect-status" style="margin-left: 10px;"></span>
							</p>
							
							<div id="pmip-auto-connect-message" style="margin-top: 15px;"></div>

							<!-- Zone Selection -->
							<div id="pmip-zone-selection" style="display: none; margin-top: 20px; padding: 15px; background: #f9f9f9; border: 1px solid #ddd; border-radius: 4px;">
								<h4 style="margin-top: 0;"><?php esc_attr_e( 'Step 2: Select Zone', 'polar-mass-advanced-ip-blocker' ); ?></h4>
								<p>
									<label for="pmip_zone_select" style="display: block; margin-bottom: 5px;">
										<strong><?php esc_attr_e( 'Select Zone:', 'polar-mass-advanced-ip-blocker' ); ?></strong>
									</label>
									<select id="pmip_zone_select" 
											class="regular-text" 
											style="width: 100%; max-width: 500px;">
										<option value=""><?php esc_attr_e( '-- Please select a zone --', 'polar-mass-advanced-ip-blocker' ); ?></option>
									</select>
								</p>
								<p>
									<button type="button" 
											id="pmip-select-zone-btn" 
											class="button button-primary"
											style="margin-top: 10px;">
										<?php esc_attr_e( 'Save & Create Rule', 'polar-mass-advanced-ip-blocker' ); ?>
									</button>
									<span id="pmip-zone-selection-status" style="margin-left: 10px;"></span>
								</p>
								<div id="pmip-zone-selection-message" style="margin-top: 15px;"></div>
							</div>
						</div>
					</div>

					<!-- Manual Connect Tab -->
					<div id="pmip-tab-manual-connect" class="pmip-tab-content" style="padding: 20px; display: none;">
						<h3 style="margin-top: 0;"><?php esc_attr_e( 'Manual Configuration', 'polar-mass-advanced-ip-blocker' ); ?></h3>
						<p style="color: #d63638;">
							<strong><?php esc_attr_e( 'Note:', 'polar-mass-advanced-ip-blocker' ); ?></strong>
							<?php esc_attr_e( 'Auto Connect is recommended for easier setup. Only use Manual Connect if you need custom configuration.', 'polar-mass-advanced-ip-blocker' ); ?>
						</p>
						
						<form method="post" action="">
							<?php wp_nonce_field( 'pmip_settings' ); ?>
							<table class="form-table" style="margin-top: 20px;">
							<tr>
								<th scope="row">
									<label for="pmip_api_token_manual"><?php esc_attr_e( 'Cloudflare API Token', 'polar-mass-advanced-ip-blocker' ); ?></label>
								</th>
								<td>
									<input type="password" 
											id="pmip_api_token_manual" 
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
									<label for="pmip_zone_id_manual"><?php esc_attr_e( 'Zone ID', 'polar-mass-advanced-ip-blocker' ); ?></label>
								</th>
								<td>
									<input type="text" 
											id="pmip_zone_id_manual" 
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
									<label for="pmip_ruleset_id_manual"><?php esc_attr_e( 'Ruleset ID', 'polar-mass-advanced-ip-blocker' ); ?></label>
								</th>
								<td>
									<input type="text" 
											id="pmip_ruleset_id_manual" 
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
									<label for="pmip_rule_id_manual"><?php esc_attr_e( 'Rule ID', 'polar-mass-advanced-ip-blocker' ); ?></label>
								</th>
								<td>
									<input type="text" 
											id="pmip_rule_id_manual" 
											name="pmip_rule_id" 
											value="<?php echo esc_attr( get_option( 'pmip_rule_id' ) ); ?>" 
											class="regular-text">
									<p class="description">
										<?php esc_attr_e( 'Enter your Cloudflare Rule ID. Found in the specific rule settings under WAF > Custom Rules.', 'polar-mass-advanced-ip-blocker' ); ?>
									</p>
								</td>
							</tr>
						</table>
						<p>
							<?php submit_button( __( 'Save Manual Configuration', 'polar-mass-advanced-ip-blocker' ), 'primary', 'pmip_save_manual_config', false ); ?>
						</p>
						</form>
					</div>
				</div>
			</div>

			<div class="pmip-main-settings-section">
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
			</div>

			<div class="pmip-main-settings-section" style="padding: 0; background: unset; border: unset;">
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
				<li>
					<?php esc_attr_e( 'Log in to your Cloudflare dashboard', 'polar-mass-advanced-ip-blocker' ); ?>
				</li>
				<li>
					<?php esc_attr_e( 'Click on "My Profile" in the top right corner', 'polar-mass-advanced-ip-blocker' ); ?>
				</li>
				<li>
					<?php esc_attr_e( 'Select "API Tokens" from the left menu', 'polar-mass-advanced-ip-blocker' ); ?>
					<br>
					<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-api-tokens.png' ); ?>" class="pmip-lightbox" target="_blank">
						<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-api-tokens.png' ); ?>" alt="Cloudflare API Tokens" style="max-width:100%;margin-top:8px;cursor:pointer;">
					</a>
				</li>
				<li>
					<?php esc_attr_e( 'Click "Create Token"', 'polar-mass-advanced-ip-blocker' ); ?>
				</li>
				<li>
					<?php esc_attr_e( 'Use the "Create Custom Token" option', 'polar-mass-advanced-ip-blocker' ); ?>
					<br>
					<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-create-token.png' ); ?>" class="pmip-lightbox" target="_blank">
						<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-create-token.png' ); ?>" alt="Cloudflare Create Token" style="max-width:100%;margin-top:8px;cursor:pointer;">
					</a>
				</li>
				<li><?php esc_attr_e( 'Set the following permissions:', 'polar-mass-advanced-ip-blocker' ); ?>
					<ul>
						<li><?php esc_attr_e( 'Zone - Zone WAF - Edit', 'polar-mass-advanced-ip-blocker' ); ?></li>
					</ul>
				</li>
				<li>
					<?php esc_attr_e( 'Set Zone Resources to "All Zones"', 'polar-mass-advanced-ip-blocker' ); ?>
					<br>
					<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-set-zone-resources.png' ); ?>" class="pmip-lightbox" target="_blank">
						<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-set-zone-resources.png' ); ?>" alt="Cloudflare Set Zone Resources" style="max-width:100%;margin-top:8px;cursor:pointer;">
					</a>
				</li>
				<li><?php esc_attr_e( 'Click "Continue to Summary" and then "Create Token"', 'polar-mass-advanced-ip-blocker' ); ?></li>
				<li>
					<?php esc_attr_e( 'Copy the generated token and paste it in the field above', 'polar-mass-advanced-ip-blocker' ); ?>
					<br>
					<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-copy-token.png' ); ?>" class="pmip-lightbox" target="_blank">
						<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-copy-token.png' ); ?>" alt="Cloudflare Copy Token" style="max-width:100%;margin-top:8px;cursor:pointer;">
					</a>
				</li>
			</ol>

			<h4><?php esc_attr_e( 'Finding Your Zone ID', 'polar-mass-advanced-ip-blocker' ); ?></h4>
			<ol>
				<li>
					<?php esc_attr_e( 'Log in to your Cloudflare dashboard', 'polar-mass-advanced-ip-blocker' ); ?>
				</li>
				<li>
					<?php esc_attr_e( 'Select your domain/website', 'polar-mass-advanced-ip-blocker' ); ?>
					<br>
					<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-select-domain.png' ); ?>" class="pmip-lightbox" target="_blank">
						<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-select-domain.png' ); ?>" alt="Cloudflare Select Domain" style="max-width:100%;margin-top:8px;cursor:pointer;">
					</a>
				</li>
				<li>
					<?php esc_attr_e( 'Go to the "Overview" tab and scroll down to the "API" section', 'polar-mass-advanced-ip-blocker' ); ?>
					<br>
					<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-api-section.png' ); ?>" class="pmip-lightbox" target="_blank">
						<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-api-section.png' ); ?>" alt="Cloudflare API Section" style="max-width:100%;margin-top:8px;cursor:pointer;">
					</a>
				</li>
				<li><?php esc_attr_e( 'Your Zone ID will be displayed there', 'polar-mass-advanced-ip-blocker' ); ?></li>
			</ol>

			<h4><?php esc_attr_e( 'Setting Up Custom Rules', 'polar-mass-advanced-ip-blocker' ); ?></h4>
			<div class="pmip-tabs">
				<button class="pmip-tab active" data-tab="old">Old Security Page</button>
				<button class="pmip-tab" data-tab="new">New Security Page</button>
			</div>
			<div class="pmip-tab-content pmip-tab-content-old active">
				<ol>
					<li>
						<?php esc_attr_e( 'In your Cloudflare dashboard, go to Security > WAF > Custom Rules', 'polar-mass-advanced-ip-blocker' ); ?>
						<br>
						<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-waf-custom-rules.png' ); ?>" class="pmip-lightbox" target="_blank">
							<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-waf-custom-rules.png' ); ?>" alt="Cloudflare WAF Custom Rules" style="max-width:100%;margin-top:8px;cursor:pointer;">
						</a>
					</li>
					<li><?php esc_attr_e( 'Click "Create Rule"', 'polar-mass-advanced-ip-blocker' ); ?></li>
					<li><?php esc_attr_e( 'Configure the rule:', 'polar-mass-advanced-ip-blocker' ); ?>
						<ul>
							<li><?php esc_attr_e( 'Rule name: "Block Malicious IPs"', 'polar-mass-advanced-ip-blocker' ); ?></li>
							<li>
								<?php esc_attr_e( 'Click on Edit Expression, then paste the following expression: (ip.src in {})', 'polar-mass-advanced-ip-blocker' ); ?>
								<br>
								<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-edit-expression.png' ); ?>" class="pmip-lightbox" target="_blank">
									<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-edit-expression.png' ); ?>" alt="Cloudflare Edit Expression" style="max-width:100%;margin-top:8px;cursor:pointer;">
								</a>
							</li>
							<li><?php esc_attr_e( 'Action: Block', 'polar-mass-advanced-ip-blocker' ); ?></li>
						</ul>
					</li>
					<li><?php esc_attr_e( 'Click on the "Deploy" button', 'polar-mass-advanced-ip-blocker' ); ?></li>
					<li><?php esc_attr_e( 'After creating the rule:', 'polar-mass-advanced-ip-blocker' ); ?>
						<ul>
							<li><?php esc_attr_e( 'The Ruleset ID and Rule ID are shown in the URL when editing the ruleset', 'polar-mass-advanced-ip-blocker' ); ?></li>
						</ul>
						<pre style="background:#f6f8fa;padding:8px 12px;border-radius:4px;margin-top:8px;overflow-x:auto;font-size:13px;">
https://api.cloudflare.com/client/v4/zones/[ZONE_ID]/rulesets/[RULESET_ID]/rules/[RULE_ID]
</pre>
<br>
<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-ruleset-id.png' ); ?>" class="pmip-lightbox" target="_blank">
	<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-ruleset-id.png' ); ?>" alt="Cloudflare Ruleset ID" style="max-width:100%;margin-top:8px;cursor:pointer;">
</a>
					</li>
				</ol>
			</div>
			<div class="pmip-tab-content pmip-tab-content-new">
				<ol>
					<li>
						<?php esc_attr_e( 'In the new Cloudflare dashboard, go to Security > Security Rules', 'polar-mass-advanced-ip-blocker' ); ?>
						<br>
						<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-create-rule-new.png' ); ?>" class="pmip-lightbox" target="_blank">
							<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-create-rule-new.png' ); ?>" alt="Cloudflare Create Rule" style="max-width:100%;margin-top:8px;cursor:pointer;">
						</a>
					</li>
					<li>
						<?php esc_attr_e( 'Click "Create Rule" and choose "Custom Rule"', 'polar-mass-advanced-ip-blocker' ); ?>
					</li>
					<li><?php esc_attr_e( 'Configure the rule:', 'polar-mass-advanced-ip-blocker' ); ?>
						<ul>
							<li><?php esc_attr_e( 'Rule name: "Block Malicious IPs"', 'polar-mass-advanced-ip-blocker' ); ?></li>
							<li>
								<?php esc_attr_e( 'Click on Edit Expression, then paste the following expression: (ip.src in {})', 'polar-mass-advanced-ip-blocker' ); ?>
								<br>
								<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-edit-expression-new.png' ); ?>" class="pmip-lightbox" target="_blank">
									<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-edit-expression-new.png' ); ?>" alt="Cloudflare Edit Expression" style="max-width:100%;margin-top:8px;cursor:pointer;">
								</a>
							</li>
							<li><?php esc_attr_e( 'Action: Block', 'polar-mass-advanced-ip-blocker' ); ?></li>
						</ul>
					</li>
					<li><?php esc_attr_e( 'Click on the "Deploy" button', 'polar-mass-advanced-ip-blocker' ); ?></li>
					<li><?php esc_attr_e( 'After creating the rule:', 'polar-mass-advanced-ip-blocker' ); ?>
						<ul>
							<li><?php esc_attr_e( 'The Ruleset ID and Rule ID are shown in the URL when editing the ruleset', 'polar-mass-advanced-ip-blocker' ); ?></li>
						</ul>
						<pre style="background:#f6f8fa;padding:8px 12px;border-radius:4px;margin-top:8px;overflow-x:auto;font-size:13px;">
https://api.cloudflare.com/client/v4/zones/[ZONE_ID]/rulesets/[RULESET_ID]/rules/[RULE_ID]
</pre>
<br>
<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-ruleset-id-new.png' ); ?>" class="pmip-lightbox" target="_blank">
	<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-ruleset-id-new.png' ); ?>" alt="Cloudflare Ruleset ID" style="max-width:100%;margin-top:8px;cursor:pointer;">
</a>
					</li>
					<li><?php esc_attr_e( 'After creating the rule, note the new location for Ruleset ID and Rule ID', 'polar-mass-advanced-ip-blocker' ); ?></li>
				</ol>
			</div>

			<p class="description">
				<?php esc_attr_e( 'Note: Make sure to keep these IDs secure and never share them publicly.', 'polar-mass-advanced-ip-blocker' ); ?>
			</p>
		</div>
	</div>
</div>
