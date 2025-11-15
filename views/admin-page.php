<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Pm_Ip_Blocker\Logger;

$is_subscribed  = get_option( 'pmip_newsletter_subscribed' ) === '1';
$server_ip      = isset( $server_ip ) ? $server_ip : false;
$server_ip_type = isset( $server_ip_type ) ? $server_ip_type : false;

// Determine connection state
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
$connection_state    = 'not_connected'; // not_connected, connected_verified, connected_unverified

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

	$connection_state = $connection_verified ? 'connected_verified' : 'connected_unverified';
}
?>
<div class="wrap">
	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

	<?php settings_errors( 'pmip_settings' ); ?>

	<div class="pmip-admin-grid">
		<div class="pmip-main-settings">
			<!-- Cloudflare Setup & Status Card -->
			<div class="pmip-cloudflare-setup-card pmip-main-settings-section">
				<h2><?php esc_html_e( 'Cloudflare Connection', 'polar-mass-advanced-ip-blocker' ); ?></h2>

				<!-- Connection Status Banner -->
				<div class="pmip-connection-status-banner">
					<?php if ( 'not_connected' === $connection_state ) : ?>
						<div class="pmip-status-badge pmip-status-not-connected">
							<span class="dashicons dashicons-warning"></span>
							<?php esc_html_e( 'Not Connected', 'polar-mass-advanced-ip-blocker' ); ?>
						</div>
						<p class="pmip-status-description">
							<?php esc_html_e( 'Not connected to Cloudflare. Connect now to enable IP blocking.', 'polar-mass-advanced-ip-blocker' ); ?>
						</p>
					<?php elseif ( 'connected_verified' === $connection_state ) : ?>
						<div class="pmip-status-badge pmip-status-connected">
							<span class="dashicons dashicons-yes-alt"></span>
							<?php esc_html_e( 'Connected', 'polar-mass-advanced-ip-blocker' ); ?>
						</div>
						<div class="pmip-connection-summary">
							<?php if ( ! empty( $zone_name ) ) : ?>
								<p><strong><?php esc_html_e( 'Zone:', 'polar-mass-advanced-ip-blocker' ); ?></strong> <?php echo esc_html( $zone_name ); ?></p>
							<?php endif; ?>
							<?php if ( $rule_details && isset( $rule_details['enabled'] ) ) : ?>
								<p>
									<strong><?php esc_html_e( 'Rule Status:', 'polar-mass-advanced-ip-blocker' ); ?></strong>
									<span class="pmip-rule-status-badge pmip-rule-<?php echo $rule_details['enabled'] ? 'enabled' : 'disabled'; ?>">
										<?php echo $rule_details['enabled'] ? esc_html__( 'Enabled', 'polar-mass-advanced-ip-blocker' ) : esc_html__( 'Disabled', 'polar-mass-advanced-ip-blocker' ); ?>
									</span>
								</p>
							<?php endif; ?>
						</div>
						<p>
							<button type="button" id="pmip-test-connection" class="button button-secondary">
								<?php esc_html_e( 'Test Connection', 'polar-mass-advanced-ip-blocker' ); ?>
							</button>
							<button type="button" id="pmip-reset-cloudflare" class="button button-link-delete" style="margin-left: 10px;">
								<?php esc_html_e( 'Reset Settings', 'polar-mass-advanced-ip-blocker' ); ?>
							</button>
							<a href="#" id="pmip-view-details-toggle" class="pmip-toggle-link">
								<?php esc_html_e( 'View Details', 'polar-mass-advanced-ip-blocker' ); ?>
							</a>
						</p>
					<?php else : // connected_unverified ?>
						<div class="pmip-status-badge pmip-status-warning">
							<span class="dashicons dashicons-warning"></span>
							<?php esc_html_e( 'Warning', 'polar-mass-advanced-ip-blocker' ); ?>
						</div>
						<div class="notice notice-warning inline" style="margin: 10px 0;">
							<p>
								<?php esc_html_e( 'Connection could not be verified. This may be a temporary network issue. Please reconnect or check your configuration.', 'polar-mass-advanced-ip-blocker' ); ?>
							</p>
						</div>
						<p>
							<button type="button" id="pmip-reconnect-btn" class="button button-primary">
								<?php esc_html_e( 'Reconnect', 'polar-mass-advanced-ip-blocker' ); ?>
							</button>
							<button type="button" id="pmip-reset-cloudflare" class="button button-link-delete" style="margin-left: 10px;">
								<?php esc_html_e( 'Reset Settings', 'polar-mass-advanced-ip-blocker' ); ?>
							</button>
							<a href="#" id="pmip-view-details-toggle" class="pmip-toggle-link">
								<?php esc_html_e( 'View Details', 'polar-mass-advanced-ip-blocker' ); ?>
							</a>
						</p>
					<?php endif; ?>
				</div>

				<!-- Connection Details (Expandable) -->
				<?php if ( 'not_connected' !== $connection_state ) : ?>
					<div id="pmip-connection-details" class="pmip-connection-details" style="display: none;">
						<div class="pmip-connection-details-box">
							<h4><?php esc_html_e( 'Connection Details', 'polar-mass-advanced-ip-blocker' ); ?></h4>
							<table class="pmip-details-table">
								<tr>
									<td><strong><?php esc_html_e( 'API Token:', 'polar-mass-advanced-ip-blocker' ); ?></strong></td>
									<td>
										<?php if ( ! empty( $scoped_token_stored ) ) : ?>
											<code><?php echo esc_html( substr( $scoped_token_stored, 0, 8 ) . '...' . substr( $scoped_token_stored, -4 ) ); ?></code>
										<?php else : ?>
											<span class="pmip-error-text"><?php esc_html_e( 'Not set', 'polar-mass-advanced-ip-blocker' ); ?></span>
										<?php endif; ?>
									</td>
								</tr>
								<?php if ( ! empty( $zone_id ) ) : ?>
									<tr>
										<td><strong><?php esc_html_e( 'Zone:', 'polar-mass-advanced-ip-blocker' ); ?></strong></td>
										<td>
											<?php if ( ! empty( $zone_name ) ) : ?>
												<strong><?php echo esc_html( $zone_name ); ?></strong>
												<span class="pmip-muted-text">(<?php echo esc_html( substr( $zone_id, 0, 8 ) . '...' . substr( $zone_id, -4 ) ); ?>)</span>
											<?php else : ?>
												<code><?php echo esc_html( substr( $zone_id, 0, 8 ) . '...' . substr( $zone_id, -4 ) ); ?></code>
											<?php endif; ?>
										</td>
									</tr>
								<?php endif; ?>
								<?php if ( ! empty( $ruleset_id ) ) : ?>
									<tr>
										<td><strong><?php esc_html_e( 'Ruleset ID:', 'polar-mass-advanced-ip-blocker' ); ?></strong></td>
										<td><code><?php echo esc_html( substr( $ruleset_id, 0, 8 ) . '...' . substr( $ruleset_id, -4 ) ); ?></code></td>
									</tr>
								<?php endif; ?>
								<?php if ( ! empty( $rule_id ) ) : ?>
									<tr>
										<td><strong><?php esc_html_e( 'Rule:', 'polar-mass-advanced-ip-blocker' ); ?></strong></td>
										<td>
											<?php if ( $rule_details && ! empty( $rule_details['description'] ) ) : ?>
												<strong><?php echo esc_html( $rule_details['description'] ); ?></strong>
												<span class="pmip-muted-text">(<?php echo esc_html( substr( $rule_id, 0, 8 ) . '...' . substr( $rule_id, -4 ) ); ?>)</span>
											<?php else : ?>
												<strong><?php esc_html_e( 'MaliciousIPs - Polar Mass Advanced IP Blocker', 'polar-mass-advanced-ip-blocker' ); ?></strong>
												<span class="pmip-muted-text">(<?php echo esc_html( substr( $rule_id, 0, 8 ) . '...' . substr( $rule_id, -4 ) ); ?>)</span>
											<?php endif; ?>
										</td>
									</tr>
								<?php endif; ?>
							</table>
						</div>
					</div>
				<?php endif; ?>

				<!-- Setup Flow (shown when not connected) -->
				<?php if ( 'not_connected' === $connection_state ) : ?>
					<div class="pmip-setup-flow" id="pmip-setup-flow">
						<div class="pmip-setup-intro">
							<p><?php esc_html_e( 'We\'ll help you connect to Cloudflare in 2 simple steps.', 'polar-mass-advanced-ip-blocker' ); ?></p>
						</div>

						<!-- Step 1: Master Token -->
						<div class="pmip-setup-step" id="pmip-step-1">
							<div class="pmip-step-header">
								<span class="pmip-step-number">1</span>
								<h3><?php esc_html_e( 'Enter Your Master Token', 'polar-mass-advanced-ip-blocker' ); ?></h3>
							</div>
							<p class="pmip-step-description">
								<?php esc_html_e( 'We\'ll use this to create a secure, limited-access token for your site.', 'polar-mass-advanced-ip-blocker' ); ?>
							</p>

							<?php if ( ! empty( $scoped_token_stored ) ) : ?>
								<div class="notice notice-info inline">
									<p>
										<strong><?php esc_html_e( 'Generated API Token:', 'polar-mass-advanced-ip-blocker' ); ?></strong>
										<code><?php echo esc_html( substr( $scoped_token_stored, 0, 8 ) . '...' . substr( $scoped_token_stored, -4 ) ); ?></code>
									</p>
								</div>
							<?php endif; ?>

							<div class="pmip-token-input-section">
								<p>
									<label for="pmip_master_token">
										<strong><?php esc_html_e( 'Master Token:', 'polar-mass-advanced-ip-blocker' ); ?></strong>
									</label>
									<input type="password" 
											id="pmip_master_token" 
											value="<?php echo ! empty( $master_token_stored ) ? esc_attr( $master_token_stored ) : ''; ?>"
											placeholder="<?php esc_attr_e( 'Enter your master token', 'polar-mass-advanced-ip-blocker' ); ?>"
											class="regular-text pmip-token-input">
									<button type="button" id="pmip-toggle-token-visibility" class="button button-small" style="margin-left: 5px;">
										<span class="dashicons dashicons-visibility"></span>
									</button>
								</p>
								<p class="description">
									<?php esc_html_e( 'Token with "Create Additional Tokens" permission.', 'polar-mass-advanced-ip-blocker' ); ?>
									<a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank"><?php esc_html_e( 'Get your master token', 'polar-mass-advanced-ip-blocker' ); ?></a>
								</p>

								<?php if ( $server_ip ) : ?>
									<div class="notice notice-info inline">
										<p>
											<strong><?php esc_html_e( 'Your Server IP:', 'polar-mass-advanced-ip-blocker' ); ?></strong>
											<code><?php echo esc_html( $server_ip ); ?></code>
											<?php if ( 'private' === $server_ip_type ) : ?>
												<span class="pmip-error-text"><?php esc_html_e( '(Private IP detected)', 'polar-mass-advanced-ip-blocker' ); ?></span>
											<?php endif; ?>
											<br>
											<span class="description"><?php esc_html_e( 'Use this IP in "Client IP Address Filtering" when creating your master token for extra security.', 'polar-mass-advanced-ip-blocker' ); ?></span>
										</p>
									</div>
								<?php endif; ?>

								<p>
									<button type="button" id="pmip-auto-connect-btn" class="button button-primary button-large">
										<?php esc_html_e( 'Connect to Cloudflare', 'polar-mass-advanced-ip-blocker' ); ?>
									</button>
									<span id="pmip-auto-connect-status" class="pmip-status-inline"></span>
								</p>
								<div id="pmip-auto-connect-message"></div>
							</div>
						</div>

						<!-- Step 2: Zone Selection (hidden initially) -->
						<div class="pmip-setup-step" id="pmip-step-2" style="display: none;">
							<div class="pmip-step-header">
								<span class="pmip-step-number">2</span>
								<h3><?php esc_html_e( 'Select Your Zone', 'polar-mass-advanced-ip-blocker' ); ?></h3>
							</div>
							<p class="pmip-step-description">
								<?php esc_html_e( 'Choose the Cloudflare zone (domain) you want to protect.', 'polar-mass-advanced-ip-blocker' ); ?>
							</p>

							<div class="pmip-zone-selection-section">
								<p>
									<label for="pmip_zone_select">
										<strong><?php esc_html_e( 'Select Zone:', 'polar-mass-advanced-ip-blocker' ); ?></strong>
									</label>
									<select id="pmip_zone_select" class="regular-text">
										<option value=""><?php esc_html_e( '-- Please select a zone --', 'polar-mass-advanced-ip-blocker' ); ?></option>
									</select>
								</p>
								<p>
									<button type="button" id="pmip-select-zone-btn" class="button button-primary">
										<?php esc_html_e( 'Save & Create Rule', 'polar-mass-advanced-ip-blocker' ); ?>
									</button>
									<span id="pmip-zone-selection-status" class="pmip-status-inline"></span>
								</p>
								<div id="pmip-zone-selection-message"></div>
							</div>
						</div>
					</div>
				<?php endif; ?>

				<!-- Advanced/Manual Configuration (Collapsible) -->
				<div class="pmip-manual-config-section">
					<a href="#" id="pmip-advanced-config-toggle" class="pmip-toggle-link">
						<span class="dashicons dashicons-arrow-down-alt2"></span>
						<?php esc_html_e( 'Advanced: Manual Configuration', 'polar-mass-advanced-ip-blocker' ); ?>
					</a>
					<div id="pmip-manual-config" style="display: none;">
						<div class="notice notice-warning inline">
							<p>
								<strong><?php esc_html_e( 'Note:', 'polar-mass-advanced-ip-blocker' ); ?></strong>
								<?php esc_html_e( 'Manual setup requires existing Cloudflare API token, Zone ID, Ruleset ID, and Rule ID. Auto Connect is recommended for easier setup.', 'polar-mass-advanced-ip-blocker' ); ?>
							</p>
						</div>

						<form method="post" action="">
							<?php wp_nonce_field( 'pmip_settings' ); ?>
							<table class="form-table">
								<tr>
									<th scope="row">
										<label for="pmip_api_token_manual"><?php esc_html_e( 'Cloudflare API Token', 'polar-mass-advanced-ip-blocker' ); ?></label>
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
										<label for="pmip_zone_id_manual"><?php esc_html_e( 'Zone ID', 'polar-mass-advanced-ip-blocker' ); ?></label>
									</th>
									<td>
										<input type="text" 
												id="pmip_zone_id_manual" 
												name="pmip_zone_id" 
												value="<?php echo esc_attr( get_option( 'pmip_zone_id' ) ); ?>" 
												class="regular-text">
										<p class="description">
											<?php esc_html_e( 'Enter your Cloudflare Zone ID. Found in the Overview tab of your domain.', 'polar-mass-advanced-ip-blocker' ); ?>
										</p>
									</td>
								</tr>
								<tr>
									<th scope="row">
										<label for="pmip_ruleset_id_manual"><?php esc_html_e( 'Ruleset ID', 'polar-mass-advanced-ip-blocker' ); ?></label>
									</th>
									<td>
										<input type="text" 
												id="pmip_ruleset_id_manual" 
												name="pmip_ruleset_id" 
												value="<?php echo esc_attr( get_option( 'pmip_ruleset_id' ) ); ?>" 
												class="regular-text">
										<p class="description">
											<?php esc_html_e( 'Enter your Cloudflare Ruleset ID. Found in the WAF > Custom Rules section.', 'polar-mass-advanced-ip-blocker' ); ?>
										</p>
									</td>
								</tr>
								<tr>
									<th scope="row">
										<label for="pmip_rule_id_manual"><?php esc_html_e( 'Rule ID', 'polar-mass-advanced-ip-blocker' ); ?></label>
									</th>
									<td>
										<input type="text" 
												id="pmip_rule_id_manual" 
												name="pmip_rule_id" 
												value="<?php echo esc_attr( get_option( 'pmip_rule_id' ) ); ?>" 
												class="regular-text">
										<p class="description">
											<?php esc_html_e( 'Enter your Cloudflare Rule ID. Found in the specific rule settings under WAF > Custom Rules.', 'polar-mass-advanced-ip-blocker' ); ?>
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

			<!-- IP List Configuration Card -->
			<div class="pmip-ip-list-card pmip-main-settings-section <?php echo ( 'not_connected' === $connection_state ) ? 'pmip-disabled-section' : ''; ?>" data-requires-connection="true">
				<form method="post" action="">
					<?php wp_nonce_field( 'pmip_settings' ); ?>
					
					<h2><?php esc_html_e( 'IP List Configuration', 'polar-mass-advanced-ip-blocker' ); ?></h2>

					<?php if ( 'not_connected' === $connection_state ) : ?>
						<div class="notice notice-info inline">
							<p><?php esc_html_e( 'Connect to Cloudflare above to configure IP lists.', 'polar-mass-advanced-ip-blocker' ); ?></p>
						</div>
					<?php endif; ?>

					<table class="form-table">
						<tr>
							<th scope="row">
								<label for="pmip_use_ip_list"><?php esc_html_e( 'Use Cloudflare IP List', 'polar-mass-advanced-ip-blocker' ); ?></label>
							</th>
							<td>
								<label class="pmip-switch">
									<input type="checkbox" 
											id="pmip_use_ip_list" 
											name="pmip_use_ip_list" 
											value="true"
											<?php checked( get_option( 'pmip_use_ip_list', 'false' ), 'true' ); ?>
											<?php echo ( 'not_connected' === $connection_state ) ? 'disabled' : ''; ?>>
									<span class="pmip-slider"></span>
								</label>
								<p class="description">
									<?php esc_html_e( 'When enabled, IPs will be stored in a Cloudflare IP List and referenced in rules using (ip.src in $listname). When disabled, IPs are embedded directly in the rule expression.', 'polar-mass-advanced-ip-blocker' ); ?>
								</p>
							</td>
						</tr>
						<tr id="pmip-ip-list-info" style="display: none;">
							<th scope="row">
								<?php esc_html_e( 'IP List Status', 'polar-mass-advanced-ip-blocker' ); ?>
							</th>
							<td>
								<div id="pmip-lists-info">
									<p class="description">
										<span class="spinner is-active" style="float: none; margin: 0 10px 0 0;"></span>
										<?php esc_html_e( 'Loading IP lists information...', 'polar-mass-advanced-ip-blocker' ); ?>
									</p>
								</div>
								<p>
									<button type="button" id="pmip-refresh-lists" class="button button-secondary" <?php echo ( 'not_connected' === $connection_state ) ? 'disabled' : ''; ?>>
										<?php esc_html_e( 'Refresh Lists', 'polar-mass-advanced-ip-blocker' ); ?>
									</button>
									<button type="button" id="pmip-create-list" class="button button-secondary" style="display: none;" <?php echo ( 'not_connected' === $connection_state ) ? 'disabled' : ''; ?>>
										<?php esc_html_e( 'Create IP List', 'polar-mass-advanced-ip-blocker' ); ?>
									</button>
								</p>
							</td>
						</tr>
					</table>

					<?php submit_button( null, 'primary', 'submit', false, ( 'not_connected' === $connection_state ) ? array( 'disabled' => 'disabled' ) : array() ); ?>
				</form>
			</div>

			<!-- General Settings -->
			<div class="pmip-main-settings-section">
				<form method="post" action="">
					<?php wp_nonce_field( 'pmip_settings' ); ?>
					
					<h2><?php esc_html_e( 'General Settings', 'polar-mass-advanced-ip-blocker' ); ?></h2>
					<table class="form-table">
						<tr>
							<th scope="row">
								<label for="pmip_plugin_status"><?php esc_html_e( 'Plugin Status', 'polar-mass-advanced-ip-blocker' ); ?></label>
							</th>
							<td>
								<select id="pmip_plugin_status" name="pmip_plugin_status">
									<option value="active" <?php selected( get_option( 'pmip_plugin_status' ), 'active' ); ?>>
										<?php esc_html_e( 'Active', 'polar-mass-advanced-ip-blocker' ); ?>
									</option>
									<option value="inactive" <?php selected( get_option( 'pmip_plugin_status' ), 'inactive' ); ?>>
										<?php esc_html_e( 'Inactive', 'polar-mass-advanced-ip-blocker' ); ?>
									</option>
								</select>
							</td>
						</tr>
						<tr>
							<th scope="row">
								<label for="pmip_scan_interval"><?php esc_html_e( 'Scan Interval', 'polar-mass-advanced-ip-blocker' ); ?></label>
							</th>
							<td>
								<select id="pmip_scan_interval" name="pmip_scan_interval">
									<option value="5" <?php selected( get_option( 'pmip_scan_interval' ), 5 ); ?>>
										<?php esc_html_e( '5 minutes', 'polar-mass-advanced-ip-blocker' ); ?>
									</option>
									<option value="15" <?php selected( get_option( 'pmip_scan_interval' ), 15 ); ?>>
										<?php esc_html_e( '15 minutes', 'polar-mass-advanced-ip-blocker' ); ?>
									</option>
									<option value="30" <?php selected( get_option( 'pmip_scan_interval' ), 30 ); ?>>
										<?php esc_html_e( '30 minutes', 'polar-mass-advanced-ip-blocker' ); ?>
									</option>
									<option value="60" <?php selected( get_option( 'pmip_scan_interval' ), 60 ); ?>>
										<?php esc_html_e( '60 minutes', 'polar-mass-advanced-ip-blocker' ); ?>
									</option>
								</select>
							</td>
						</tr>
						<tr>
							<th scope="row">
								<label for="pmip_failed_attempts"><?php esc_html_e( 'Failed Attempts Threshold', 'polar-mass-advanced-ip-blocker' ); ?></label>
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
									<?php esc_html_e( 'Number of failed login attempts before blocking (3-10)', 'polar-mass-advanced-ip-blocker' ); ?>
								</p>
							</td>
						</tr>
						<tr>
							<th scope="row">
								<label for="pmip_block_duration"><?php esc_html_e( 'Block Duration', 'polar-mass-advanced-ip-blocker' ); ?></label>
							</th>
							<td>
								<select id="pmip_block_duration" name="pmip_block_duration">
									<option value="24h" <?php selected( get_option( 'pmip_block_duration' ), '24h' ); ?>>
										<?php esc_html_e( '24 Hours', 'polar-mass-advanced-ip-blocker' ); ?>
									</option>
									<option value="7d" <?php selected( get_option( 'pmip_block_duration' ), '7d' ); ?>>
										<?php esc_html_e( '7 Days', 'polar-mass-advanced-ip-blocker' ); ?>
									</option>
									<option value="permanent" <?php selected( get_option( 'pmip_block_duration' ), 'permanent' ); ?>>
										<?php esc_html_e( 'Permanent', 'polar-mass-advanced-ip-blocker' ); ?>
									</option>
								</select>
							</td>
						</tr>
						<tr>
							<th scope="row">
								<label for="pmip_max_logs"><?php esc_html_e( 'Maximum Log Entries', 'polar-mass-advanced-ip-blocker' ); ?></label>
							</th>
							<td>
								<input type="number" 
										id="pmip_max_logs" 
										name="pmip_max_logs" 
										value="<?php echo esc_attr( get_option( 'pmip_max_logs', 1000 ) ); ?>" 
										min="100" 
										class="small-text">
								<p class="description">
									<?php esc_html_e( 'Maximum number of log entries to keep', 'polar-mass-advanced-ip-blocker' ); ?>
								</p>
							</td>
						</tr>
					</table>

					<?php submit_button(); ?>
				</form>
			</div>

			<!-- Support Section -->
			<div class="pmip-main-settings-section" style="padding: 0; background: unset; border: unset;">
				<div class="pmip-support-section">
					<h2><?php esc_html_e( 'Support Our Development', 'polar-mass-advanced-ip-blocker' ); ?></h2>
					<p><?php esc_html_e( 'Help us continue improving and maintaining this plugin for the WordPress community.', 'polar-mass-advanced-ip-blocker' ); ?></p>
					
					<div class="pmip-buymeacoffee">
						<a href="https://www.buymeacoffee.com/polarmass" target="_blank">
							<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/buymeacoffee-blue.png' ); ?>" alt="Buy Me A Coffee" style="height: 60px !important; width: 217px !important;">
						</a>
					</div>

					<div class="pmip-contact-info">
						<h3><?php esc_html_e( 'Get in Touch', 'polar-mass-advanced-ip-blocker' ); ?></h3>
						<p><?php esc_html_e( 'Have questions or need assistance? We\'re here to help!', 'polar-mass-advanced-ip-blocker' ); ?></p>
						
						<div class="pmip-contact-methods">
							<div class="pmip-contact-method">
								<i class="dashicons dashicons-email"></i>
								<h4><?php esc_html_e( 'Email Support', 'polar-mass-advanced-ip-blocker' ); ?></h4>
								<p><?php esc_html_e( 'For technical issues and general inquiries', 'polar-mass-advanced-ip-blocker' ); ?></p>
								<a href="mailto:contact@polarmass.com">contact@polarmass.com</a>
							</div>
							
							<div class="pmip-contact-method">
								<i class="dashicons dashicons-admin-site"></i>
								<h4><?php esc_html_e( 'Visit Website', 'polar-mass-advanced-ip-blocker' ); ?></h4>
								<p><?php esc_html_e( 'Documentation and resources', 'polar-mass-advanced-ip-blocker' ); ?></p>
								<a href="https://polarmass.com/" target="_blank">polarmass.com</a>
							</div>
						</div>
					</div>

					<div class="pmip-newsletter">
						<?php if ( ! $is_subscribed ) : ?>
							<h3><?php esc_html_e( 'Stay Updated', 'polar-mass-advanced-ip-blocker' ); ?></h3>
							<p><?php esc_html_e( 'Subscribe to our newsletter for security tips, updates, and special offers.', 'polar-mass-advanced-ip-blocker' ); ?></p>
							<form class="pmip-newsletter-form">
								<input type="email" placeholder="<?php esc_attr_e( 'Enter your email address', 'polar-mass-advanced-ip-blocker' ); ?>" required>
								<button type="submit"><?php esc_html_e( 'Subscribe', 'polar-mass-advanced-ip-blocker' ); ?></button>
							</form>
							<div class="pmip-newsletter-message"></div>
						<?php else : ?>
							<div class="pmip-newsletter-success">
								<p><?php esc_html_e( 'Thank you for subscribing to our newsletter!', 'polar-mass-advanced-ip-blocker' ); ?></p>
								<p><?php esc_html_e( 'You\'ll receive updates and security tips directly in your inbox.', 'polar-mass-advanced-ip-blocker' ); ?></p>
							</div>
						<?php endif; ?>
					</div>
				</div>
			</div>
		</div>

		<!-- Side Panel (Unchanged) -->
		<div class="pmip-side-panel">
			<div class="pmip-manual-block">
				<h3><?php esc_html_e( 'Manual IP Management', 'polar-mass-advanced-ip-blocker' ); ?></h3>
				<div class="pmip-manual-block-form">
					<input type="text" id="pmip-ip-input" placeholder="<?php esc_attr_e( 'Enter IP address', 'polar-mass-advanced-ip-blocker' ); ?>">
					<button class="button button-primary" id="pmip-block-ip">
						<?php esc_html_e( 'Block IP', 'polar-mass-advanced-ip-blocker' ); ?>
					</button>
					<button class="button" id="pmip-unblock-ip">
						<?php esc_html_e( 'Unblock IP', 'polar-mass-advanced-ip-blocker' ); ?>
					</button>
				</div>
				<div class="pmip-manual-sync">
					<button class="button button-secondary" id="pmip-sync-wordfence">
						<?php esc_html_e( 'Sync from Wordfence', 'polar-mass-advanced-ip-blocker' ); ?>
					</button>
					<p class="description">
						<?php esc_html_e( 'Manually sync blocked IPs from Wordfence', 'polar-mass-advanced-ip-blocker' ); ?>
					</p>
				</div>
			</div>

			<div class="pmip-logs">
				<h3><?php esc_html_e( 'Recent Activity Logs', 'polar-mass-advanced-ip-blocker' ); ?></h3>
				<div class="pmip-log-filters">
					<select id="pmip-log-level">
						<option value=""><?php esc_html_e( 'All Levels', 'polar-mass-advanced-ip-blocker' ); ?></option>
						<option value="info"><?php esc_html_e( 'Info', 'polar-mass-advanced-ip-blocker' ); ?></option>
						<option value="warning"><?php esc_html_e( 'Warning', 'polar-mass-advanced-ip-blocker' ); ?></option>
						<option value="error"><?php esc_html_e( 'Error', 'polar-mass-advanced-ip-blocker' ); ?></option>
					</select>
					<button class="button" id="pmip-export-logs">
						<?php esc_html_e( 'Export Logs', 'polar-mass-advanced-ip-blocker' ); ?>
					</button>
				</div>
				<div class="pmip-log-entries">
					<?php
					$logger = new Logger();
					$logs   = $logger->get_logs( 10 );
					if ( empty( $logs ) ) :
						?>
						<p><?php esc_html_e( 'No logs available', 'polar-mass-advanced-ip-blocker' ); ?></p>
					<?php else : ?>
						<table class="widefat">
							<thead>
								<tr>
									<th><?php esc_html_e( 'Time', 'polar-mass-advanced-ip-blocker' ); ?></th>
									<th><?php esc_html_e( 'Level', 'polar-mass-advanced-ip-blocker' ); ?></th>
									<th><?php esc_html_e( 'Message', 'polar-mass-advanced-ip-blocker' ); ?></th>
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

	<!-- Token Instructions Modal (Unchanged) -->
	<div id="pmip-token-instructions" style="display: none;">
		<div id="pmip-token-instructions--content">
			<button id="pmip-close">X</button>
			<h3><?php esc_html_e( 'How to Configure Cloudflare Integration', 'polar-mass-advanced-ip-blocker' ); ?></h3>

			<h4><?php esc_html_e( 'Getting Your API Token', 'polar-mass-advanced-ip-blocker' ); ?></h4>
			<ol>
				<li>
					<?php esc_html_e( 'Log in to your Cloudflare dashboard', 'polar-mass-advanced-ip-blocker' ); ?>
				</li>
				<li>
					<?php esc_html_e( 'Click on "My Profile" in the top right corner', 'polar-mass-advanced-ip-blocker' ); ?>
				</li>
				<li>
					<?php esc_html_e( 'Select "API Tokens" from the left menu', 'polar-mass-advanced-ip-blocker' ); ?>
					<br>
					<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-api-tokens.png' ); ?>" class="pmip-lightbox" target="_blank">
						<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-api-tokens.png' ); ?>" alt="Cloudflare API Tokens" style="max-width:100%;margin-top:8px;cursor:pointer;">
					</a>
				</li>
				<li>
					<?php esc_html_e( 'Click "Create Token"', 'polar-mass-advanced-ip-blocker' ); ?>
				</li>
				<li>
					<?php esc_html_e( 'Use the "Create Custom Token" option', 'polar-mass-advanced-ip-blocker' ); ?>
					<br>
					<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-create-token.png' ); ?>" class="pmip-lightbox" target="_blank">
						<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-create-token.png' ); ?>" alt="Cloudflare Create Token" style="max-width:100%;margin-top:8px;cursor:pointer;">
					</a>
				</li>
				<li><?php esc_html_e( 'Set the following permissions:', 'polar-mass-advanced-ip-blocker' ); ?>
					<ul>
						<li><?php esc_html_e( 'Zone - Zone - Read', 'polar-mass-advanced-ip-blocker' ); ?></li>
						<li><?php esc_html_e( 'Zone - Zone WAF - Edit', 'polar-mass-advanced-ip-blocker' ); ?></li>
						<li><?php esc_html_e( 'Account - Filter Lists - Edit', 'polar-mass-advanced-ip-blocker' ); ?></li>
						<li><?php esc_html_e( 'Account - Filter Lists - Read', 'polar-mass-advanced-ip-blocker' ); ?></li>
					</ul>
				</li>
				<li>
					<?php esc_html_e( 'Set Zone Resources to "All Zones"', 'polar-mass-advanced-ip-blocker' ); ?>
					<br>
					<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-set-zone-resources.png' ); ?>" class="pmip-lightbox" target="_blank">
						<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-set-zone-resources.png' ); ?>" alt="Cloudflare Set Zone Resources" style="max-width:100%;margin-top:8px;cursor:pointer;">
					</a>
				</li>
				<li><?php esc_html_e( 'Click "Continue to Summary" and then "Create Token"', 'polar-mass-advanced-ip-blocker' ); ?></li>
				<li>
					<?php esc_html_e( 'Copy the generated token and paste it in the field above', 'polar-mass-advanced-ip-blocker' ); ?>
					<br>
					<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-copy-token.png' ); ?>" class="pmip-lightbox" target="_blank">
						<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-copy-token.png' ); ?>" alt="Cloudflare Copy Token" style="max-width:100%;margin-top:8px;cursor:pointer;">
					</a>
				</li>
			</ol>

			<h4><?php esc_html_e( 'Finding Your Zone ID', 'polar-mass-advanced-ip-blocker' ); ?></h4>
			<ol>
				<li>
					<?php esc_html_e( 'Log in to your Cloudflare dashboard', 'polar-mass-advanced-ip-blocker' ); ?>
				</li>
				<li>
					<?php esc_html_e( 'Select your domain/website', 'polar-mass-advanced-ip-blocker' ); ?>
					<br>
					<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-select-domain.png' ); ?>" class="pmip-lightbox" target="_blank">
						<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-select-domain.png' ); ?>" alt="Cloudflare Select Domain" style="max-width:100%;margin-top:8px;cursor:pointer;">
					</a>
				</li>
				<li>
					<?php esc_html_e( 'Go to the "Overview" tab and scroll down to the "API" section', 'polar-mass-advanced-ip-blocker' ); ?>
					<br>
					<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-api-section.png' ); ?>" class="pmip-lightbox" target="_blank">
						<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-api-section.png' ); ?>" alt="Cloudflare API Section" style="max-width:100%;margin-top:8px;cursor:pointer;">
					</a>
				</li>
				<li><?php esc_html_e( 'Your Zone ID will be displayed there', 'polar-mass-advanced-ip-blocker' ); ?></li>
			</ol>

			<h4><?php esc_html_e( 'Setting Up Custom Rules', 'polar-mass-advanced-ip-blocker' ); ?></h4>
			<div class="pmip-tabs">
				<button class="pmip-tab active" data-tab="old">Old Security Page</button>
				<button class="pmip-tab" data-tab="new">New Security Page</button>
			</div>
			<div class="pmip-tab-content pmip-tab-content-old active">
				<ol>
					<li>
						<?php esc_html_e( 'In your Cloudflare dashboard, go to Security > WAF > Custom Rules', 'polar-mass-advanced-ip-blocker' ); ?>
						<br>
						<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-waf-custom-rules.png' ); ?>" class="pmip-lightbox" target="_blank">
							<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-waf-custom-rules.png' ); ?>" alt="Cloudflare WAF Custom Rules" style="max-width:100%;margin-top:8px;cursor:pointer;">
						</a>
					</li>
					<li><?php esc_html_e( 'Click "Create Rule"', 'polar-mass-advanced-ip-blocker' ); ?></li>
					<li><?php esc_html_e( 'Configure the rule:', 'polar-mass-advanced-ip-blocker' ); ?>
						<ul>
							<li><?php esc_html_e( 'Rule name: "Block Malicious IPs"', 'polar-mass-advanced-ip-blocker' ); ?></li>
							<li>
								<?php esc_html_e( 'Click on Edit Expression, then paste the following expression: (ip.src in {})', 'polar-mass-advanced-ip-blocker' ); ?>
								<br>
								<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-edit-expression.png' ); ?>" class="pmip-lightbox" target="_blank">
									<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-edit-expression.png' ); ?>" alt="Cloudflare Edit Expression" style="max-width:100%;margin-top:8px;cursor:pointer;">
								</a>
							</li>
							<li><?php esc_html_e( 'Action: Block', 'polar-mass-advanced-ip-blocker' ); ?></li>
						</ul>
					</li>
					<li><?php esc_html_e( 'Click on the "Deploy" button', 'polar-mass-advanced-ip-blocker' ); ?></li>
					<li><?php esc_html_e( 'After creating the rule:', 'polar-mass-advanced-ip-blocker' ); ?>
						<ul>
							<li><?php esc_html_e( 'The Ruleset ID and Rule ID are shown in the URL when editing the ruleset', 'polar-mass-advanced-ip-blocker' ); ?></li>
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
						<?php esc_html_e( 'In the new Cloudflare dashboard, go to Security > Security Rules', 'polar-mass-advanced-ip-blocker' ); ?>
						<br>
						<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-create-rule-new.png' ); ?>" class="pmip-lightbox" target="_blank">
							<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-create-rule-new.png' ); ?>" alt="Cloudflare Create Rule" style="max-width:100%;margin-top:8px;cursor:pointer;">
						</a>
					</li>
					<li>
						<?php esc_html_e( 'Click "Create Rule" and choose "Custom Rule"', 'polar-mass-advanced-ip-blocker' ); ?>
					</li>
					<li><?php esc_html_e( 'Configure the rule:', 'polar-mass-advanced-ip-blocker' ); ?>
						<ul>
							<li><?php esc_html_e( 'Rule name: "Block Malicious IPs"', 'polar-mass-advanced-ip-blocker' ); ?></li>
							<li>
								<?php esc_html_e( 'Click on Edit Expression, then paste the following expression: (ip.src in {})', 'polar-mass-advanced-ip-blocker' ); ?>
								<br>
								<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-edit-expression-new.png' ); ?>" class="pmip-lightbox" target="_blank">
									<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-edit-expression-new.png' ); ?>" alt="Cloudflare Edit Expression" style="max-width:100%;margin-top:8px;cursor:pointer;">
								</a>
							</li>
							<li><?php esc_html_e( 'Action: Block', 'polar-mass-advanced-ip-blocker' ); ?></li>
						</ul>
					</li>
					<li><?php esc_html_e( 'Click on the "Deploy" button', 'polar-mass-advanced-ip-blocker' ); ?></li>
					<li><?php esc_html_e( 'After creating the rule:', 'polar-mass-advanced-ip-blocker' ); ?>
						<ul>
							<li><?php esc_html_e( 'The Ruleset ID and Rule ID are shown in the URL when editing the ruleset', 'polar-mass-advanced-ip-blocker' ); ?></li>
						</ul>
						<pre style="background:#f6f8fa;padding:8px 12px;border-radius:4px;margin-top:8px;overflow-x:auto;font-size:13px;">
https://api.cloudflare.com/client/v4/zones/[ZONE_ID]/rulesets/[RULESET_ID]/rules/[RULE_ID]
</pre>
<br>
<a href="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-ruleset-id-new.png' ); ?>" class="pmip-lightbox" target="_blank">
	<img src="<?php echo esc_url( PMIP_BLOCKER_PLUGIN_URL . 'assets/images/cloudflare-ruleset-id-new.png' ); ?>" alt="Cloudflare Ruleset ID" style="max-width:100%;margin-top:8px;cursor:pointer;">
</a>
					</li>
					<li><?php esc_html_e( 'After creating the rule, note the new location for Ruleset ID and Rule ID', 'polar-mass-advanced-ip-blocker' ); ?></li>
				</ol>
			</div>

			<p class="description">
				<?php esc_html_e( 'Note: Make sure to keep these IDs secure and never share them publicly.', 'polar-mass-advanced-ip-blocker' ); ?>
			</p>
		</div>
	</div>
</div>
