<?php
namespace CloudflareIpBlocker;

class IpBlocker {
    /**
     * @var Logger
     */
    private $logger;

    /**
     * @var array
     */
    private $blocked_ips;

    /**
     * @var CloudflareApi
     */
    private $cloudflare;

    /**
     * Constructor
     *
     * @param Logger $logger Logger instance
     */
    public function __construct(Logger $logger) {
        $this->logger = $logger;
        $this->cloudflare = new CloudflareApi($logger);
        $this->blocked_ips = get_option('cfip_blocked_ips', []);
    }

    /**
     * Sync blocked IPs from Wordfence
     */
    public function sync_from_wordfence() {
        if (!class_exists('wfActivityReport')) {
            $this->logger->log('Wordfence not installed or activated', 'error');
            return false;
        }

        try {
            $activityReport = new \wfActivityReport();
            
            // Get blocked IPs from last 24 hours, 7 days, and 30 days
            $ips24h = (array) $activityReport->getTopIPsBlocked(100, 1);
            $ips7d = (array) $activityReport->getTopIPsBlocked(100, 7);
            $ips30d = (array) $activityReport->getTopIPsBlocked(100, 30);

            // Process and normalize the data
            $threshold = get_option('cfip_failed_attempts', 5);
            $ips_to_block = [];

            foreach ([$ips24h, $ips7d, $ips30d] as $ip_list) {
                foreach ($ip_list as $entry) {
                    $entry = (array) $entry;
                    if ($entry['blockCount'] >= $threshold) {
                        $ips_to_block[] = \wfUtils::inet_ntop($entry['IP']);
                    }
                }
            }

            // Remove duplicates
            $ips_to_block = array_unique($ips_to_block);

            if (empty($ips_to_block)) {
                $this->logger->log('No IPs found that exceed the threshold', 'info');
                return true;
            }

            // Block IPs in bulk
            $result = $this->cloudflare->block_ips($ips_to_block);
            
            if ($result) {
                $this->logger->log('Successfully synced ' . count($ips_to_block) . ' IPs from Wordfence');
                return true;
            } else {
                $this->logger->log('Failed to sync IPs from Wordfence', 'error');
                return false;
            }

        } catch (\Exception $e) {
            $this->logger->log('Error syncing from Wordfence: ' . $e->getMessage(), 'error');
            return false;
        }
    }

    /**
     * Handle Wordfence security events
     *
     * @param string $event Event type
     * @param array $data Event data
     */
    public function handle_wordfence_event($event, $data) {
        // Validate event and required data
        if (!in_array($event, ['increasedAttackRate', 'loginLockout'], true) || empty($data['ip'])) {
            return;
        }
    
        $ip = $data['ip'];
        $event_text = '';
        if ($event === 'increasedAttackRate') {
            $event_text = 'increased attack rate';
        } elseif ($event === 'loginLockout') {
            $event_text = 'login lockout';
        }
        $this->logger->log("Received Wordfence event: {$event_text} for IP {$ip}");
        $threshold = (int) get_option('cfip_failed_attempts', 5); // Ensure threshold is an integer
    
        // If attackCount is set and exceeds the threshold, block immediately
        if (!empty($data['attackCount'])) {
            if ((int) $data['attackCount'] >= $threshold) {
                $result = $this->sync_from_wordfence();
                if ($result) {
                    $this->logger->log("[Wordfence] IP {$ip} exceeded threshold, blocked");
                } else {
                    $this->logger->log("[Wordfence] Failed to sync IPs from Wordfence", 'error');
                }
            }
            return;
        }
    
        // Retrieve failed attempts safely
        $failed_attempts_data = $this->get_failed_attempts($ip);

        if ($this->is_block_expired($failed_attempts_data)) {
            // Expired, reset to 1
            $failed_attempts = 1;
        } else {
            // Still valid, increment count
            $failed_attempts = (int) $failed_attempts_data['count'] + 1;
        }

        // Update the failed attempts count
        $this->update_failed_attempts($ip, $failed_attempts);
    
        // Block if threshold is reached
        if ($failed_attempts >= $threshold) {
            $result = $this->sync_from_wordfence();
            if ($result) {
                $this->logger->log("[Wordfence] IP {$ip} exceeded threshold, blocked");
            } else {
                $this->logger->log("[Wordfence] Failed to sync IPs from Wordfence", 'error');
            }
        }
    }

    /**
     * Get failed login attempts and block info for an IP.
     *
     * @param string $ip The IP address to check.
     * @return array An array containing 'count' (int), 'timestamp' (int|null), and 'duration' (string|null).
     */
    private function get_failed_attempts($ip) {
        $attempts = get_option('cfip_failed_attempts_log', []);
        return isset($attempts[$ip]) ? $attempts[$ip] : ['count' => 0, 'timestamp' => null, 'duration' => null];
    }

    /**
     * Update the failed login attempts for an IP address.
     * Stores the count, timestamp, and block duration.
     *
     * @param string $ip The IP address to track.
     * @param int $count The number of failed attempts.
     */
    private function update_failed_attempts($ip, $count) {
        $attempts = get_option('cfip_failed_attempts_log', []);
        
        if ($count === 1) {
            // If this is the first failure, store the timestamp
            $attempts[$ip] = [
                'count' => $count,
                'timestamp' => time(), 
                'duration' => get_option('cfip_block_duration', '24h')
            ];
        } else {
            // Otherwise, just update the count
            if (isset($attempts[$ip])) {
                $attempts[$ip]['count'] = $count;
            } else {
                $attempts[$ip] = ['count' => $count, 'timestamp' => time(), 'duration' => get_option('cfip_block_duration', '24h')];
            }
        }
        
        update_option('cfip_failed_attempts_log', $attempts);
    }

    /**
     * Block an IP address
     *
     * @param string $ip IP address to block
     * @return bool Success status
     */
    public function block_ip($ip) {
        try {
            if ($this->is_whitelisted($ip)) {
                $this->logger->log("IP {$ip} is whitelisted, skipping block");
                return false;
            }

            if ($this->is_blocked($ip)) {
                $this->logger->log("IP {$ip} is already blocked");
                return true;
            }

            $result = $this->cloudflare->block_ip($ip);
            if ($result) {
                $this->blocked_ips[$ip] = [
                    'timestamp' => time(),
                    'duration' => get_option('cfip_block_duration', '24h')
                ];
                update_option('cfip_blocked_ips', $this->blocked_ips);
                $this->logger->log("Successfully blocked IP: {$ip}");
                return true;
            }

            $this->logger->log("Failed to block IP: {$ip}");
            return false;
        } catch (\Exception $e) {
            $this->logger->log("Error blocking IP {$ip}: " . $e->getMessage(), 'error');
            return false;
        }
    }

    /**
     * Unblock an IP address
     *
     * @param string $ip IP address to unblock
     * @return bool Success status
     */
    public function unblock_ip($ip) {
        try {
            if (!$this->is_blocked($ip)) {
                $this->logger->log("IP {$ip} is not blocked");
                return true;
            }

            $result = $this->cloudflare->unblock_ip($ip);
            if ($result) {
                unset($this->blocked_ips[$ip]);
                update_option('cfip_blocked_ips', $this->blocked_ips);
                $this->logger->log("Successfully unblocked IP: {$ip}");
                return true;
            }

            $this->logger->log("Failed to unblock IP: {$ip}");
            return false;
        } catch (\Exception $e) {
            $this->logger->log("Error unblocking IP {$ip}: " . $e->getMessage(), 'error');
            return false;
        }
    }

    /**
     * Check if an IP is blocked
     *
     * @param string $ip IP address to check
     * @return bool Whether IP is blocked
     */
    public function is_blocked($ip) {
        return isset($this->blocked_ips[$ip]);
    }

    /**
     * Check if an IP is whitelisted
     *
     * @param string $ip IP address to check
     * @return bool Whether IP is whitelisted
     */
    public function is_whitelisted($ip) {
        $whitelist = get_option('cfip_ip_whitelist', []);
        return in_array($ip, $whitelist);
    }

    /**
     * Check and block IPs based on failed login attempts
     */
    public function check_and_block_ips() {
        if (get_option('cfip_plugin_status', 'inactive') !== 'active') {
            return;
        }

        $this->sync_from_wordfence();
    }

    /**
     * Clean up expired IP blocks
     */
    private function cleanup_blocked_ips() {
        $modified = false;
        foreach ($this->blocked_ips as $ip => $data) {
            if ($this->is_block_expired($data)) {
                $this->unblock_ip($ip);
                $modified = true;
            }
        }

        if ($modified) {
            update_option('cfip_blocked_ips', $this->blocked_ips);
        }
    }

    /**
     * Check if an IP block has expired
     *
     * @param array $data Block data
     * @return bool Whether block has expired
     */
    private function is_block_expired($data) {
        $duration = $this->parse_duration($data['duration']);
        return (time() - $data['timestamp']) > $duration;
    }

    /**
     * Parse duration string to seconds
     *
     * @param string $duration Duration string (e.g., "24h", "7d", "permanent")
     * @return int Duration in seconds
     */
    private function parse_duration($duration) {
        if ($duration === 'permanent') {
            return PHP_INT_MAX;
        }

        $unit = substr($duration, -1);
        $value = intval(substr($duration, 0, -1));

        switch ($unit) {
            case 'h':
                return $value * 3600;
            case 'd':
                return $value * 86400;
            default:
                return 86400; // Default to 24 hours
        }
    }
}