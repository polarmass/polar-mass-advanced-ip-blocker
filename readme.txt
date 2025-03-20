=== Polar Mass Advanced IP Blocker ===
Contributors: polarmass  
Donate link: https://www.buymeacoffee.com/polarmass
Tags: security, cloudflare, ip-blocker, firewall, wordpress-security  
Requires at least: 5.8  
Tested up to: 6.7  
Stable tag: 1.0.2  
Requires PHP: 7.4  
License: GPLv2 or later  
License URI: https://www.gnu.org/licenses/gpl-2.0.html  

Automatically block threats at the network level by forwarding Wordfence-detected IPs to Cloudflare.

== Description ==

**Automatically Block Malicious IPs with Cloudflare**  
Protect your WordPress site from hackers and brute-force attacks. This free plugin automatically blocks malicious IPs detected by Wordfence and integrates with Cloudflare for real-time security.

= Features =
- 🔒 **Automatic IP Blocking** – Blocks malicious IPs detected by Wordfence.
- ⚡ **Cloudflare Integration** – Uses Cloudflare's API for real-time threat mitigation.
- 📉 **Reduces Server Load** – Shifts security tasks from WordPress to Cloudflare.
- 🏆 **Lightweight & Fast** – Security without slowing down your site.
- 🛠️ **Easy Setup** – Just enter your Cloudflare API key and Zone ID.
- 🆓 **Free & Open Source** – Transparent and continuously improved.

== Installation ==
1. Download the latest release from [WordPress Repository](https://wordpress.org/plugins/polar-mass-advanced-ip-blocker/).
2. Upload the plugin to your WordPress installation (`/wp-content/plugins/`).
3. Activate it from the **WordPress Admin Panel**.
4. Enter your **Cloudflare API Key** and **Zone ID** in the settings.

== Frequently Asked Questions ==

= Does this plugin work without Wordfence? =  
No, this plugin relies on Wordfence logs to detect malicious IPs.

= Is my Cloudflare API Key safe? =  
Yes, your API Key is stored securely and is only used for API requests.

= Can I manually block IPs? =  
Yes, you can add and remove IPs manually in the settings.

== Changelog ==

= 1.0.0 =  
- Initial release  
- Cloudflare API integration  
- Automatic IP blocking  
- Manual IP blocking  

== License ==

This plugin is licensed under the [GPL v2 or later](https://www.gnu.org/licenses/gpl-2.0.html).

== Support ==

For support, feature requests, or bug reports, open an issue or reach out via [email](mailto:contact@polarmass.com).

== External Services ==

To improve the user experience, **Polar Mass Advanced IP Blocker** may use the following third-party services:  

= Cloudflare API (https://api.cloudflare.com/client/v4/) =
This plugin integrates with **Cloudflare's API** to manage IP rules and firewall settings, helping block malicious traffic in real-time.  
- Users must manually enter their **Cloudflare API Key** and **Zone ID** in the plugin settings to enable this feature.  
- No automatic data collection occurs without user input.  
- When configured, the plugin securely sends user-defined IPs and rules to Cloudflare's servers.  
- Cloudflare Privacy Policy: [https://www.cloudflare.com/privacypolicy](https://www.cloudflare.com/privacypolicy)  

= Polar Mass API (https://polarmass.com/wp-json/pmip/v1/newsletter/signup) =
This plugin provides an **optional** newsletter signup form within the admin panel.  
- The **only** data collected is the email address entered by the user.  
- This data is securely transmitted to our server at **polarmass.com**.  
- No personal information is shared or processed without explicit user consent.  
- Privacy Policy: [https://polarmass.com/privacy-policy/](https://polarmass.com/privacy-policy/)  

For more details, please review our [Terms and Conditions](https://polarmass.com/terms-and-conditions/) and [Privacy Policy](https://polarmass.com/privacy-policy/).  
