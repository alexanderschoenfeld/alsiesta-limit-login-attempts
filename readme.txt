=== Alsiesta Limit Login Attempts ===
Contributors: alsiesta
Tags: login, security, brute force, blacklist, login attempts
Requires at least: 5.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.2.0
License: GPL-2.0+
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Protects the WordPress login against brute-force attacks by auto-blacklisting IPs that exceed the failed login threshold.

== Description ==

By default WordPress allows unlimited login attempts. This allows passwords to be brute-force cracked with relative ease.

Alsiesta Limit Login Attempts fixes this by tracking every failed login attempt per IP address. Once an IP exceeds the configured threshold, it is permanently blacklisted — no timeouts, no second chances. Blocked IPs can be removed manually by the administrator at any time.

**How it works**

Every failed login attempt — whether through the login form or via auth cookies — is recorded in a dedicated database table. When an IP reaches the failure threshold, it is moved to a permanent blacklist. Subsequent attempts from that IP are blocked immediately, before WordPress even checks the credentials.

On a successful login the attempt counter is reset, but blacklist entries persist until manually removed. This prevents attackers from simply waiting out a lockout period.

**Features**

* Tracks failed login attempts per IP in a custom database table
* Permanently blacklists IPs that reach the failure threshold
* Blocks both login form and auth cookie brute-force attacks
* Manual blacklisting of known malicious IPs via the admin panel
* One-click removal of IPs from the blacklist
* Optional email notification to the administrator on each blacklist event
* Configurable failure threshold
* Full attempt log in the admin panel (last 50 entries)
* Clean uninstall — removes all plugin data on deletion

== Installation ==

1. Upload the `alsiesta-limit-login-attempts` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the **Plugins** menu in WordPress
3. Configure the plugin under **Settings → Limit Logins**

== Frequently Asked Questions ==

= I locked myself out. How do I get back in? =

Go to phpMyAdmin and run:
`DELETE FROM wp_lla_blacklist WHERE ip_address = 'your.ip.address';`

Or truncate the table to remove all blacklist entries:
`TRUNCATE TABLE wp_lla_blacklist;`

= Where is the settings page? =

Under **Settings → Limit Logins** in the WordPress admin panel.

= Does this work with Cloudflare? =

Yes. The plugin reads the `HTTP_CF_CONNECTING_IP` header first, so the real visitor IP is captured correctly when behind Cloudflare.

= What happens to a blocked user who was mistakenly blacklisted? =

Go to **Settings → Limit Logins**, find their IP in the Blacklisted IPs table, and click Remove. They will be able to log in immediately.

= Does the plugin slow down my site? =

No. It makes one lightweight indexed database query per login attempt — only on the login page, never on the front end.

= What database tables does this plugin create? =

Two tables:
- `wp_lla_login_attempts` — temporary attempt counter per IP
- `wp_lla_blacklist` — permanent blacklist with reason and timestamp

Both are removed cleanly when the plugin is deleted.

== Screenshots ==

1. Settings page with configurable threshold and email notification
2. Blacklisted IPs table with manual add and remove controls
3. Recent attempt log showing IP, attempt count, and last attempt time
4. Login page error message shown to a blocked IP

== Changelog ==

= 1.2.0 =
* Replaced timed lockout with permanent auto-blacklist
* Added wp_lla_blacklist database table
* Added manual blacklist management in admin panel
* Added auth cookie brute-force protection

= 1.1.0 =
* Added auth cookie failure hooks (auth_cookie_bad_username, auth_cookie_bad_hash)
* Added cookie-based lockout check via auth_cookie_valid hook

= 1.0.0 =
* Initial release
* Login form protection with custom database table
* Admin settings page with attempt log

== Upgrade Notice ==

= 1.2.0 =
Deactivate and reactivate the plugin after updating to create the new wp_lla_blacklist database table.
