# Alsiesta Limit Login Attempts

A lightweight WordPress plugin that protects the login page against brute-force attacks by tracking failed attempts per IP address and permanently blacklisting offending IPs.

## How It Works

Every time someone enters wrong credentials — either through the login form or via auth cookies — the attempt is counted in a custom database table. Once an IP reaches the configured threshold (default: 5 attempts), it is permanently added to a blacklist. From that point on, any login attempt from that IP is blocked immediately with no time limit and no automatic expiry.

On a successful login, the attempt counter for that IP is reset — but blacklist entries are never removed automatically. This means a determined attacker cannot simply wait out a timeout and try again.

## Features

- Tracks failed login attempts per IP in a dedicated database table
- Auto-blacklists IPs that reach the failure threshold
- Blocks both login form attempts and auth cookie brute-force attacks
- **Whitelist** support — trusted IPs are always allowed through, never counted or blocked
- Manual blacklisting and whitelisting of IPs via the admin panel
- One-click removal of IPs from blacklist or whitelist
- Optional email notification to the administrator on each auto-blacklist event
- Configurable failure threshold
- Full attempt log in the admin panel (last 50 entries)
- Cloudflare-compatible — reads `HTTP_CF_CONNECTING_IP` header
- Clean uninstall — removes all tables and options on deletion

## Installation

1. Copy the `alsiesta-limit-login-attempts` folder into `wp-content/plugins/`
2. Go to **WP Admin → Plugins** and activate **Alsiesta Limit Login Attempts**
3. The required database tables are created automatically on activation
4. Configure settings under **Settings → Limit Logins**

## Configuration

Navigate to **Settings → Limit Logins** in the WordPress admin panel.

| Setting | Default | Description |
|---|---|---|
| Failed attempts before blacklist | 5 | Number of failures before an IP is permanently blocked |
| Email notification | On | Send an email to the admin when an IP is auto-blacklisted |
| Notification email | Admin email | The address that receives blacklist notifications |

## Database Tables

The plugin creates three custom tables on activation:

| Table | Purpose |
|---|---|
| `wp_lla_login_attempts` | Tracks attempt counts per IP while below the threshold |
| `wp_lla_blacklist` | Stores permanently blocked IPs with reason and timestamp |
| `wp_lla_whitelist` | Stores trusted IPs that are always allowed through |

All tables are removed cleanly when the plugin is deleted via the WordPress admin.

## Admin Panel

**Settings → Limit Logins** provides:

- Settings form (threshold, email notification)
- Whitelisted IPs table with per-IP remove button and manual add form
- Blacklisted IPs table with per-IP remove button and manual add form
- Recent attempt log (last 50 entries) with purge option

## Locked Yourself Out?

Go to phpMyAdmin and run:

```sql
DELETE FROM wp_lla_blacklist WHERE ip_address = 'your.ip.address';
```

Or remove all blacklist entries:

```sql
TRUNCATE TABLE wp_lla_blacklist;
```

## Changelog

### 1.3.0
- Added whitelist support — trusted IPs bypass all checks

### 1.2.0
- Replaced timed lockout with permanent auto-blacklist
- Added `wp_lla_blacklist` table
- Added manual blacklist management in admin panel
- Added auth cookie brute-force protection

### 1.1.0
- Added auth cookie failure hooks (`auth_cookie_bad_username`, `auth_cookie_bad_hash`)
- Added cookie-based lockout check via `auth_cookie_valid`

### 1.0.0
- Initial release
- Login form protection with custom DB table
- Admin settings page with attempt log and unlock functionality

## License

GPL-2.0+
