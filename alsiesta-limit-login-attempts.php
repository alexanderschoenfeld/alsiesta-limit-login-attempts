<?php
/**
 * Plugin Name: Alsiesta Limit Login Attempts
 * Plugin URI:  https://github.com/alexanderschoenfeld/alsiesta-limit-login-attempts
 * Description: Blocks brute-force login attacks. Auto-blacklists IPs that hit the lockout threshold.
 * Version:     1.4.0
 * Author:      Alsiesta
 * License:     GPL-2.0+
 */

defined( 'ABSPATH' ) || exit;

define( 'LLA_TABLE',      'lla_login_attempts' );
define( 'LLA_BLACKLIST',  'lla_blacklist' );
define( 'LLA_WHITELIST',  'lla_whitelist' );
define( 'LLA_VERSION',    '1.4.0' );

/* ─────────────────────────────────────────────
   1. ACTIVATION / UNINSTALL
───────────────────────────────────────────── */

register_activation_hook( __FILE__, 'lla_activate' );
function lla_activate() {
    lla_run_migrations();
    add_option( 'lla_max_attempts',      5 );
    add_option( 'lla_notify_email',      get_option( 'admin_email' ) );
    add_option( 'lla_notify_on_lockout', 1 );
    update_option( 'lla_db_version', LLA_VERSION );
}

register_uninstall_hook( __FILE__, 'lla_uninstall' );
function lla_uninstall() {
    global $wpdb;
    $wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}" . LLA_TABLE );
    $wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}" . LLA_BLACKLIST );
    $wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}" . LLA_WHITELIST );
    foreach ( [ 'lla_max_attempts', 'lla_notify_email',
                'lla_notify_on_lockout', 'lla_db_version' ] as $opt ) {
        delete_option( $opt );
    }
}

/* ─────────────────────────────────────────────
   1b. DB MIGRATIONS (runs on plugin update too)
───────────────────────────────────────────── */

add_action( 'plugins_loaded', 'lla_maybe_migrate' );
function lla_maybe_migrate() {
    if ( get_option( 'lla_db_version' ) !== LLA_VERSION ) {
        lla_run_migrations();
        update_option( 'lla_db_version', LLA_VERSION );
    }
}

function lla_run_migrations() {
    global $wpdb;
    $charset_collate = $wpdb->get_charset_collate();
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';

    // Attempts table — dbDelta adds missing columns automatically
    $t1 = $wpdb->prefix . LLA_TABLE;
    dbDelta( "CREATE TABLE {$t1} (
        id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        ip_address    VARCHAR(45)  NOT NULL,
        attempts      INT UNSIGNED NOT NULL DEFAULT 1,
        last_attempt  DATETIME     NOT NULL,
        last_endpoint VARCHAR(60)  NOT NULL DEFAULT 'wp-login',
        PRIMARY KEY (id),
        UNIQUE KEY ip_address (ip_address)
    ) {$charset_collate};" );

    $t2 = $wpdb->prefix . LLA_BLACKLIST;
    dbDelta( "CREATE TABLE {$t2} (
        id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        ip_address VARCHAR(45)  NOT NULL,
        reason     VARCHAR(255) DEFAULT 'Auto-blacklisted after repeated failed logins',
        added_at   DATETIME     NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY ip_address (ip_address)
    ) {$charset_collate};" );

    $t3 = $wpdb->prefix . LLA_WHITELIST;
    dbDelta( "CREATE TABLE {$t3} (
        id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        ip_address VARCHAR(45)  NOT NULL,
        reason     VARCHAR(255) DEFAULT 'Trusted IP',
        added_at   DATETIME     NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY ip_address (ip_address)
    ) {$charset_collate};" );
}

/* ─────────────────────────────────────────────
   2. HELPERS
───────────────────────────────────────────── */

function lla_get_ip() {
    $keys = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'REMOTE_ADDR',
    ];
    foreach ( $keys as $key ) {
        if ( ! empty( $_SERVER[ $key ] ) ) {
            $ip = trim( explode( ',', $_SERVER[ $key ] )[0] );
            if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                return $ip;
            }
        }
    }
    return '0.0.0.0';
}

function lla_get_endpoint() {
    if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )   return 'xmlrpc';
    if ( defined( 'REST_REQUEST' )   && REST_REQUEST )     return 'rest-api';
    if ( defined( 'DOING_CRON' )     && DOING_CRON )       return 'wp-cron';
    $uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
    if ( strpos( $uri, 'wc-ajax'      ) !== false )        return 'woocommerce';
    if ( strpos( $uri, 'wp-comments'  ) !== false )        return 'wp-comments';
    return 'wp-login';
}

function lla_get_record( $ip ) {
    global $wpdb;
    $table = $wpdb->prefix . LLA_TABLE;
    return $wpdb->get_row(
        $wpdb->prepare( "SELECT * FROM {$table} WHERE ip_address = %s", $ip )
    );
}

function lla_is_blacklisted( $ip ) {
    global $wpdb;
    $table = $wpdb->prefix . LLA_BLACKLIST;
    return (bool) $wpdb->get_var(
        $wpdb->prepare( "SELECT id FROM {$table} WHERE ip_address = %s", $ip )
    );
}

function lla_blacklist_ip( $ip, $reason = 'Auto-blacklisted after repeated failed logins' ) {
    global $wpdb;
    $table = $wpdb->prefix . LLA_BLACKLIST;
    $wpdb->query(
        $wpdb->prepare(
            "INSERT IGNORE INTO {$table} (ip_address, reason, added_at) VALUES (%s, %s, %s)",
            $ip,
            $reason,
            current_time( 'mysql' )
        )
    );
    $wpdb->delete( $wpdb->prefix . LLA_TABLE, [ 'ip_address' => $ip ] );
}

function lla_is_whitelisted( $ip ) {
    global $wpdb;
    $table = $wpdb->prefix . LLA_WHITELIST;
    return (bool) $wpdb->get_var(
        $wpdb->prepare( "SELECT id FROM {$table} WHERE ip_address = %s", $ip )
    );
}

function lla_whitelist_ip( $ip, $reason = 'Trusted IP' ) {
    global $wpdb;
    $table = $wpdb->prefix . LLA_WHITELIST;
    $wpdb->query(
        $wpdb->prepare(
            "INSERT IGNORE INTO {$table} (ip_address, reason, added_at) VALUES (%s, %s, %s)",
            $ip,
            $reason,
            current_time( 'mysql' )
        )
    );
    $wpdb->delete( $wpdb->prefix . LLA_TABLE,    [ 'ip_address' => $ip ] );
    $wpdb->delete( $wpdb->prefix . LLA_BLACKLIST, [ 'ip_address' => $ip ] );
}

/* ─────────────────────────────────────────────
   3. CORE HOOKS
───────────────────────────────────────────── */

add_filter( 'authenticate', 'lla_check_lockout', 1, 3 );
function lla_check_lockout( $user, $username, $password ) {
    if ( empty( $username ) ) {
        return $user;
    }
    $ip = lla_get_ip();

    if ( lla_is_whitelisted( $ip ) ) {
        return $user;
    }

    if ( lla_is_blacklisted( $ip ) ) {
        return new WP_Error(
            'lla_blacklisted',
            __( '<strong>Access denied.</strong> Your IP has been permanently blocked due to too many failed login attempts. Contact the site administrator if you believe this is an error.', 'limit-login-attempts' )
        );
    }
    return $user;
}

add_action( 'wp_login_failed', 'lla_record_failure' );
function lla_record_failure( $username ) {
    global $wpdb;
    $table    = $wpdb->prefix . LLA_TABLE;
    $ip       = lla_get_ip();
    $endpoint = lla_get_endpoint();
    $max      = (int) get_option( 'lla_max_attempts', 5 );

    if ( lla_is_whitelisted( $ip ) ) return;
    if ( lla_is_blacklisted( $ip ) ) return;

    $record = lla_get_record( $ip );

    if ( ! $record ) {
        $wpdb->insert( $table, [
            'ip_address'    => $ip,
            'attempts'      => 1,
            'last_attempt'  => current_time( 'mysql' ),
            'last_endpoint' => $endpoint,
        ] );
        $new_attempts = 1;
    } else {
        $new_attempts = (int) $record->attempts + 1;
        $wpdb->update(
            $table,
            [
                'attempts'      => $new_attempts,
                'last_attempt'  => current_time( 'mysql' ),
                'last_endpoint' => $endpoint,
            ],
            [ 'ip_address' => $ip ]
        );
    }

    if ( $new_attempts >= $max ) {
        lla_blacklist_ip( $ip );
        lla_maybe_notify( $ip, $username, $endpoint );
    }
}

add_action( 'auth_cookie_bad_username', 'lla_record_cookie_failure' );
add_action( 'auth_cookie_bad_hash',     'lla_record_cookie_failure' );
function lla_record_cookie_failure( $cookie_elements ) {
    $username = isset( $cookie_elements['username'] ) ? $cookie_elements['username'] : '';
    lla_record_failure( $username );
}

add_action( 'auth_cookie_valid', 'lla_check_cookie_lockout', 1, 2 );
function lla_check_cookie_lockout( $cookie_elements, $user ) {
    $ip = lla_get_ip();
    if ( lla_is_whitelisted( $ip ) ) return;
    if ( lla_is_blacklisted( $ip ) ) {
        wp_logout();
        wp_die(
            __( '<strong>Access denied.</strong> Your IP has been permanently blocked.', 'limit-login-attempts' ),
            __( 'Blocked', 'limit-login-attempts' ),
            [ 'response' => 403 ]
        );
    }
}

add_action( 'wp_login', 'lla_clear_on_success', 10, 2 );
function lla_clear_on_success( $user_login, $user ) {
    global $wpdb;
    $wpdb->delete( $wpdb->prefix . LLA_TABLE, [ 'ip_address' => lla_get_ip() ] );
}

/* ─────────────────────────────────────────────
   4. EMAIL NOTIFICATION
───────────────────────────────────────────── */

function lla_maybe_notify( $ip, $username, $endpoint = 'unknown' ) {
    if ( ! get_option( 'lla_notify_on_lockout' ) ) return;

    $to      = get_option( 'lla_notify_email', get_option( 'admin_email' ) );
    $subject = sprintf( '[%s] IP auto-blacklisted: %s', get_bloginfo( 'name' ), $ip );
    $message = sprintf(
        "IP address %s has been permanently blacklisted after repeated failed login attempts.\n\nUsername tried: %s\nEndpoint: %s\nBlacklisted at: %s\n\nTo remove this IP visit:\n%s",
        $ip, $username, $endpoint, current_time( 'mysql' ),
        admin_url( 'options-general.php?page=limit-login-attempts' )
    );
    wp_mail( $to, $subject, $message );
}

/* ─────────────────────────────────────────────
   5. ADMIN PAGE
───────────────────────────────────────────── */

add_action( 'admin_menu', 'lla_add_menu' );
function lla_add_menu() {
    add_options_page(
        __( 'Alsiesta Limit Login Attempts', 'limit-login-attempts' ),
        __( 'Limit Logins', 'limit-login-attempts' ),
        'manage_options',
        'limit-login-attempts',
        'lla_settings_page'
    );
}

add_action( 'admin_init', 'lla_register_settings' );
function lla_register_settings() {
    register_setting( 'lla_settings_group', 'lla_max_attempts',      [ 'sanitize_callback' => 'absint' ] );
    register_setting( 'lla_settings_group', 'lla_notify_email',      [ 'sanitize_callback' => 'sanitize_email' ] );
    register_setting( 'lla_settings_group', 'lla_notify_on_lockout', [ 'sanitize_callback' => 'absint' ] );
}

/* Endpoint badge colours */
function lla_endpoint_badge( $endpoint ) {
    $colours = [
        'wp-login'    => '#2271b1',
        'xmlrpc'      => '#d63638',
        'rest-api'    => '#8c5e00',
        'woocommerce' => '#7f54b3',
        'wp-cron'     => '#555',
        'wp-comments' => '#1d6522',
    ];
    $bg = isset( $colours[ $endpoint ] ) ? $colours[ $endpoint ] : '#555';
    return sprintf(
        '<span style="background:%s;color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600;">%s</span>',
        esc_attr( $bg ),
        esc_html( $endpoint )
    );
}

function lla_settings_page() {
    global $wpdb;
    $attempts_table  = $wpdb->prefix . LLA_TABLE;
    $blacklist_table = $wpdb->prefix . LLA_BLACKLIST;
    $whitelist_table = $wpdb->prefix . LLA_WHITELIST;

    // — Actions —
    if ( isset( $_POST['lla_unblock_ip'] ) && check_admin_referer( 'lla_unblock', 'lla_nonce_unblock' ) ) {
        $wpdb->delete( $blacklist_table, [ 'ip_address' => sanitize_text_field( $_POST['lla_unblock_ip'] ) ] );
        echo '<div class="notice notice-success"><p>' . esc_html__( 'IP removed from blacklist.', 'limit-login-attempts' ) . '</p></div>';
    }
    if ( isset( $_POST['lla_manual_blacklist'] ) && check_admin_referer( 'lla_add_blacklist', 'lla_nonce_add' ) ) {
        $new_ip = sanitize_text_field( $_POST['lla_manual_ip'] );
        if ( filter_var( $new_ip, FILTER_VALIDATE_IP ) ) {
            lla_blacklist_ip( $new_ip, 'Manually blacklisted by admin' );
            echo '<div class="notice notice-success"><p>' . esc_html__( 'IP blacklisted.', 'limit-login-attempts' ) . '</p></div>';
        } else {
            echo '<div class="notice notice-error"><p>' . esc_html__( 'Invalid IP address.', 'limit-login-attempts' ) . '</p></div>';
        }
    }
    if ( isset( $_POST['lla_purge_all'] ) && check_admin_referer( 'lla_purge', 'lla_nonce_purge' ) ) {
        $wpdb->query( "TRUNCATE TABLE {$attempts_table}" );
        echo '<div class="notice notice-success"><p>' . esc_html__( 'Attempt log purged.', 'limit-login-attempts' ) . '</p></div>';
    }
    if ( isset( $_POST['lla_unwhitelist_ip'] ) && check_admin_referer( 'lla_unwhitelist', 'lla_nonce_unwhitelist' ) ) {
        $wpdb->delete( $whitelist_table, [ 'ip_address' => sanitize_text_field( $_POST['lla_unwhitelist_ip'] ) ] );
        echo '<div class="notice notice-success"><p>' . esc_html__( 'IP removed from whitelist.', 'limit-login-attempts' ) . '</p></div>';
    }
    if ( isset( $_POST['lla_manual_whitelist'] ) && check_admin_referer( 'lla_add_whitelist', 'lla_nonce_whitelist_add' ) ) {
        $new_ip = sanitize_text_field( $_POST['lla_whitelist_ip'] );
        if ( filter_var( $new_ip, FILTER_VALIDATE_IP ) ) {
            lla_whitelist_ip( $new_ip, 'Manually whitelisted by admin' );
            echo '<div class="notice notice-success"><p>' . esc_html__( 'IP whitelisted.', 'limit-login-attempts' ) . '</p></div>';
        } else {
            echo '<div class="notice notice-error"><p>' . esc_html__( 'Invalid IP address.', 'limit-login-attempts' ) . '</p></div>';
        }
    }

    $blacklist_rows = $wpdb->get_results( "SELECT * FROM {$blacklist_table} ORDER BY added_at DESC" );
    $whitelist_rows = $wpdb->get_results( "SELECT * FROM {$whitelist_table} ORDER BY added_at DESC" );
    $attempt_rows   = $wpdb->get_results( "SELECT * FROM {$attempts_table} ORDER BY last_attempt DESC LIMIT 50" );
    ?>
    <div class="wrap">
        <h1><?php esc_html_e( 'Limit Login Attempts', 'limit-login-attempts' ); ?></h1>

        <h2><?php esc_html_e( 'Settings', 'limit-login-attempts' ); ?></h2>
        <form method="post" action="options.php">
            <?php settings_fields( 'lla_settings_group' ); ?>
            <table class="form-table">
                <tr>
                    <th><?php esc_html_e( 'Failed attempts before blacklist', 'limit-login-attempts' ); ?></th>
                    <td>
                        <input type="number" name="lla_max_attempts"
                               value="<?php echo esc_attr( get_option( 'lla_max_attempts', 5 ) ); ?>"
                               min="1" max="100" />
                        <p class="description"><?php esc_html_e( 'After this many failures the IP is permanently blacklisted.', 'limit-login-attempts' ); ?></p>
                    </td>
                </tr>
                <tr>
                    <th><?php esc_html_e( 'Email notification', 'limit-login-attempts' ); ?></th>
                    <td>
                        <input type="checkbox" name="lla_notify_on_lockout" value="1"
                               <?php checked( 1, get_option( 'lla_notify_on_lockout', 1 ) ); ?> />
                        <?php esc_html_e( 'Send email when an IP is blacklisted', 'limit-login-attempts' ); ?>
                        <br>
                        <input type="email" name="lla_notify_email"
                               value="<?php echo esc_attr( get_option( 'lla_notify_email', get_option( 'admin_email' ) ) ); ?>"
                               style="width:280px;margin-top:6px;" />
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>

        <hr>
        <h2><?php esc_html_e( 'Whitelisted IPs', 'limit-login-attempts' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Whitelisted IPs are always allowed through — they are never counted, never blocked, and always override the blacklist.', 'limit-login-attempts' ); ?></p>
        <form method="post" style="margin-bottom:16px;">
            <?php wp_nonce_field( 'lla_add_whitelist', 'lla_nonce_whitelist_add' ); ?>
            <input type="text" name="lla_whitelist_ip" placeholder="e.g. 203.0.113.42" style="width:200px;" />
            <button type="submit" name="lla_manual_whitelist" class="button button-primary">
                <?php esc_html_e( 'Whitelist this IP', 'limit-login-attempts' ); ?>
            </button>
        </form>
        <?php if ( $whitelist_rows ) : ?>
            <table class="widefat striped" style="max-width:800px;">
                <thead><tr>
                    <th><?php esc_html_e( 'IP Address', 'limit-login-attempts' ); ?></th>
                    <th><?php esc_html_e( 'Reason', 'limit-login-attempts' ); ?></th>
                    <th><?php esc_html_e( 'Added At', 'limit-login-attempts' ); ?></th>
                    <th><?php esc_html_e( 'Action', 'limit-login-attempts' ); ?></th>
                </tr></thead>
                <tbody>
                <?php foreach ( $whitelist_rows as $row ) : ?>
                    <tr style="background:#f0fff0;">
                        <td><strong><?php echo esc_html( $row->ip_address ); ?></strong></td>
                        <td><?php echo esc_html( $row->reason ); ?></td>
                        <td><?php echo esc_html( $row->added_at ); ?></td>
                        <td>
                            <form method="post" style="display:inline;">
                                <?php wp_nonce_field( 'lla_unwhitelist', 'lla_nonce_unwhitelist' ); ?>
                                <input type="hidden" name="lla_unwhitelist_ip" value="<?php echo esc_attr( $row->ip_address ); ?>" />
                                <button type="submit" class="button button-small"
                                        onclick="return confirm('Remove this IP from the whitelist?');">
                                    <?php esc_html_e( 'Remove', 'limit-login-attempts' ); ?>
                                </button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php else : ?>
            <p><?php esc_html_e( 'No IPs are currently whitelisted.', 'limit-login-attempts' ); ?></p>
        <?php endif; ?>

        <hr>
        <h2><?php esc_html_e( 'Blacklisted IPs', 'limit-login-attempts' ); ?></h2>
        <form method="post" style="margin-bottom:16px;">
            <?php wp_nonce_field( 'lla_add_blacklist', 'lla_nonce_add' ); ?>
            <input type="text" name="lla_manual_ip" placeholder="e.g. 192.168.1.100" style="width:200px;" />
            <button type="submit" name="lla_manual_blacklist" class="button button-secondary">
                <?php esc_html_e( 'Blacklist this IP manually', 'limit-login-attempts' ); ?>
            </button>
        </form>
        <?php if ( $blacklist_rows ) : ?>
            <table class="widefat striped" style="max-width:800px;">
                <thead><tr>
                    <th><?php esc_html_e( 'IP Address', 'limit-login-attempts' ); ?></th>
                    <th><?php esc_html_e( 'Reason', 'limit-login-attempts' ); ?></th>
                    <th><?php esc_html_e( 'Blacklisted At', 'limit-login-attempts' ); ?></th>
                    <th><?php esc_html_e( 'Action', 'limit-login-attempts' ); ?></th>
                </tr></thead>
                <tbody>
                <?php foreach ( $blacklist_rows as $row ) : ?>
                    <tr>
                        <td><strong><?php echo esc_html( $row->ip_address ); ?></strong></td>
                        <td><?php echo esc_html( $row->reason ); ?></td>
                        <td><?php echo esc_html( $row->added_at ); ?></td>
                        <td>
                            <form method="post" style="display:inline;">
                                <?php wp_nonce_field( 'lla_unblock', 'lla_nonce_unblock' ); ?>
                                <input type="hidden" name="lla_unblock_ip" value="<?php echo esc_attr( $row->ip_address ); ?>" />
                                <button type="submit" class="button button-small"
                                        onclick="return confirm('Remove this IP from the blacklist?');">
                                    <?php esc_html_e( 'Remove', 'limit-login-attempts' ); ?>
                                </button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php else : ?>
            <p><?php esc_html_e( 'No IPs are currently blacklisted.', 'limit-login-attempts' ); ?></p>
        <?php endif; ?>

        <hr>
        <h2><?php esc_html_e( 'Recent Attempt Log (last 50)', 'limit-login-attempts' ); ?></h2>
        <p class="description"><?php esc_html_e( 'IPs that reach the threshold are moved to the blacklist and removed from this log automatically.', 'limit-login-attempts' ); ?></p>
        <?php if ( $attempt_rows ) : ?>
            <table class="widefat striped" style="max-width:800px;">
                <thead><tr>
                    <th><?php esc_html_e( 'IP Address', 'limit-login-attempts' ); ?></th>
                    <th><?php esc_html_e( 'Attempts', 'limit-login-attempts' ); ?></th>
                    <th><?php esc_html_e( 'Last Attempt', 'limit-login-attempts' ); ?></th>
                    <th><?php esc_html_e( 'Endpoint', 'limit-login-attempts' ); ?></th>
                </tr></thead>
                <tbody>
                <?php foreach ( $attempt_rows as $row ) : ?>
                    <tr>
                        <td><?php echo esc_html( $row->ip_address ); ?></td>
                        <td><?php echo esc_html( $row->attempts ); ?></td>
                        <td><?php echo esc_html( $row->last_attempt ); ?></td>
                        <td><?php echo lla_endpoint_badge( $row->last_endpoint ?? 'wp-login' ); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <form method="post" style="margin-top:12px;" onsubmit="return confirm('Purge the entire attempt log?');">
                <?php wp_nonce_field( 'lla_purge', 'lla_nonce_purge' ); ?>
                <button type="submit" name="lla_purge_all" class="button button-secondary">
                    <?php esc_html_e( 'Purge Attempt Log', 'limit-login-attempts' ); ?>
                </button>
            </form>
        <?php else : ?>
            <p><?php esc_html_e( 'No attempts recorded yet.', 'limit-login-attempts' ); ?></p>
        <?php endif; ?>

        <hr>
        <h2><?php esc_html_e( 'Endpoint Legend', 'limit-login-attempts' ); ?></h2>
        <p>
            <?php echo lla_endpoint_badge( 'wp-login' ); ?> <?php esc_html_e( 'Standard login form', 'limit-login-attempts' ); ?> &nbsp;
            <?php echo lla_endpoint_badge( 'xmlrpc' ); ?> <?php esc_html_e( 'XML-RPC (should be 0 if DLA Security active)', 'limit-login-attempts' ); ?> &nbsp;
            <?php echo lla_endpoint_badge( 'rest-api' ); ?> <?php esc_html_e( 'REST API application passwords', 'limit-login-attempts' ); ?> &nbsp;
            <?php echo lla_endpoint_badge( 'woocommerce' ); ?> <?php esc_html_e( 'WooCommerce login', 'limit-login-attempts' ); ?> &nbsp;
            <?php echo lla_endpoint_badge( 'wp-cron' ); ?> <?php esc_html_e( 'WP Cron', 'limit-login-attempts' ); ?>
        </p>
    </div>
    <?php
}
