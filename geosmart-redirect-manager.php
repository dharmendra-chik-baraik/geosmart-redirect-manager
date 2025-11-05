<?php

/**
 * Plugin Name: GeoSmart Redirect Manager
 * Plugin URI:  https://wordpress.org/plugins/geosmart-redirect-manager
 * Description: Redirect visitors based on country or IP with whitelist and admin log viewer.
 * Version:     1.0.0
 * Author:      Dharmendra Chik Baraik

 * Author URI:  https://wordpress.org/plugins/geosmart-redirect-manager
 * License:     GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: geosmart-redirect-manager
 */

if (!defined('ABSPATH')) {
    exit;
}

final class GeoSmart_Redirect_Manager
{

    const OPTION_KEY = 'gsrm_settings';
    const LOG_FILE = 'gsrm-redirect-log.txt';
    const VERSION = '1.0.0';

    private $plugin_dir;
    private $log_path;

    public function __construct()
    {
        $this->plugin_dir = plugin_dir_path(__FILE__);
        $this->log_path = $this->plugin_dir . self::LOG_FILE;

        // Admin
        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('admin_init', [$this, 'maybe_handle_log_actions']);

        // Frontend redirect
        add_action('template_redirect', [$this, 'maybe_redirect']);
        add_action('admin_head', [$this, 'admin_custom_css']);
        // Activation/Deactivation/Uninstall
        register_activation_hook(__FILE__, [$this, 'on_activate']);
        register_deactivation_hook(__FILE__, [$this, 'on_deactivate']);
        register_uninstall_hook(__FILE__, ['GeoSmart_Redirect_Manager', 'on_uninstall']);
    }

    // ------------------------
    // Activation: create defaults and log
    // ------------------------
    public function on_activate()
    {
        $defaults = [
            'enabled'       => '1',
            'country_rules' => "US=https://example-us.com\nIN=https://example-in.com",
            'ip_rules'      => "203.0.113.10=https://example-vip.com",
            'whitelist'     => "127.0.0.1\n::1",
        ];

        if (get_option(self::OPTION_KEY) === false) {
            add_option(self::OPTION_KEY, $defaults);
        }

        if (!file_exists($this->log_path)) {
            @file_put_contents($this->log_path, "=== GeoSmart Redirect Manager Log ===\nActivated: " . date('Y-m-d H:i:s') . "\n\n");
        }
    }

    // ------------------------
    // Deactivation: log
    // ------------------------
    public function on_deactivate()
    {
        @file_put_contents($this->log_path, "Plugin deactivated on: " . date('Y-m-d H:i:s') . "\n", FILE_APPEND);
    }

    // ------------------------
    // Uninstall: remove options and log entry
    // ------------------------
    public static function on_uninstall()
    {
        delete_option(self::OPTION_KEY);
        $log = plugin_dir_path(__FILE__) . self::LOG_FILE;
        @file_put_contents($log, "Plugin uninstalled on: " . date('Y-m-d H:i:s') . "\n", FILE_APPEND);
    }

    // ------------------------
    // Admin Menu & Page
    // ------------------------
    public function admin_menu()
    {
        add_menu_page(
            __('GeoSmart Redirect', 'geosmart-redirect-manager'),
            __('Geo Redirect', 'geosmart-redirect-manager'),
            'manage_options',
            'gsrm-settings',
            [$this, 'render_admin_page'],
            'dashicons-location-alt',
            81
        );
    }

    // Handle Clear Log / Download / other admin actions
    public function maybe_handle_log_actions()
    {
        if (!current_user_can('manage_options')) return;
        if (!isset($_GET['page']) || $_GET['page'] !== 'gsrm-settings') return;

        // Clear log
        if (isset($_POST['gsrm_clear_log']) && check_admin_referer('gsrm_clear_log_nonce')) {
            @file_put_contents($this->log_path, "=== GeoSmart Redirect Manager Log ===\nCleared: " . date('Y-m-d H:i:s') . "\n\n");
            add_action('admin_notices', function () {
                echo '<div class="updated"><p>Log cleared.</p></div>';
            });
        }

        // Download log
        if (isset($_POST['gsrm_download_log']) && check_admin_referer('gsrm_download_log_nonce')) {
            if (file_exists($this->log_path)) {
                header('Content-Type: text/plain');
                header('Content-Disposition: attachment; filename="' . basename($this->log_path) . '"');
                readfile($this->log_path);
                exit;
            } else {
                add_action('admin_notices', function () {
                    echo '<div class="error"><p>Log file not found.</p></div>';
                });
            }
        }
    }

    // ------------------------
    // Render Admin Page
    // ------------------------
    public function render_admin_page()
    {
        if (!current_user_can('manage_options')) return;

        $settings = get_option(self::OPTION_KEY, [
            'enabled' => '1',
            'country_rules' => '',
            'ip_rules' => '',
            'whitelist' => '',
        ]);

        // Save settings
        if (isset($_POST['gsrm_save']) && check_admin_referer('gsrm_save_nonce')) {
            $settings['enabled'] = isset($_POST['enabled']) ? '1' : '0';
            $settings['country_rules'] = isset($_POST['country_rules']) ? sanitize_textarea_field($_POST['country_rules']) : '';
            $settings['ip_rules'] = isset($_POST['ip_rules']) ? sanitize_textarea_field($_POST['ip_rules']) : '';
            $settings['whitelist'] = isset($_POST['whitelist']) ? sanitize_textarea_field($_POST['whitelist']) : '';
            update_option(self::OPTION_KEY, $settings);
            echo '<div class="updated"><p><strong>Settings saved.</strong></p></div>';
        }

        // Values for the form
        $enabled = $settings['enabled'] ?? '0';
        $country_rules = $settings['country_rules'] ?? '';
        $ip_rules = $settings['ip_rules'] ?? '';
        $whitelist = $settings['whitelist'] ?? '';

        // Read log tail
        $log_tail = '';
        if (file_exists($this->log_path)) {
            $log_contents = @file_get_contents($this->log_path);
            if ($log_contents !== false) {
                // show last ~8000 chars to avoid huge output
                $log_tail = mb_substr($log_contents, -8000);
            }
        }
?>
        <div class="wrap">
            <h1>GeoSmart Redirect Manager</h1>

            <form method="post" style="max-width:1000px;">
                <?php wp_nonce_field('gsrm_save_nonce'); ?>

                <h2>Plugin Status</h2>
                <label>
                    <input type="checkbox" name="enabled" value="1" <?php checked($enabled, '1'); ?>>
                    Enable Redirects
                </label>
                <p class="description">Uncheck to temporarily disable all redirects.</p>
                <hr>

                <h2>Country-based Redirects</h2>
                <p class="description">One rule per line. Format: <code>IN=https://in.armadapos.com</code> (Country code = ISO 3166-1 alpha-2).</p>
                <textarea name="country_rules" rows="6" style="width:100%;"><?php echo esc_textarea($country_rules); ?></textarea>

                <h2>IP-based Redirects</h2>
                <p class="description">One rule per line. Format: <code>203.0.113.45=https://example.com/path</code></p>
                <textarea name="ip_rules" rows="6" style="width:100%;"><?php echo esc_textarea($ip_rules); ?></textarea>

                <h2>Whitelist IPs (Skip Redirect)</h2>
                <p class="description">One IP per line — these IPs will never be redirected (useful for devs / testing).</p>
                <textarea name="whitelist" rows="4" style="width:100%;"><?php echo esc_textarea($whitelist); ?></textarea>

                <p style="margin-top: 12px;">
                    <button type="submit" name="gsrm_save" class="button button-primary">💾 Save Settings</button>
                </p>
            </form>

            <hr>
            <h2>Logs</h2>
            <form method="post" style="display:inline-block;">
                <?php wp_nonce_field('gsrm_clear_log_nonce'); ?>
                <button type="submit" name="gsrm_clear_log" class="button">Clear Log</button>
            </form>

            <form method="post" style="display:inline-block; margin-left:10px;">
                <?php wp_nonce_field('gsrm_download_log_nonce'); ?>
                <button type="submit" name="gsrm_download_log" class="button">Download Log</button>
            </form>

            <h3 style="margin-top:18px;">Recent Log (tail)</h3>
            <pre style="background:#fff; border:1px solid #ddd; padding:12px; max-height:400px; overflow:auto;"><?php echo esc_textarea($log_tail ?: "Log file empty."); ?></pre>

            <p class="description">Log file path: <code><?php echo esc_html($this->log_path); ?></code></p>
        </div>
    <?php
    }

    // ------------------------
    // Redirect logic
    // ------------------------
    public function maybe_redirect()
    {
        if (
            is_admin()
            || wp_doing_ajax()
            || (defined('REST_REQUEST') && REST_REQUEST)
            || (defined('WP_CLI') && WP_CLI)
            || php_sapi_name() === 'cli'
            || strpos($_SERVER['REQUEST_URI'], '/wp-login.php') !== false
            || strpos($_SERVER['REQUEST_URI'], '/wp-admin') !== false
        ) {
            return;
        }

        $settings = get_option(self::OPTION_KEY, [
            'enabled' => '0',
            'country_rules' => '',
            'ip_rules' => '',
            'whitelist' => '',
        ]);

        if (!isset($settings['enabled']) || $settings['enabled'] !== '1') {
            return; // disabled
        }

        $ip = $this->get_visitor_ip();
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $host = $_SERVER['HTTP_HOST'] ?? '';
        $current_url = (is_ssl() ? 'https://' : 'http://') . $host . $uri;

        // Normalize rules into arrays
        $whitelist = $this->lines_to_array($settings['whitelist']);
        if (in_array($ip, $whitelist, true)) {
            $this->log("[$ip] Whitelisted - skip redirect");
            return;
        }

        // IP rules first
        $ip_rules_lines = $this->lines_to_array($settings['ip_rules']);
        foreach ($ip_rules_lines as $line) {
            if (strpos($line, '=') === false) continue;
            list($match_ip, $target) = array_map('trim', explode('=', $line, 2));
            if ($match_ip === $ip && !empty($target)) {
                $target = $this->normalize_url($target);
                if ($target && $target !== $current_url) {
                    $this->log("[$ip] IP rule matched. Redirecting to: $target");
                    wp_safe_redirect($target, 302);
                    exit;
                } else {
                    $this->log("[$ip] IP rule matched but target same as current or invalid: $target");
                }
            }
        }

        // Country rules
        $country = $this->detect_country_by_ip($ip);
        if ($country) {
            $country_rules_lines = $this->lines_to_array($settings['country_rules']);
            foreach ($country_rules_lines as $line) {
                if (strpos($line, '=') === false) continue;
                list($code, $target) = array_map('trim', explode('=', $line, 2));
                if (strtoupper($code) === strtoupper($country) && !empty($target)) {
                    $target = $this->normalize_url($target) . $uri; // preserve path
                    if ($target && $target !== $current_url) {
                        $this->log("[$ip] ($country) Country rule matched. Redirecting to: $target");
                        wp_safe_redirect($target, 302);
                        exit;
                    } else {
                        $this->log("[$ip] ($country) Country rule matched but target same as current or invalid: $target");
                    }
                }
            }
        } else {
            $this->log("[$ip] Country detection failed or empty.");
        }
    }

    // ------------------------
    // Helpers
    // ------------------------
    private function get_visitor_ip()
    {
        // Basic approach. If you are behind proxy, you might want to adapt this.
        $keys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
        foreach ($keys as $k) {
            if (!empty($_SERVER[$k])) {
                // HTTP_X_FORWARDED_FOR can contain comma-separated IPs
                $ip = $_SERVER[$k];
                if (strpos($ip, ',') !== false) {
                    $parts = array_map('trim', explode(',', $ip));
                    $ip = $parts[0];
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return '0.0.0.0';
    }

    private function detect_country_by_ip($ip)
    {
        if (empty($ip) || $ip === '0.0.0.0') return '';

        // Use ipapi.co (free, no key for basic usage). You can change to another provider.
        $url = "https://ipapi.co/{$ip}/country/";

        $response = wp_remote_get($url, [
            'timeout' => 5,
            'sslverify' => true,
        ]);

        if (is_wp_error($response)) {
            $this->log("[$ip] ipapi request error: " . $response->get_error_message());
            return '';
        }

        $body = wp_remote_retrieve_body($response);
        $body = trim($body);

        if ($body && preg_match('/^[A-Z]{2}$/i', $body)) {
            return strtoupper($body);
        }

        return '';
    }

    private function lines_to_array($text)
    {
        $lines = preg_split('/\r\n|\r|\n/', trim($text));
        $result = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line !== '') $result[] = $line;
        }
        return $result;
    }

    private function normalize_url($url)
    {
        // If relative path provided, force to full URL? For now, accept absolute URLs only.
        $url = trim($url);
        if (empty($url)) return '';
        // If missing scheme, assume https
        if (!preg_match('#^https?://#i', $url)) {
            $url = 'https://' . ltrim($url, '/');
        }
        // Validate
        return filter_var($url, FILTER_VALIDATE_URL) ? $url : '';
    }

    private function log($message)
    {
        $time = date('Y-m-d H:i:s');
        @file_put_contents($this->log_path, "[$time] $message\n", FILE_APPEND);
    }
    public function admin_custom_css()
    {
        $screen = get_current_screen();
        if (isset($screen->id) && $screen->id !== 'toplevel_page_gsrm-settings') return;

    ?>
        <style>
            .wrap h1 {
                display: flex;
                align-items: center;
                font-size: 28px;
                font-weight: 700;
                color: #1d2327;
                margin-bottom: 24px;
                text-transform: uppercase;
            }

            .wrap h2,
            .wrap h1 {
                color: #2271b1;
                border-left: 4px solid #2271b1;
                padding-left: 10px;
                margin-top: 28px;
                font-size: 20px;
            }

            .description {
                color: #666;
                font-size: 13px;
                margin: 4px 0 8px;
            }

            textarea {
                background: #f9fafb;
                border: 1px solid #ccd0d4;
                border-radius: 6px;
                font-family: monospace;
                font-size: 13px;
                width: 100%;
                box-sizing: border-box;
                padding: 10px;
                transition: all 0.2s ease-in-out;
            }

            textarea:focus {
                background: #fff;
                border-color: #2271b1;
                box-shadow: 0 0 0 2px rgba(34, 113, 177, 0.2);
                outline: none;
            }

            button.button-primary {
                background-color: #2271b1;
                border-color: #135e96;
                font-weight: 600;
                padding: 6px 16px;
                border-radius: 4px;
                transition: all 0.2s ease;
            }

            button.button-primary:hover {
                background-color: #135e96;
            }

            button.button {
                background-color: #f6f7f7;
                border-color: #ccd0d4;
                border-radius: 4px;
                font-weight: 500;
                transition: all 0.2s ease;
            }

            button.button:hover {
                background-color: #e9ecef;
            }

            pre {
                background: #ffffff;
                border: 1px solid #ccd0d4;
                border-radius: 6px;
                padding: 14px;
                font-size: 13px;
                font-family: "Courier New", monospace;
                color: #111;
                overflow-x: auto;
                line-height: 1.45;
                box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.05);
            }

            code {
                background: #f3f4f6;
                padding: 2px 6px;
                border-radius: 4px;
                font-size: 13px;
            }

            hr {
                border: none;
                border-top: 1px solid #e2e4e7;
                margin: 30px 0;
            }

            .wrap label {
                font-weight: 500;
                display: inline-block;
                margin-bottom: 6px;
            }

            .wrap {
                background: #fff;
                border: 1px solid #ccd0d4;
                border-radius: 8px;
                padding: 20px;
                box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
                margin-bottom: 30px;
            }

            .wrap p.description code {
                background: #eef3fa;
                color: #135e96;
            }

            @media (max-width: 782px) {
                textarea {
                    font-size: 14px;
                    padding: 8px;
                }

                .wrap h2 {
                    font-size: 18px;
                }
            }
        </style>
<?php
    }
}

// Init plugin
new GeoSmart_Redirect_Manager();
