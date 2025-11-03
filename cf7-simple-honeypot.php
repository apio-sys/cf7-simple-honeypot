<?php
/**
 * Plugin Name: Simple Honeypot for Contact Form 7
 * Plugin URI: https://github.com/apio-sys/cf7-simple-honeypot
 * Description: Simple Honeypot plugin for Contact Form 7 to reduce spam on form submissions without user interaction. Includes honeypot field, time-based validation, and content analysis. Store results in Flamingo.
 * Version: 0.9.1
 * Author: Joris Le Blansch
 * Author URI: https://apio.systems
 * License: MIT
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: cf7-simple-honeypot
 * Requires at least: 5.0
 * Requires PHP: 7.2
 * Requires Plugins: contact-form-7, flamingo
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

// Plugin version
define('CF7_SIMPLE_HONEYPOT_VERSION', '0.9.1');

// Get plugin option with default fallback
function cf7_simple_honeypot_get_option($key, $default = '') {
    $options = get_option('cf7_simple_honeypot_settings', array());
    return isset($options[$key]) ? $options[$key] : $default;
}

// Get default settings
function cf7_simple_honeypot_default_settings() {
    return array(
        'honeypot_field_name' => 'your-website',
        'max_urls' => 2,
        'max_caps_percentage' => 50,
        'min_words' => 3,
        'min_submit_time' => 5,
        'max_submit_time' => 3600,
        'spam_keywords' => "viagra\ncialis\npharmacy\nprescription\ncasino\npoker\nbetting\ngambling\nloan\nmortgage\ncrypto\nbitcoin\nforex\ninvestment opportunity\npassive income\ncash flow\nearning money\nearn money\nmake money\nmaking money\nthousands of dollars\nhundreds of dollars\nmoney flow\nclick here\nbuy now\nlimited offer\nact now\norder now\nvisit now\ncheck this out\nweight loss\nwork from home\nseo service\nseo services\nlink building\nincrease traffic\nbacklinks\nboost your ranking\nget more followers\ngrow your business\ninstagram followers\nfacebook likes\nyoutube views\nincrease followers\ngain followers\nreal deal\nskeptical at first\nevaluation copy\nthis system\namazing opportunity\nlimited time\ndon't miss out\nact fast\nspecial offer\ncongratulations\nyou've been selected\nclaim your\nrisk free\nmoney back guarantee\nno obligation",
        'message_field_names' => "your-message\nmessage\nyour-comment\ncomment"
    );
}

// Check if Contact Form 7 is active
function cf7_simple_honeypot_check_cf7() {
    if (!function_exists('wpcf7')) {
        add_action('admin_notices', 'cf7_simple_honeypot_cf7_missing_notice');
        deactivate_plugins(plugin_basename(__FILE__));
        if (isset($_GET['activate'])) {
            unset($_GET['activate']);
        }
    }
}
add_action('admin_init', 'cf7_simple_honeypot_check_cf7');

// Admin notice if Contact Form 7 is not installed
function cf7_simple_honeypot_cf7_missing_notice() {
    ?>
    <div class="notice notice-error">
        <p><?php _e('Contact Form 7 Simple Honeypot requires Contact Form 7 to be installed and activated.', 'cf7-simple-honeypot'); ?></p>
    </div>
    <?php
}

// Add admin menu under Contact
add_action('admin_menu', 'cf7_simple_honeypot_add_admin_menu');
function cf7_simple_honeypot_add_admin_menu() {
    add_submenu_page(
        'wpcf7',
        __('Simple Honeypot', 'cf7-simple-honeypot'),
        __('Simple Honeypot', 'cf7-simple-honeypot'),
        'manage_options',
        'cf7-simple-honeypot',
        'cf7_simple_honeypot_settings_page'
    );
}

// Link to settings from plugin list
add_filter( 'plugin_action_links_' . plugin_basename(__FILE__), 'apd_settings_link' );
function apd_settings_link( array $links ) {
    $url = get_admin_url() . "admin.php?page=cf7-simple-honeypot";
    $settings_link = '<a href="' . $url . '">' . __('Settings', 'cf7-simple-honeypot') . '</a>';
      $links[] = $settings_link;
    return $links;
}

// Register settings
add_action('admin_init', 'cf7_simple_honeypot_register_settings');
function cf7_simple_honeypot_register_settings() {
    register_setting('cf7_simple_honeypot_settings', 'cf7_simple_honeypot_settings', 'cf7_simple_honeypot_sanitize_settings');
}

// Sanitize settings
function cf7_simple_honeypot_sanitize_settings($input) {
    $sanitized = array();
    $sanitized['honeypot_field_name'] = sanitize_text_field($input['honeypot_field_name']);
    $sanitized['max_urls'] = absint($input['max_urls']);
    $sanitized['max_caps_percentage'] = absint($input['max_caps_percentage']);
    $sanitized['min_words'] = absint($input['min_words']);
    $sanitized['min_submit_time'] = absint($input['min_submit_time']);
    $sanitized['max_submit_time'] = absint($input['max_submit_time']);
    $sanitized['spam_keywords'] = sanitize_textarea_field($input['spam_keywords']);
    $sanitized['message_field_names'] = sanitize_textarea_field($input['message_field_names']);
    return $sanitized;
}

// Settings page
function cf7_simple_honeypot_settings_page() {
    // Get current settings or defaults
    $options = get_option('cf7_simple_honeypot_settings', cf7_simple_honeypot_default_settings());
    ?>
    <div class="wrap">
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
        <div class="notice notice-info">
            <h3><?php _e('How to Use', 'cf7-simple-honeypot'); ?></h3>
            <p><?php _e('Add the following shortcodes to your Contact Form 7 forms:', 'cf7-simple-honeypot'); ?></p>
            <p><code>[honeypot]</code> - <?php _e('Adds the hidden honeypot field', 'cf7-simple-honeypot'); ?></p>
            <p><code>[timestamp]</code> - <?php _e('Adds time-based validation', 'cf7-simple-honeypot'); ?></p>
            <p><strong><?php _e('Example form:', 'cf7-simple-honeypot'); ?></strong></p>
            <pre style="background: #f5f5f5; padding: 10px; border: 1px solid #ddd;">
&lt;label&gt; Your Name
    [text* your-name] &lt;/label&gt;

&lt;label&gt; Your Email
    [email* your-email] &lt;/label&gt;

&lt;label&gt; Your Message
    [textarea your-message] &lt;/label&gt;

[honeypot]
[timestamp]

[submit "Send"]</pre>
        </div>
        <form method="post" action="options.php">
            <?php settings_fields('cf7_simple_honeypot_settings'); ?>
            <table class="form-table">
                <tr>
                    <th colspan="2"><h2><?php _e('Honeypot Settings', 'cf7-simple-honeypot'); ?></h2></th>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="honeypot_field_name"><?php _e('Honeypot Field Name', 'cf7-simple-honeypot'); ?></label>
                    </th>
                    <td>
                        <input type="text" id="honeypot_field_name" name="cf7_simple_honeypot_settings[honeypot_field_name]" value="<?php echo esc_attr($options['honeypot_field_name']); ?>" class="regular-text" />
                        <p class="description"><?php _e('The name of the hidden field. Use CF7-style names (e.g., your-website, your-company)', 'cf7-simple-honeypot'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th colspan="2"><h2><?php _e('Time-Based Validation', 'cf7-simple-honeypot'); ?></h2></th>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="min_submit_time"><?php _e('Minimum Submit Time (seconds)', 'cf7-simple-honeypot'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="min_submit_time" name="cf7_simple_honeypot_settings[min_submit_time]" value="<?php echo esc_attr($options['min_submit_time']); ?>" min="1" max="60" class="small-text" />
                        <p class="description"><?php _e('Forms submitted faster than this will be marked as spam (recommended: 3-5 seconds)', 'cf7-simple-honeypot'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="max_submit_time"><?php _e('Maximum Submit Time (seconds)', 'cf7-simple-honeypot'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="max_submit_time" name="cf7_simple_honeypot_settings[max_submit_time]" value="<?php echo esc_attr($options['max_submit_time']); ?>" min="300" max="7200" class="small-text" />
                        <p class="description"><?php _e('Forms older than this will be marked as spam (recommended: 3600 = 1 hour)', 'cf7-simple-honeypot'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th colspan="2"><h2><?php _e('Content Analysis Settings', 'cf7-simple-honeypot'); ?></h2></th>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="message_field_names"><?php _e('Message Field Names', 'cf7-simple-honeypot'); ?></label>
                    </th>
                    <td>
                        <textarea id="message_field_names" name="cf7_simple_honeypot_settings[message_field_names]" rows="4" class="large-text"><?php echo esc_textarea($options['message_field_names']); ?></textarea>
                        <p class="description"><?php _e('One field name per line. These are the fields that will be analyzed for spam content.', 'cf7-simple-honeypot'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="max_urls"><?php _e('Maximum URLs Allowed', 'cf7-simple-honeypot'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="max_urls" name="cf7_simple_honeypot_settings[max_urls]" value="<?php echo esc_attr($options['max_urls']); ?>" min="0" max="10" class="small-text" />
                        <p class="description"><?php _e('Messages with more URLs than this will be marked as spam', 'cf7-simple-honeypot'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="max_caps_percentage"><?php _e('Maximum Uppercase Percentage', 'cf7-simple-honeypot'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="max_caps_percentage" name="cf7_simple_honeypot_settings[max_caps_percentage]" value="<?php echo esc_attr($options['max_caps_percentage']); ?>" min="0" max="100" class="small-text" />%
                        <p class="description"><?php _e('Messages with more uppercase letters than this percentage will be marked as spam', 'cf7-simple-honeypot'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="min_words"><?php _e('Minimum Word Count', 'cf7-simple-honeypot'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="min_words" name="cf7_simple_honeypot_settings[min_words]" value="<?php echo esc_attr($options['min_words']); ?>" min="1" max="20" class="small-text" />
                        <p class="description"><?php _e('Messages with fewer words than this will be marked as spam', 'cf7-simple-honeypot'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="spam_keywords"><?php _e('Spam Keywords', 'cf7-simple-honeypot'); ?></label>
                    </th>
                    <td>
                        <textarea id="spam_keywords" name="cf7_simple_honeypot_settings[spam_keywords]" rows="15" class="large-text code"><?php echo esc_textarea($options['spam_keywords']); ?></textarea>
                        <p class="description"><?php _e('One keyword or phrase per line. Messages containing any of these will be marked as spam. Case-insensitive.', 'cf7-simple-honeypot'); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}

// Add honeypot field to CF7 forms
add_action('wpcf7_init', 'cf7_simple_honeypot_add_shortcode');
function cf7_simple_honeypot_add_shortcode() {
    wpcf7_add_form_tag('honeypot', 'cf7_simple_honeypot_handler');
}

// Handle the honeypot shortcode
function cf7_simple_honeypot_handler($tag) {
    $field_name = cf7_simple_honeypot_get_option('honeypot_field_name', 'your-website');
    $html = sprintf(
        '<span class="wpcf7-form-control-wrap" data-name="%1$s" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden;">
            <label>Website (optional)</label>
            <input type="text" name="%1$s" value="" size="40" class="wpcf7-form-control" tabindex="-1" autocomplete="off" aria-hidden="true" />
        </span>',
        esc_attr($field_name)
    );
    return $html;
}

// Validate honeypot on form submission
add_filter('wpcf7_spam', 'cf7_simple_honeypot_validation', 10, 2);
function cf7_simple_honeypot_validation($spam, $submission) {
    // If already marked as spam, return early
    if ($spam) {
        return $spam;
    }
    $data = $submission->get_posted_data();
    $field_name = cf7_simple_honeypot_get_option('honeypot_field_name', 'your-website');
    // Check if honeypot field exists and has a value
    if (isset($data[$field_name]) && !empty($data[$field_name])) {
        // Honeypot was filled - this is spam
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'honeypot',
            'reason' => __('Honeypot field was filled', 'cf7-simple-honeypot')
        ));
    }
    return $spam;
}

// Add time-based check
add_action('wpcf7_init', 'cf7_simple_honeypot_add_timestamp');
function cf7_simple_honeypot_add_timestamp() {
    wpcf7_add_form_tag('timestamp', 'cf7_simple_honeypot_timestamp_handler');
}

// Handle timestamp field
function cf7_simple_honeypot_timestamp_handler($tag) {
    $timestamp = time();
    $html = sprintf(
        '<input type="hidden" name="cf7_timestamp" value="%s" />',
        esc_attr($timestamp)
    );
    return $html;
}

// Validate timestamp
add_filter('wpcf7_spam', 'cf7_simple_honeypot_timestamp_validation', 10, 2);
function cf7_simple_honeypot_timestamp_validation($spam, $submission) {
    // If already marked as spam, return early
    if ($spam) {
        return $spam;
    }
    $data = $submission->get_posted_data();
    if (!isset($data['cf7_timestamp'])) {
        // No timestamp found - mark as spam
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'timestamp',
            'reason' => __('Timestamp field missing', 'cf7-simple-honeypot')
        ));
        return $spam;
    }
    $timestamp = intval($data['cf7_timestamp']);
    $time_elapsed = time() - $timestamp;
    $min_time = cf7_simple_honeypot_get_option('min_submit_time', 5);
    $max_time = cf7_simple_honeypot_get_option('max_submit_time', 3600);
    // Form submitted too quickly
    if ($time_elapsed < $min_time) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'timestamp',
            'reason' => sprintf(__('Form submitted too quickly (%d seconds)', 'cf7-simple-honeypot'), $time_elapsed)
        ));
        return $spam;
    }
    // Form took too long
    if ($time_elapsed > $max_time) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'timestamp',
            'reason' => sprintf(__('Form session expired (%d seconds old)', 'cf7-simple-honeypot'), $time_elapsed)
        ));
        return $spam;
    }
    return $spam;
}

// Content analysis spam detection
add_filter('wpcf7_spam', 'cf7_simple_honeypot_content_analysis', 10, 2);
function cf7_simple_honeypot_content_analysis($spam, $submission) {
    // If already marked as spam, return early
    if ($spam) {
        return $spam;
    }
    $data = $submission->get_posted_data();
    // Get message field names from settings
    $field_names_str = cf7_simple_honeypot_get_option('message_field_names', "your-message\nmessage\nyour-comment\ncomment");
    $message_fields = array_filter(array_map('trim', explode("\n", $field_names_str)));
    $message = '';
    foreach ($message_fields as $field) {
        if (isset($data[$field]) && !empty($data[$field])) {
            $message = $data[$field];
            break;
        }
    }
    // If no message field found, skip content analysis
    if (empty($message)) {
        return $spam;
    }
    // 1. Check for excessive URLs
    $max_urls = cf7_simple_honeypot_get_option('max_urls', 2);
    $url_count = preg_match_all('/https?:\/\/[^\s]+/i', $message);
    if ($url_count > $max_urls) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'content-analysis',
            'reason' => sprintf(__('Too many URLs in message (%d found, max %d allowed)', 'cf7-simple-honeypot'), $url_count, $max_urls)
        ));
        return $spam;
    }
    // 2. Check for excessive uppercase
    $max_caps = cf7_simple_honeypot_get_option('max_caps_percentage', 50);
    $letters_only = preg_replace('/[^a-zA-Z]/', '', $message);
    if (strlen($letters_only) > 10) {
        $uppercase_count = strlen(preg_replace('/[^A-Z]/', '', $letters_only));
        $caps_percentage = ($uppercase_count / strlen($letters_only)) * 100;
        if ($caps_percentage > $max_caps) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'content-analysis',
                'reason' => sprintf(__('Excessive uppercase text (%.0f%% caps, max %d%% allowed)', 'cf7-simple-honeypot'), $caps_percentage, $max_caps)
            ));
            return $spam;
        }
    }
    // 3. Check for minimum word count
    $min_words = cf7_simple_honeypot_get_option('min_words', 3);
    $word_count = str_word_count($message);
    if ($word_count < $min_words) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'content-analysis',
            'reason' => sprintf(__('Message too short (%d words, min %d required)', 'cf7-simple-honeypot'), $word_count, $min_words)
        ));
        return $spam;
    }
    // 4. Check for spam keywords
    $keywords_str = cf7_simple_honeypot_get_option('spam_keywords', '');
    $spam_keywords = array_filter(array_map('trim', explode("\n", $keywords_str)));
    $message_lower = strtolower($message);
    foreach ($spam_keywords as $keyword) {
        if (strpos($message_lower, strtolower($keyword)) !== false) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'content-analysis',
                'reason' => sprintf(__('Spam keyword detected: "%s"', 'cf7-simple-honeypot'), $keyword)
            ));
            return $spam;
        }
    }
    // 5. Check for repetitive patterns
    if (preg_match('/(.)\1{5,}/', $message) || preg_match('/(.{2,})\1{3,}/', $message)) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'content-analysis',
            'reason' => __('Repetitive text pattern detected', 'cf7-simple-honeypot')
        ));
        return $spam;
    }
    // 6. Check for excessive special characters
    $special_char_count = preg_match_all('/[^a-zA-Z0-9\s.,!?\-\'"()]/', $message);
    $total_chars = strlen($message);
    if ($total_chars > 0) {
        $special_char_percentage = ($special_char_count / $total_chars) * 100;
        if ($special_char_percentage > 30) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'content-analysis',
                'reason' => sprintf(__('Excessive special characters (%.0f%% of message)', 'cf7-simple-honeypot'), $special_char_percentage)
            ));
            return $spam;
        }
    }
    return $spam;
}

// Add custom CSS to ensure honeypot is completely hidden
add_action('wp_head', 'cf7_simple_honeypot_css');
function cf7_simple_honeypot_css() {
    $field_name = cf7_simple_honeypot_get_option('honeypot_field_name', 'your-website');
    echo '<style>
        .wpcf7-form-control-wrap[data-name="' . esc_attr($field_name) . '"] {
            position: absolute !important;
            left: -9999px !important;
            width: 1px !important;
            height: 1px !important;
            overflow: hidden !important;
            opacity: 0 !important;
            pointer-events: none !important;
        }
    </style>';
}
