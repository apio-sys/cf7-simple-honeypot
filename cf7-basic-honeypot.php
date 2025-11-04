<?php
/**
 * Plugin Name: Basic Honeypot for Contact Form 7
 * Plugin URI: https://github.com/apio-sys/cf7-basic-honeypot
 * Description: Basic Honeypot plugin for Contact Form 7 to drastically reduce spam on form submissions without user interaction. Includes honeypot field, time-based validation, and content analysis. Store results in Flamingo.
 * Version: 0.9.1
 * Author: Joris Le Blansch
 * Author URI: https://apio.systems
 * License: MIT
 * License URI: https://github.com/apio-sys/cf7-basic-honeypot/blob/main/LICENSE
 * Text Domain: cf7-basic-honeypot
 * Requires at least: 6.5
 * Requires PHP: 7.2
 * Requires Plugins: contact-form-7, flamingo
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

// Get plugin option with default fallback
function cf7_basic_honeypot_get_option($key, $default = '') {
    $options = get_option('cf7_basic_honeypot_settings', array());
    return isset($options[$key]) ? $options[$key] : $default;
}

// Get default settings
function cf7_basic_honeypot_default_settings() {
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

// Add admin menu under Contact
add_action('admin_menu', 'cf7_basic_honeypot_add_admin_menu');
function cf7_basic_honeypot_add_admin_menu() {
    add_submenu_page(
        'wpcf7',
        __('Basic Honeypot', 'cf7-basic-honeypot'),
        __('Basic Honeypot', 'cf7-basic-honeypot'),
        'manage_options',
        'cf7-basic-honeypot',
        'cf7_basic_honeypot_settings_page'
    );
}

// Link to settings from plugin list
add_filter( 'plugin_action_links_' . plugin_basename(__FILE__), 'cf7_basic_honeypot_settings_link' );
function cf7_basic_honeypot_settings_link( array $links ) {
    $url = get_admin_url() . "admin.php?page=cf7-basic-honeypot";
    $settings_link = '<a href="' . $url . '">' . __('Settings', 'cf7-basic-honeypot') . '</a>';
      $links[] = $settings_link;
    return $links;
}

// Register settings
add_action('admin_init', 'cf7_basic_honeypot_register_settings');
function cf7_basic_honeypot_register_settings() {
    register_setting('cf7_basic_honeypot_settings', 'cf7_basic_honeypot_settings', 'cf7_basic_honeypot_sanitize_settings');
}

// Sanitize settings
function cf7_basic_honeypot_sanitize_settings($input) {
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
function cf7_basic_honeypot_settings_page() {
    // Get current settings or defaults
    $options = get_option('cf7_basic_honeypot_settings', cf7_basic_honeypot_default_settings());
    ?>
    <div class="wrap">
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
        <div class="notice notice-info">
            <h3><?php esc_html_e('How to Use', 'cf7-basic-honeypot'); ?></h3>
            <p><?php esc_html_e('Add the following shortcodes to your Contact Form 7 forms:', 'cf7-basic-honeypot'); ?></p>
            <p><code>[honeypot]</code> - <?php esc_html_e('Adds the hidden honeypot field', 'cf7-basic-honeypot'); ?></p>
            <p><code>[timestamp]</code> - <?php esc_html_e('Adds time-based validation', 'cf7-basic-honeypot'); ?></p>
            <p><strong><?php esc_html_e('Example form:', 'cf7-basic-honeypot'); ?></strong></p>
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
            <?php settings_fields('cf7_basic_honeypot_settings'); ?>
            <table class="form-table">
                <tr>
                    <th colspan="2"><h2><?php esc_html_e('Honeypot Settings', 'cf7-basic-honeypot'); ?></h2></th>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="honeypot_field_name"><?php esc_html_e('Honeypot Field Name', 'cf7-basic-honeypot'); ?></label>
                    </th>
                    <td>
                        <input type="text" id="honeypot_field_name" name="cf7_basic_honeypot_settings[honeypot_field_name]" value="<?php echo esc_attr($options['honeypot_field_name']); ?>" class="regular-text" />
                        <p class="description"><?php esc_html_e('The name of the hidden field. Use CF7-style names (e.g., your-website, your-company)', 'cf7-basic-honeypot'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th colspan="2"><h2><?php esc_html_e('Time-Based Validation', 'cf7-basic-honeypot'); ?></h2></th>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="min_submit_time"><?php esc_html_e('Minimum Submit Time (seconds)', 'cf7-basic-honeypot'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="min_submit_time" name="cf7_basic_honeypot_settings[min_submit_time]" value="<?php echo esc_attr($options['min_submit_time']); ?>" min="1" max="60" class="small-text" />
                        <p class="description"><?php esc_html_e('Forms submitted faster than this will be marked as spam (recommended: 3-5 seconds)', 'cf7-basic-honeypot'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="max_submit_time"><?php esc_html_e('Maximum Submit Time (seconds)', 'cf7-basic-honeypot'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="max_submit_time" name="cf7_basic_honeypot_settings[max_submit_time]" value="<?php echo esc_attr($options['max_submit_time']); ?>" min="300" max="7200" class="small-text" />
                        <p class="description"><?php esc_html_e('Forms older than this will be marked as spam (recommended: 3600 = 1 hour)', 'cf7-basic-honeypot'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th colspan="2"><h2><?php esc_html_e('Content Analysis Settings', 'cf7-basic-honeypot'); ?></h2></th>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="message_field_names"><?php esc_html_e('Message Field Names', 'cf7-basic-honeypot'); ?></label>
                    </th>
                    <td>
                        <textarea id="message_field_names" name="cf7_basic_honeypot_settings[message_field_names]" rows="4" class="large-text"><?php echo esc_textarea($options['message_field_names']); ?></textarea>
                        <p class="description"><?php esc_html_e('One field name per line. These are the fields that will be analyzed for spam content.', 'cf7-basic-honeypot'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="max_urls"><?php esc_html_e('Maximum URLs Allowed', 'cf7-basic-honeypot'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="max_urls" name="cf7_basic_honeypot_settings[max_urls]" value="<?php echo esc_attr($options['max_urls']); ?>" min="0" max="10" class="small-text" />
                        <p class="description"><?php esc_html_e('Messages with more URLs than this will be marked as spam', 'cf7-basic-honeypot'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="max_caps_percentage"><?php esc_html_e('Maximum Uppercase Percentage', 'cf7-basic-honeypot'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="max_caps_percentage" name="cf7_basic_honeypot_settings[max_caps_percentage]" value="<?php echo esc_attr($options['max_caps_percentage']); ?>" min="0" max="100" class="small-text" />%
                        <p class="description"><?php esc_html_e('Messages with more uppercase letters than this percentage will be marked as spam', 'cf7-basic-honeypot'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="min_words"><?php esc_html_e('Minimum Word Count', 'cf7-basic-honeypot'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="min_words" name="cf7_basic_honeypot_settings[min_words]" value="<?php echo esc_attr($options['min_words']); ?>" min="1" max="20" class="small-text" />
                        <p class="description"><?php esc_html_e('Messages with fewer words than this will be marked as spam', 'cf7-basic-honeypot'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="spam_keywords"><?php esc_html_e('Spam Keywords', 'cf7-basic-honeypot'); ?></label>
                    </th>
                    <td>
                        <textarea id="spam_keywords" name="cf7_basic_honeypot_settings[spam_keywords]" rows="15" class="large-text code"><?php echo esc_textarea($options['spam_keywords']); ?></textarea>
                        <p class="description"><?php esc_html_e('One keyword or phrase per line. Messages containing any of these will be marked as spam. Case-insensitive.', 'cf7-basic-honeypot'); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}

// Add honeypot field to CF7 forms
add_action('wpcf7_init', 'cf7_basic_honeypot_add_shortcode');
function cf7_basic_honeypot_add_shortcode() {
    wpcf7_add_form_tag('honeypot', 'cf7_basic_honeypot_handler');
}

// Handle the honeypot shortcode
function cf7_basic_honeypot_handler($tag) {
    $field_name = cf7_basic_honeypot_get_option('honeypot_field_name', 'your-website');
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
add_filter('wpcf7_spam', 'cf7_basic_honeypot_validation', 10, 2);
function cf7_basic_honeypot_validation($spam, $submission) {
    // If already marked as spam, return early
    if ($spam) {
        return $spam;
    }
    $data = $submission->get_posted_data();
    $field_name = cf7_basic_honeypot_get_option('honeypot_field_name', 'your-website');
    // Check if honeypot field exists and has a value
    if (isset($data[$field_name]) && !empty($data[$field_name])) {
        // Honeypot was filled - this is spam
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'honeypot',
            'reason' => __('Honeypot field was filled', 'cf7-basic-honeypot')
        ));
    }
    return $spam;
}

// Add time-based check
add_action('wpcf7_init', 'cf7_basic_honeypot_add_timestamp');
function cf7_basic_honeypot_add_timestamp() {
    wpcf7_add_form_tag('timestamp', 'cf7_basic_honeypot_timestamp_handler');
}

// Handle timestamp field
function cf7_basic_honeypot_timestamp_handler($tag) {
    $timestamp = time();
    $html = sprintf(
        '<input type="hidden" name="cf7_timestamp" value="%s" />',
        esc_attr($timestamp)
    );
    return $html;
}

// Validate timestamp
add_filter('wpcf7_spam', 'cf7_basic_honeypot_timestamp_validation', 10, 2);
function cf7_basic_honeypot_timestamp_validation($spam, $submission) {
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
            'reason' => __('Timestamp field missing', 'cf7-basic-honeypot')
        ));
        return $spam;
    }
    $timestamp = intval($data['cf7_timestamp']);
    $time_elapsed = time() - $timestamp;
    $min_time = cf7_basic_honeypot_get_option('min_submit_time', 5);
    $max_time = cf7_basic_honeypot_get_option('max_submit_time', 3600);
    // Form submitted too quickly
    if ($time_elapsed < $min_time) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'timestamp',
	    /* translators: %d: number of seconds elapsed */
            'reason' => sprintf(__('Form submitted too quickly (%d seconds)', 'cf7-basic-honeypot'), $time_elapsed)
        ));
        return $spam;
    }
    // Form took too long
    if ($time_elapsed > $max_time) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'timestamp',
            /* translators: %d: number of seconds the form was open */
            'reason' => sprintf(__('Form session expired (%d seconds old)', 'cf7-basic-honeypot'), $time_elapsed)
        ));
        return $spam;
    }
    return $spam;
}

// Content analysis spam detection
add_filter('wpcf7_spam', 'cf7_basic_honeypot_content_analysis', 10, 2);
function cf7_basic_honeypot_content_analysis($spam, $submission) {
    // If already marked as spam, return early
    if ($spam) {
        return $spam;
    }
    $data = $submission->get_posted_data();
    // Get message field names from settings
    $field_names_str = cf7_basic_honeypot_get_option('message_field_names', "your-message\nmessage\nyour-comment\ncomment");
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
    $max_urls = cf7_basic_honeypot_get_option('max_urls', 2);
    $url_count = preg_match_all('/https?:\/\/[^\s]+/i', $message);
    if ($url_count > $max_urls) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'content-analysis',
            /* translators: 1: number of URLs found, 2: maximum number allowed */
            'reason' => sprintf(__('Too many URLs in message (%1$d found, max %2$d allowed)', 'cf7-basic-honeypot'), $url_count, $max_urls)
        ));
        return $spam;
    }
    // 2. Check for excessive uppercase
    $max_caps = cf7_basic_honeypot_get_option('max_caps_percentage', 50);
    $letters_only = preg_replace('/[^a-zA-Z]/', '', $message);
    if (strlen($letters_only) > 10) {
        $uppercase_count = strlen(preg_replace('/[^A-Z]/', '', $letters_only));
        $caps_percentage = ($uppercase_count / strlen($letters_only)) * 100;
        if ($caps_percentage > $max_caps) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'content-analysis',
                /* translators: 1: percentage of uppercase characters, 2: maximum percentage allowed */
                'reason' => sprintf(__('Excessive uppercase text (%1$.0f%% caps, max %2$d%% allowed)', 'cf7-basic-honeypot'), $caps_percentage, $max_caps)
            ));
            return $spam;
        }
    }
    // 3. Check for minimum word count
    $min_words = cf7_basic_honeypot_get_option('min_words', 3);
    $word_count = str_word_count($message);
    if ($word_count < $min_words) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'content-analysis',
            /* translators: 1: number of words in message, 2: minimum number required */
            'reason' => sprintf(__('Message too short (%1$d words, min %2$d required)', 'cf7-basic-honeypot'), $word_count, $min_words)
        ));
        return $spam;
    }
    // 4. Check for spam keywords
    $keywords_str = cf7_basic_honeypot_get_option('spam_keywords', '');
    $spam_keywords = array_filter(array_map('trim', explode("\n", $keywords_str)));
    $message_lower = strtolower($message);
    foreach ($spam_keywords as $keyword) {
        if (strpos($message_lower, strtolower($keyword)) !== false) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'content-analysis',
                /* translators: %s: the spam keyword that was detected */
                'reason' => sprintf(__('Spam keyword detected: "%s"', 'cf7-basic-honeypot'), $keyword)
            ));
            return $spam;
        }
    }
    // 5. Check for repetitive patterns
    if (preg_match('/(.)\1{5,}/', $message) || preg_match('/(.{2,})\1{3,}/', $message)) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'content-analysis',
            'reason' => __('Repetitive text pattern detected', 'cf7-basic-honeypot')
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
                /* translators: %s: percentage of special characters in the message */
                'reason' => sprintf(__('Excessive special characters (%.0f%% of message)', 'cf7-basic-honeypot'), $special_char_percentage)
            ));
            return $spam;
        }
    }
    return $spam;
}

// Add custom CSS to ensure honeypot is completely hidden
add_action('wp_head', 'cf7_basic_honeypot_css');
function cf7_basic_honeypot_css() {
    $field_name = cf7_basic_honeypot_get_option('honeypot_field_name', 'your-website');
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
