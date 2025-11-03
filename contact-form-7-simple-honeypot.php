<?php
/**
 * Plugin Name: Contact Form 7 Simple Honeypot
 * Plugin URI: https://github.com/apio-sys/contact-form-7-simple-honeypot
 * Description: Simple Honeypot plugin for CF7 to reduce spam on form submissions without user interaction. Includes honeypot field, time-based validation, and content analysis.
 * Version: 1.0.0
 * Author: Joris Le Blansch, Apio systems
 * Author URI: https://apio.systems
 * License: GPL v2 or later
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
define('CF7_SIMPLE_HONEYPOT_VERSION', '1.0.0');

// Configuration constants
define('CF7_HONEYPOT_FIELD_NAME', 'your-website');
define('CF7_MAX_URLS', 1); // Maximum allowed URLs in message
define('CF7_MAX_CAPS_PERCENTAGE', 50); // Maximum percentage of uppercase characters
define('CF7_MIN_WORDS', 3); // Minimum number of words in message
define('CF7_MIN_SUBMIT_TIME', 5); // Minimum seconds before form can be submitted
define('CF7_MAX_SUBMIT_TIME', 3600); // Maximum seconds (1 hour) before form expires

/**
 * Check if Contact Form 7 is active
 */
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

/**
 * Admin notice if Contact Form 7 is not installed
 */
function cf7_simple_honeypot_cf7_missing_notice() {
    ?>
    <div class="notice notice-error">
        <p><?php _e('Contact Form 7 Simple Honeypot requires Contact Form 7 to be installed and activated.', 'cf7-simple-honeypot'); ?></p>
    </div>
    <?php
}

/**
 * Add honeypot field to CF7 forms
 */
add_action('wpcf7_init', 'cf7_simple_honeypot_add_shortcode');
function cf7_simple_honeypot_add_shortcode() {
    wpcf7_add_form_tag('honeypot', 'cf7_simple_honeypot_handler');
}

/**
 * Handle the honeypot shortcode
 */
function cf7_simple_honeypot_handler($tag) {
    $field_name = CF7_HONEYPOT_FIELD_NAME;
    
    $html = sprintf(
        '<span class="wpcf7-form-control-wrap" data-name="%1$s" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden;">
            <label>Website (optional)</label>
            <input type="text" name="%1$s" value="" size="40" class="wpcf7-form-control" tabindex="-1" autocomplete="off" aria-hidden="true" />
        </span>',
        esc_attr($field_name)
    );
    
    return $html;
}

/**
 * Validate honeypot on form submission
 */
add_filter('wpcf7_spam', 'cf7_simple_honeypot_validation', 10, 2);
function cf7_simple_honeypot_validation($spam, $submission) {
    // If already marked as spam, return early
    if ($spam) {
        return $spam;
    }
    
    $data = $submission->get_posted_data();
    $field_name = CF7_HONEYPOT_FIELD_NAME;
    
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

/**
 * Add time-based check (optional extra protection)
 */
add_action('wpcf7_init', 'cf7_simple_honeypot_add_timestamp');
function cf7_simple_honeypot_add_timestamp() {
    wpcf7_add_form_tag('timestamp', 'cf7_simple_honeypot_timestamp_handler');
}

/**
 * Handle timestamp field
 */
function cf7_simple_honeypot_timestamp_handler($tag) {
    $timestamp = time();
    
    $html = sprintf(
        '<input type="hidden" name="cf7_timestamp" value="%s" />',
        esc_attr($timestamp)
    );
    
    return $html;
}

/**
 * Validate timestamp (form must take at least X seconds to submit)
 */
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
    
    // Form submitted too quickly
    if ($time_elapsed < CF7_MIN_SUBMIT_TIME) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'timestamp',
            'reason' => sprintf(__('Form submitted too quickly (%d seconds)', 'cf7-simple-honeypot'), $time_elapsed)
        ));
        return $spam;
    }
    
    // Form took too long (possible bot)
    if ($time_elapsed > CF7_MAX_SUBMIT_TIME) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'timestamp',
            'reason' => sprintf(__('Form session expired (%d seconds old)', 'cf7-simple-honeypot'), $time_elapsed)
        ));
        return $spam;
    }
    
    return $spam;
}

/**
 * Content analysis spam detection
 */
add_filter('wpcf7_spam', 'cf7_simple_honeypot_content_analysis', 10, 2);
function cf7_simple_honeypot_content_analysis($spam, $submission) {
    // If already marked as spam, return early
    if ($spam) {
        return $spam;
    }
    
    $data = $submission->get_posted_data();
    
    // Get common message fields (adjust based on your form field names)
    $message_fields = array('your-message', 'message', 'your-comment', 'comment');
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
    $url_count = preg_match_all('/https?:\/\/[^\s]+/i', $message);
    if ($url_count > CF7_MAX_URLS) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'content-analysis',
            'reason' => sprintf(__('Too many URLs in message (%d found, max %d allowed)', 'cf7-simple-honeypot'), $url_count, CF7_MAX_URLS)
        ));
        return $spam;
    }
    
    // 2. Check for excessive uppercase (shouting/spam pattern)
    $letters_only = preg_replace('/[^a-zA-Z]/', '', $message);
    if (strlen($letters_only) > 10) { // Only check if there are enough letters
        $uppercase_count = strlen(preg_replace('/[^A-Z]/', '', $letters_only));
        $caps_percentage = ($uppercase_count / strlen($letters_only)) * 100;
        
        if ($caps_percentage > CF7_MAX_CAPS_PERCENTAGE) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'content-analysis',
                'reason' => sprintf(__('Excessive uppercase text (%.0f%% caps, max %d%% allowed)', 'cf7-simple-honeypot'), $caps_percentage, CF7_MAX_CAPS_PERCENTAGE)
            ));
            return $spam;
        }
    }
    
    // 3. Check for minimum word count (gibberish detection)
    $word_count = str_word_count($message);
    if ($word_count < CF7_MIN_WORDS) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'content-analysis',
            'reason' => sprintf(__('Message too short (%d words, min %d required)', 'cf7-simple-honeypot'), $word_count, CF7_MIN_WORDS)
        ));
        return $spam;
    }
    
    // 4. Check for common spam keywords
    $spam_keywords = array(
        // Pharmaceutical spam
        'viagra', 'cialis', 'pharmacy', 'prescription',
        
        // Gambling spam
        'casino', 'poker', 'betting', 'gambling',
        
        // Financial spam
        'loan', 'mortgage', 'crypto', 'bitcoin', 'forex',
        'investment opportunity', 'passive income', 'cash flow',
        'earning money', 'earn money', 'make money', 'making money',
        'thousands of dollars', 'hundreds of dollars', 'money flow',
        
        // Call-to-action spam
        'click here', 'buy now', 'limited offer', 'act now',
        'order now', 'visit now', 'check this out',
        
        // Marketing/SEO spam
        'weight loss', 'work from home', 'seo service', 'seo services',
        'link building', 'increase traffic', 'backlinks', 'boost your ranking',
        'get more followers', 'grow your business',
        
        // Social media spam
        'instagram followers', 'facebook likes', 'youtube views',
        'increase followers', 'gain followers',
        
        // Common spam phrases
        'real deal', 'skeptical at first', 'evaluation copy',
        'this system', 'amazing opportunity', 'limited time',
        'don\'t miss out', 'act fast', 'special offer',
        'congratulations', 'you\'ve been selected', 'claim your',
        'risk free', 'money back guarantee', 'no obligation'
    );
    
    $message_lower = strtolower($message);
    foreach ($spam_keywords as $keyword) {
        if (strpos($message_lower, $keyword) !== false) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'content-analysis',
                'reason' => sprintf(__('Spam keyword detected: "%s"', 'cf7-simple-honeypot'), $keyword)
            ));
            return $spam;
        }
    }
    
    // 5. Check for repetitive patterns (e.g., "aaaaaa" or "123123123")
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

/**
 * Add custom CSS to ensure honeypot is completely hidden
 */
add_action('wp_head', 'cf7_simple_honeypot_css');
function cf7_simple_honeypot_css() {
    $field_name = CF7_HONEYPOT_FIELD_NAME;
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
