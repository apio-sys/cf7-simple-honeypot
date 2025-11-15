<?php
/**
 * Uninstall script for Contact Form 7 Simple Honeypot
 * 
 * This file is called when the plugin is deleted via the WordPress admin.
 * It removes all plugin data from the database.
 */

// If uninstall not called from WordPress, exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$apiosys_honeypot_option_name = 'apiosys_honeypot_cf7_settings';

// Delete plugin options
delete_option( $apiosys_honeypot_option_name );

// for site options in Multisite installations
if (is_multisite()) {
    delete_site_option( $apiosys_honeypot_option_name );
}
