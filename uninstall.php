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

$option_name = 'cf7_basic_honeypot_settings';

// Delete plugin options
delete_option( $option_name );

// for site options in Multisite installations
if (is_multisite()) {
    delete_site_option( $option_name );
}
