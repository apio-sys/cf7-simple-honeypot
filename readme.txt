=== Basic Honeypot for Contact Form 7 ===
Contributors: apiosys
Tags: honeypot, antispam, forms
Requires at least: 6.5
Tested up to: 6.8
Stable tag: 0.9.1
Requires PHP: 7.2
License: MIT
License URI: https://github.com/apio-sys/cf7-basic-honeypot/blob/main/LICENSE

Basic Honeypot plugin for Contact Form 7 to drastically reduce spam on form submissions without user interaction.

== Description ==

I like to use Contact Form 7 on most of my WordPress sites. It's a powerful form manager that suits all my needs. I don't like to use external calls to protect the forms from spam submissions though (like reCaptcha or hCaptcha) and don't want to present a manual captcha to a user (math or other puzzle). Since I couldn't find a really basic honeypot script that works on most entries, I created one here. Hopefully it's useful to someone else also.

== Setup ==

- Install the plugin using the regular plugin setup routine or upload the entire cf7-basic-honeypot folder to the /wp-content/plugins/ directory.
- Activate the plugin through the "Plugins" menu in WordPress, you MUST have Contact Form 7 AND Flamingo installed and enabled.
- Add the following shortcodes to your Contact Form 7 forms:

[honeypot] - Adds the hidden honeypot field\
[timestamp] - Adds time-based validation

- Complete the rest of the options (a generally good working set of values is enabled by default).

== What tests are used? ==

- A Honeypot Field
- Time-Based Validation
- Basic Content Analysis

== Changelog ==
= 0.9.1 - 2025-11-04 =
* First production release.
