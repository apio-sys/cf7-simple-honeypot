=== Apio systems Honeypot for Contact Form 7 ===
Contributors: apiosys
Tags: honeypot, antispam, forms
Requires at least: 6.5
Tested up to: 6.8
Stable tag: 0.9.3
Requires PHP: 7.2
License: MIT
License URI: https://github.com/apio-sys/apiosys-honeypot-cf7/blob/main/LICENSE

Basic Honeypot plugin for Contact Form 7 to drastically reduce spam on form submissions without user interaction.

== Description ==

I like to use Contact Form 7 on most of my WordPress sites. It's a powerful form manager that suits all my needs. I don't like to use external calls to protect the forms from spam submissions though (like reCaptcha or hCaptcha) and don't want to present a manual captcha to a user (math or other puzzle). Since I couldn't find a really basic honeypot script that works on most entries, I created one here. Hopefully it's useful to someone else also.

== Setup ==

- Install the plugin using the regular plugin setup routine or upload the entire apiosys-honeypot-cf7 folder to the /wp-content/plugins/ directory.
- Activate the plugin through the "Plugins" menu in WordPress, you MUST have Contact Form 7 AND Flamingo installed and enabled.
- Add the following shortcodes to your Contact Form 7 forms:

[honeypot] - Adds the hidden honeypot field\
[timestamp] - Adds time-based validation

- Complete the rest of the options (a generally good working set of values is enabled by default).

== What tests are used? ==

- A Honeypot Field
- Time-Based Validation
- Basic Content Analysis

== Does it really work? ==

It has been tested on several high-traffic WP sites. I see a return of ~ 1 ‰ (i.e. 1 in a thousand) of spam going through. That usually corresponds to humans paid to fill forms or sophisticated bots. Please feel free to contribute to make it even better.

== Changelog ==
= 0.9.3 - 2025-11-16 =
* FIX: CSS resource version.

= 0.9.2 - 2025-11-14 =
* First production release.
