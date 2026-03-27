=== AI PatchWatch – Security Intelligence ===
Contributors: estebandezafra
Tags: security, vulnerabilities, hardening, scanner, protection
Requires at least: 6.5
Tested up to: 6.9
Stable tag: 1.0.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lightweight security intelligence for your site. Detect vulnerabilities, assess risks, and apply safe hardening — without the bloat.

== Description ==

**AI PatchWatch** is a lightweight security intelligence plugin that helps you understand and improve your site's security posture.

Unlike heavy security suites, AI PatchWatch focuses on **clarity over complexity**:

* **Security Score:** A simple 0–100 score that summarizes your site's security status at a glance.
* **Smart Scanner:** Detects outdated plugins, themes, core versions, risky configurations, and common vulnerabilities — all locally, with no external dependencies.
* **Vulnerability Intelligence:** Checks your installed software against known vulnerabilities. Prepared for external vulnerability feeds in future versions.
* **Safe Hardening:** Toggle security improvements like XML-RPC blocking, REST API restrictions, WP version hiding, and login brute-force protection — each with clear explanations and compatibility warnings.
* **Security Logs:** A clean log of all security events, scans, and changes made through the plugin.
* **Site Health Integration:** Adds custom security tests to the WordPress Site Health screen.
* **Clear Explanations:** Every risk finding includes what it means, why it matters, and what to do — in plain language.

= Philosophy =

AI PatchWatch is designed around the idea of **security intelligence, not security overload**. We believe site owners deserve clear, actionable information without being overwhelmed by technical jargon or upsell pressure.

= What AI PatchWatch Does NOT Do =

* It is NOT a firewall or WAF.
* It does NOT scan files for malware (planned for future versions).
* It does NOT modify your .htaccess or wp-config.php automatically.
* It does NOT phone home or require an account to function.

= Future Roadmap =

* Remote vulnerability feed API integration
* AI-powered risk explanations
* File integrity monitoring (hash comparison)
* Email alerts for critical findings
* Extended multi-site support
* Optional cloud dashboard

== Installation ==

1. Upload the `patchwatch` folder to `/wp-content/plugins/`.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Navigate to **AI PatchWatch → Dashboard** to run your first scan.

== Frequently Asked Questions ==

= Does this plugin slow down my site? =

No. AI PatchWatch runs scans on demand or via a daily cron job. It does not add anything to your frontend and does not intercept requests on every page load.

= Does it require an external API or account? =

No. The current version works entirely locally. Future versions will offer optional external vulnerability feeds as a complementary service.

= Will it break my site? =

AI PatchWatch is designed to be safe. Hardening options are toggled individually and include compatibility warnings. No system files are modified automatically.

= Is it compatible with other security plugins? =

Yes. AI PatchWatch focuses on intelligence and reporting, not on request filtering. It can coexist with firewall plugins like Wordfence or Sucuri.

= What data does it store? =

AI PatchWatch stores scan results, settings, hardening preferences, and security logs in your database. No data is sent externally.

== Screenshots ==

1. Security Dashboard with score and summary cards.
2. Vulnerability intelligence table.
3. Hardening toggles with explanations.
4. Security logs with severity filtering.
5. Settings page.

== Changelog ==

= 1.0.0 =
* Initial release.
* Security dashboard with risk score (0–100).
* Local security scanner (core, plugins, themes, users, configuration).
* Hardening module (XML-RPC, REST API, WP version, login protection).
* Vulnerability intelligence with provider architecture.
* Security event logging with retention management.
* WordPress Site Health integration.
* Internal REST API for plugin operations.
* Automatic daily scans via WP-Cron.

== Upgrade Notice ==

= 1.0.0 =
Initial release of AI PatchWatch.
