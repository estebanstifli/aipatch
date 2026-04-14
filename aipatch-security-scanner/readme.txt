=== Aipatch Security Scanner ===
Contributors: estebandezafra
Tags: security, scanner, hardening, vulnerabilities, audit
Requires at least: 6.5
Tested up to: 6.9
Stable tag: 1.0.2
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lightweight security scanner for WordPress. Checks for outdated software, risky configurations, and applies safe hardening measures.

== Description ==

**Aipatch Security Scanner** is a lightweight security scanner that helps you understand and improve your site's security posture.

Unlike heavy security suites, Aipatch Security Scanner focuses on **clarity over complexity**:

* **Security Score:** A simple 0–100 score that summarizes your site's security status at a glance.
* **Local Scanner:** Detects outdated plugins, themes, core versions, risky configurations, and common security weaknesses — all locally, with no external dependencies.
* **Known Vulnerabilities:** Checks your installed software against a built-in knowledge base of known vulnerabilities. Future versions will support external vulnerability feeds for broader coverage.
* **Safe Hardening:** Toggle security improvements like XML-RPC blocking, REST API restrictions, WordPress version hiding, and login brute-force protection — each with clear explanations and compatibility warnings.
* **Security Logs:** A clean log of all security events, scans, and changes made through the plugin.
* **Site Health Integration:** Adds custom security tests to the WordPress Site Health screen.
* **Scan History:** Every scan is saved so you can track your security score over time.
* **Module Control:** Enable or disable individual modules (scanner, hardening, vulnerabilities, login protection) from settings.

= Philosophy =

Aipatch Security Scanner is designed to give site owners **clear, actionable information** without being overwhelmed by technical jargon or upsell pressure. Every finding includes what it means, why it matters, and what to do — in plain language.

= What Aipatch Security Scanner Does =

* Runs 12 local security checks against your installation
* Calculates a risk score based on findings
* Compares installed plugins, themes, and core against known vulnerabilities
* Applies optional hardening rules via WordPress filters (no file modifications)
* Logs all security events to a dedicated database table
* Integrates with WordPress Site Health

= What Aipatch Security Scanner Does NOT Do =

* It is NOT a firewall or WAF.
* It does NOT scan files for malware.
* It does NOT modify your .htaccess or wp-config.php automatically.
* It does NOT phone home or require an account to function.
* It does NOT intercept frontend requests or affect page load performance.

= Future Roadmap =

* External vulnerability feed integration (API-based)
* File integrity monitoring
* Email alerts for critical findings
* Extended multisite support

== Installation ==

1. Upload the `aipatch-security-scanner` folder to `/wp-content/plugins/`.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Navigate to **Aipatch Security Scanner → Dashboard** to run your first scan.

== Frequently Asked Questions ==

= Does this plugin slow down my site? =

No. Aipatch Security Scanner runs scans on demand or via WP-Cron. It does not add anything to your frontend and does not intercept requests on every page load.

= Does it require an external API or account? =

No. The current version works entirely locally. Future versions will offer optional external vulnerability feeds.

= Will it break my site? =

Aipatch Security Scanner is designed to be safe. Hardening options are toggled individually and include compatibility warnings. No system files are modified automatically.

= Is it compatible with other security plugins? =

Yes. Aipatch Security Scanner focuses on scanning and reporting, not request filtering. It can coexist with firewall plugins like Wordfence or Sucuri.

= What data does it store? =

Scan results, settings, hardening preferences, scan history, and security logs in your WordPress database. No data is sent externally.

= How accurate is the vulnerability database? =

The built-in database covers a curated set of known vulnerabilities for popular plugins, themes, and WordPress core. It is updated with each plugin release. For broader, real-time coverage, external vulnerability feeds will be supported in future versions.

== Screenshots ==

1. Security Dashboard with score and summary cards.
2. Known vulnerabilities table.
3. Hardening toggles with explanations.
4. Security logs with severity filtering.
5. Settings page with module control.

== Changelog ==

= 1.0.1 =
* Updated version metadata and packaging adjustments for WordPress.org review.

= 1.0.0 =
* Initial release.
* Security dashboard with risk score (0–100).
* Local security scanner with 12 checks (core, plugins, themes, users, configuration, server).
* Normalized findings with evidence, source, and fingerprint.
* Scan history table for tracking score over time.
* Hardening module (XML-RPC, REST API, WordPress version, login brute-force protection).
* Built-in known vulnerability database with provider architecture.
* Module toggle control from settings.
* Security event logging with retention management.
* WordPress Site Health integration (6 tests).
* Internal REST API for plugin operations.
* Automatic scans via WP-Cron.

== Upgrade Notice ==

= 1.0.1 =
Maintenance release for WordPress.org submission updates.

= 1.0.0 =
Initial release of Aipatch Security Scanner.
