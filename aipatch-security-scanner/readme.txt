=== Aipatch Security Scanner ===
Contributors: estebandezafra
Tags: security, malware scanner, vulnerability, hardening, audit
Requires at least: 6.5
Tested up to: 6.9
Stable tag: 2.0.1
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Professional security audit engine for WordPress. 36 automated checks, malware file scanning, file integrity baseline, vulnerability intelligence, one-click remediation with rollback, and a full MCP surface for AI security agents.

== Description ==

**Aipatch Security Scanner** is a modular security audit engine built for site owners, developers, and AI-powered agents who need deep visibility into WordPress security posture — without the bloat of all-in-one security suites.

= Why Aipatch Security Scanner? =

Most WordPress security plugins are either too simple to be useful or too heavy to be practical. Aipatch takes a different approach:

* **Audit-first architecture.** Every check is a standalone, testable module that returns structured findings with severity, confidence, evidence, and fingerprints.
* **Built for automation.** 17 MCP abilities expose the full audit, scanning, and remediation surface to external AI agents — making Aipatch the first WordPress security plugin designed for agentic workflows.
* **Zero external dependencies.** Everything runs locally. No accounts, no cloud services, no API keys required.
* **Reversible by design.** Every automated remediation stores rollback data so you can undo any change with one click.

= Core Capabilities =

**36-Point Security Audit**

Aipatch runs 36 automated checks across 8 categories — core, plugins, themes, users, configuration, server, access control, and malware surface:

* Outdated WordPress core, plugins, and themes
* Default admin username, excessive admin accounts, inactive admin users, user ID 1 exposure
* XML-RPC, file editor, debug mode, debug log, REST API exposure, directory listing
* PHP version, HTTPS, file permissions, security headers (X-Frame-Options, CSP, etc.)
* Database prefix, sensitive files, PHP execution in uploads, auto-update configuration
* Salt key strength, cron health, cookie security flags, CORS, application passwords
* Exposed backup files, phpinfo files, uploads directory indexing, default login URL
* Database credential security, file installation permissions

Every finding includes a severity (critical / high / medium / low / info), confidence score, human-readable explanation, and actionable recommendation.

**Weighted Security Score (0–100)**

A logarithmic scoring engine computes an overall security score and per-area breakdown across six risk dimensions: software, access control, configuration, infrastructure, malware surface, and vulnerability exposure. Severity weights and confidence multipliers ensure the score reflects actual risk, not just issue count.

**Malware File Scanner**

A heuristic file scanner with 27 detection signatures and Shannon entropy analysis detects:

* Code execution patterns: eval(), assert(), create_function(), preg_replace /e
* System command functions: shell_exec, exec, passthru, backtick operators
* Obfuscation techniques: base64 encoding, hex encoding, str_rot13, gzinflate chains, chr() concatenation, variable variables, suspiciously long lines
* Network/exfiltration: cURL execution, fsockopen, remote file_get_contents
* Known backdoor signatures: c99, r57, WSO, b374k, weevely, FilesMan
* WordPress-specific threats: unauthorized admin creation, critical option injection, security function removal

Scanning runs in batches via an async job system with configurable batch sizes — safe for shared hosting.

**File Integrity Baseline**

Build a known-good hash baseline of all PHP files in your installation. Diff against it at any time to detect modified, deleted, or newly added files. Origin detection distinguishes core, plugin, theme, and upload files.

**Vulnerability Intelligence**

A local knowledge base of known plugin, theme, and core vulnerabilities with a database-backed caching layer for fast lookups. Provider architecture allows extending with external feeds.

**One-Click Remediation with Rollback**

Apply fixes directly from findings — change WordPress options, delete suspicious files, rename files, patch file contents, or add .htaccess rules. Every automated action stores a full rollback payload so you can reverse any change. Manual remediations can be logged for audit trails.

Six supported action types: `wp_option`, `delete_file`, `rename_file`, `file_patch`, `htaccess_rule`, `manual`.

**Hardening Module**

Five toggleable hardening rules with clear explanations and compatibility warnings:

* Disable XML-RPC — blocks external XML-RPC requests and removes X-Pingback header
* Hide WordPress Version — removes version leaks from source, RSS feeds, scripts, and styles
* Restrict REST API — limits sensitive endpoints to authenticated users
* Block Author Scanning — prevents user enumeration via author archives
* Login Brute-Force Protection — rate-limits login attempts per IP with configurable thresholds and lockout duration

**Persistent Findings Store**

All audit findings persist in a dedicated database table with automatic deduplication by fingerprint. Track findings over time — dismissed findings stay dismissed across scans; resolved findings reopen if the issue reappears.

**Security Event Logging**

Every scan, hardening change, remediation, and significant event is logged to a dedicated table. Logs are filterable by severity and exportable as CSV.

**WordPress Site Health Integration**

Adds 6 security tests to the built-in Site Health screen: file editor, debug mode, XML-RPC, admin username, SSL, and overall security score.

**Performance Diagnostics**

Built-in performance profiling to identify slow queries, high memory usage, and resource bottlenecks related to security operations.

**REST API**

10 authenticated endpoints under the `aipatch-security-scanner/v1` namespace for triggering scans, retrieving summaries, toggling hardening, exporting logs, and running performance diagnostics.

= MCP Surface for AI Agents (17 Abilities) =

Aipatch exposes 17 structured abilities via the WordPress Abilities API — making your site's security surface fully accessible to external AI agents, coding assistants, and orchestration tools:

* **aipatch/audit-site** — Run a full 36-check security audit
* **aipatch/audit-suspicious** — Scan for suspicious files with configurable scope
* **aipatch/list-findings** — Query persistent findings with filters
* **aipatch/findings-stats** — Aggregate finding statistics
* **aipatch/dismiss-finding** — Dismiss a finding as accepted risk
* **aipatch/start-file-scan** — Launch an async malware scan job
* **aipatch/file-scan-progress** — Check file scan progress
* **aipatch/file-scan-results** — Retrieve scan results with risk filtering
* **aipatch/process-file-scan-batch** — Process next batch of files
* **aipatch/baseline-build** — Build or refresh file integrity baseline
* **aipatch/baseline-diff** — Compare current files against baseline
* **aipatch/baseline-stats** — Baseline statistics
* **aipatch/list-jobs** — List scan/audit jobs
* **aipatch/apply-remediation** — Apply a security fix with rollback support
* **aipatch/rollback-remediation** — Undo a previously applied fix
* **aipatch/list-remediations** — List remediation history
* **aipatch/get-async-job-status** — Check async job status

All abilities include typed input/output schemas, permission checks, and structured error responses.

= What Aipatch Does NOT Do =

* It is NOT a firewall or WAF — it does not filter incoming traffic.
* It does NOT intercept frontend requests or affect page load performance.
* It does NOT phone home, require an account, or send data externally.
* It does NOT inject ads, upsells, or nag notices.

== Installation ==

1. Upload the `aipatch-security-scanner` folder to `/wp-content/plugins/`.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Navigate to **Aipatch Security Scanner → Dashboard** to run your first audit.
4. Review your security score and findings, then explore hardening options.

For AI agent integration, ensure the WordPress Abilities API is available and connect your agent to the `aipatch/audit-site` ability.

== Frequently Asked Questions ==

= How many security checks does Aipatch run? =

36 automated checks across 8 categories: WordPress core, plugins, themes, users, configuration, server, access control, and malware surface. Each finding includes severity, confidence, evidence, and a specific recommendation.

= Does this plugin slow down my site? =

No. Aipatch adds nothing to the frontend. Audits run on demand, via WP-Cron, or through the REST API. The malware file scanner uses a job-based batch system so it never monopolizes server resources.

= Does it require an external API or account? =

No. Everything runs locally with zero external dependencies. The vulnerability provider architecture supports optional external feeds for extended coverage.

= Can Aipatch detect malware? =

Yes. The heuristic file scanner uses 27 detection signatures covering code execution, obfuscation, backdoor patterns, and WordPress-specific threats, plus Shannon entropy analysis for encoded payloads. Files are classified as clean, suspicious, risky, or malicious with a 0–100 risk score.

= What happens if a remediation breaks something? =

Every automated remediation stores full rollback data. You can reverse any change — restored files include original content and permissions, reversed options include the previous value, removed .htaccess rules are cleanly deleted. Manual remediations are tracked but not auto-reversible.

= Is it compatible with other security plugins? =

Yes. Aipatch focuses on auditing, scanning, and remediation — not request filtering. It coexists with firewalls like Wordfence, Sucuri, or Cloudflare without conflicts.

= What is the MCP surface? =

MCP (Model Context Protocol) is the standard for AI agents to interact with tools. Aipatch exposes 17 structured abilities via the WordPress Abilities API, allowing AI agents to audit your site, scan for malware, manage findings, and apply fixes — all through typed, permissioned tool calls.

= What data does it store? =

Audit findings, scan history, file baselines, scan results, remediation records, vulnerability cache, job state, hardening preferences, settings, and event logs — all in your WordPress database. Nothing leaves your server.

= What PHP version does Aipatch require? =

PHP 7.4 or higher. WordPress 6.5 or higher.

== Screenshots ==

1. Security Dashboard — overall score, risk posture breakdown, and finding summary cards.
2. Audit findings list — filterable by severity, category, and status.
3. Malware file scan — heuristic results with risk classification.
4. Known vulnerabilities — installed software matched against the vulnerability database.
5. Hardening toggles — each rule with explanation and compatibility notes.
6. Remediation history — applied fixes with rollback controls.
7. Security event logs — severity filtering and CSV export.
8. Settings — module control, scan scheduling, and log retention.

== Changelog ==

= 1.0.2 =
* Major architecture overhaul: modular audit engine with interface/registry/engine pattern.
* 36 security checks (up from 12) across 8 categories including malware surface and access control.
* Weighted logarithmic scoring engine with per-area risk posture breakdown.
* Heuristic malware file scanner with 27 signatures and Shannon entropy check.
* Async job system for batch file scanning on shared hosting.
* File integrity baseline with origin detection (core, plugin, theme, upload).
* Persistent findings store with deduplication, automatic resolution, and dismissal tracking.
* Vulnerability intelligence caching layer with decorator pattern.
* One-click remediation engine with full rollback support (6 action types).
* 17 MCP abilities via WordPress Abilities API for AI agent integration.
* 7 new database tables (9 total) for jobs, findings, baselines, scan results, vulnerability cache, and remediations.
* New audit checks: cookie security, backup files, phpinfo exposure, CORS, uploads index, login URL, database credentials.
* Hardening: added author scanning protection.
* Path traversal protection for all file operations.

= 1.0.1 =
* Updated version metadata and packaging adjustments for WordPress.org review.

= 1.0.0 =
* Initial release.
* Security dashboard with risk score.
* Local security scanner with 12 checks.
* Hardening module with 4 toggleable rules.
* Built-in vulnerability database.
* Security event logging.
* WordPress Site Health integration.
* REST API for plugin operations.
* Automatic scans via WP-Cron.

== Upgrade Notice ==

= 1.0.2 =
Major upgrade: 36 audit checks, malware file scanner, file integrity baseline, remediation engine with rollback, and 17 MCP abilities for AI agents. Database will be upgraded automatically.

= 1.0.1 =
Maintenance release for WordPress.org submission updates.

= 1.0.0 =
Initial release of Aipatch Security Scanner.
