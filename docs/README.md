# Aipatch Security Scanner — Technical Reference

**Version:** 2.0.1  
**Requires:** WordPress 6.5+ · PHP 7.4+  
**License:** GPL v2 or later  
**DB Version:** 2.0  
**REST Namespace:** `aipatch-security-scanner/v1`

---

## Overview

Aipatch Security Scanner is a WordPress security plugin that provides a modular audit engine, multi-layer file scanner with malware family classification, persistent findings tracking, WordPress core integrity verification, and a full MCP (Model Context Protocol) Abilities API for AI-agent integration.

All scanning and analysis is performed locally — no external services except the official WordPress checksums API (`api.wordpress.org`).

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     AIPSC_Loader                        │
│  (orchestrator — instantiates and wires all modules)    │
├──────────┬──────────┬──────────┬────────────────────────┤
│  Audit   │  File    │ Findings │  MCP Abilities API     │
│  Engine  │  Scanner │  Store   │  (23 tools)            │
├──────────┼──────────┼──────────┼────────────────────────┤
│ 36 checks│ Heurist. │ Dedup    │  Core Verifier         │
│ Score    │ Classif. │ Diff     │  File Baseline         │
│ Engine   │ Baseline │ Remediat.│  Job Manager           │
└──────────┴──────────┴──────────┴────────────────────────┘
```

### Key Modules

| Module | Class | Purpose |
|--------|-------|---------|
| Audit Engine | `AIPSC_Audit_Engine` | Executes 36 security checks, produces scored report |
| Score Engine | `AIPSC_Score_Engine` | Computes 0–100 site health score from check results |
| File Scanner | `AIPSC_File_Scanner` | Multi-layer file analysis with batch processing |
| File Heuristics | `AIPSC_File_Heuristics` | Content pattern matching (eval, obfuscation, shells) |
| File Classifier | `AIPSC_File_Classifier` | Layered scoring (content 55%, context 25%, integrity 20%) + family classification |
| Core Verifier | `AIPSC_Core_Verifier` | Official WP checksum verification via api.wordpress.org |
| File Baseline | `AIPSC_File_Baseline` | SHA-256 baseline of all files, drift detection |
| Findings Store | `AIPSC_Findings_Store` | Persistent findings with fingerprint dedup, status lifecycle |
| Remediation Engine | `AIPSC_Remediation_Engine` | Apply/rollback security fixes with audit trail |
| Job Manager | `AIPSC_Job_Manager` | Async batch processing for large scans |
| Hardening | `AIPSC_Hardening` | 5 toggleable hardening rules |
| Abilities | `AIPSC_Abilities` | 23 MCP tools for AI-agent integration |

---

## Security Audit Checks (36)

The audit engine runs 36 independent checks, each producing a severity-scored finding.

| # | Check ID | Description |
|---|----------|-------------|
| 1 | `wp_version` | WordPress core version up to date |
| 2 | `php_version` | PHP version meets minimum security requirements |
| 3 | `plugins_outdated` | Plugins with available updates |
| 4 | `themes_outdated` | Themes with available updates |
| 5 | `ssl` | SSL/HTTPS enforced site-wide |
| 6 | `admin_username` | Default "admin" username exists |
| 7 | `too_many_admins` | Excessive administrator accounts |
| 8 | `inactive_admins` | Admin accounts with no recent login |
| 9 | `user_id_one` | User ID 1 is an administrator (predictable target) |
| 10 | `user_enumeration` | User enumeration via REST or author archives |
| 11 | `application_passwords` | Application Passwords feature enabled |
| 12 | `xmlrpc` | XML-RPC endpoint enabled |
| 13 | `file_editor` | In-dashboard file editor enabled |
| 14 | `debug_mode` | `WP_DEBUG` enabled in production |
| 15 | `debug_log` | Debug log file publicly accessible |
| 16 | `database_debug` | Database debug mode enabled |
| 17 | `db_prefix` | Default `wp_` database prefix |
| 18 | `db_credentials` | Weak or default database credentials |
| 19 | `rest_exposure` | Sensitive REST API endpoints exposed |
| 20 | `directory_listing` | Directory browsing enabled |
| 21 | `file_permissions` | Insecure file/directory permissions |
| 22 | `sensitive_files` | Sensitive files accessible (readme.html, etc.) |
| 23 | `php_in_uploads` | PHP files in uploads directory |
| 24 | `uploads_index` | Uploads directory lacks index.php |
| 25 | `security_headers` | Missing security headers (CSP, X-Frame-Options, etc.) |
| 26 | `salt_keys` | Weak or default authentication salt keys |
| 27 | `auto_updates` | Auto-updates disabled |
| 28 | `cookie_security` | Cookie security flags missing (httponly, secure) |
| 29 | `cors_config` | Overly permissive CORS configuration |
| 30 | `cron_health` | WP-Cron disabled or unhealthy |
| 31 | `inactive_plugins` | Inactive plugins still installed |
| 32 | `unused_themes` | Unused themes still installed |
| 33 | `backup_files` | Backup files accessible from web |
| 34 | `phpinfo_exposure` | phpinfo() files publicly accessible |
| 35 | `login_url` | Default login URL not obscured |
| 36 | `file_install` | `install.php` still accessible |

---

## File Scanner Engine

### Multi-Layer Scoring

The file scanner uses a three-layer weighted scoring system:

| Layer | Weight | What it measures |
|-------|--------|------------------|
| **Content** | 55% | Heuristic pattern matches (eval, obfuscation, shells, backdoors) |
| **Context** | 25% | File location, naming, extension anomalies, uploads detection |
| **Integrity** | 20% | Baseline drift + official WordPress core checksum verification |

Final score = weighted sum with reduction multiplier for low-signal files.

### Risk Classification

| Score Range | Classification | Severity |
|-------------|---------------|----------|
| 75–100 | `malicious` | critical |
| 45–74 | `risky` | high |
| 15–44 | `suspicious` | medium |
| 0–14 | `clean` | — |

### Core Integrity Overrides

When core tampering is detected via official WordPress checksums:

| Condition | Integrity Score | Severity | FP Likelihood |
|-----------|----------------|----------|---------------|
| `core_tampered` (checksum mismatch) | 80–100 | critical | none |
| `unexpected_in_core` (file not in manifest) | 60–85 | high | none |

### Malware Family Classification (11 families)

| Family | Label | Typical Indicators |
|--------|-------|--------------------|
| `webshell` | Web Shell | Interactive remote shell, command execution |
| `obfuscated_loader` | Obfuscated Loader | base64/gzinflate/str_rot13 encoded payloads |
| `dropper` | Dropper | File write operations, downloads malware to disk |
| `remote_fetcher` | Remote Fetcher | Fetches remote content, potential SSRF |
| `persistence_backdoor` | Persistence Backdoor | Admin creation, auth bypass, hidden execution |
| `cloaked_php` | Cloaked PHP | PHP code inside non-PHP files (.ico, .jpg, .txt) |
| `modified_core` | Modified Core File | WordPress core file modified from official checksum |
| `unexpected_upload_executable` | Unexpected Upload Exec | PHP in uploads where only media should exist |
| `injector` | Code Injector | Injects iframes, scripts, or options into pages/DB |
| `unknown_suspicious` | Unknown Suspicious | Suspicious patterns, no clear family match |
| `mixed_signals` | Mixed Signals | Multi-family match, polymorphic behavior |

Each family classification includes a confidence level (`high`, `medium`, `low`) and a remediation hint.

---

## Hardening Rules (5)

| Rule | ID | Effect |
|------|----|--------|
| Disable XML-RPC | `disable_xmlrpc` | Blocks all xmlrpc.php requests |
| Hide WP Version | `hide_wp_version` | Strips version from HTML, RSS, scripts |
| Restrict REST API | `restrict_rest_api` | Limits `/wp/v2/users` and `/wp/v2/settings` to authenticated users |
| Block Author Scanning | `block_author_scanning` | Redirects `?author=N` enumeration queries |
| Login Brute-Force Protection | `login_protection` | Rate-limits login attempts (default: 5 attempts / 15 min lockout) |

---

## Database Schema (9 tables)

| Table | Purpose |
|-------|---------|
| `aipsc_logs` | Plugin event log (event_type, severity, message, context) |
| `aipsc_scan_history` | Audit scan history (score, issues, duration) |
| `aipsc_jobs` | Async job tracking (type, status, progress, result) |
| `aipsc_job_items` | Individual items within a job (file paths, per-item status) |
| `aipsc_findings` | Persistent security findings (fingerprint dedup, severity, lifecycle) |
| `aipsc_file_baseline` | Known-good file hash baseline (SHA-256, origin, component) |
| `aipsc_file_scan_results` | Per-file scan results (risk score, classification, enriched JSON) |
| `aipsc_vulnerability_cache` | Cached vulnerability data (provider, expiry) |
| `aipsc_remediations` | Applied remediations with rollback data |

---

## MCP Abilities API (23 Tools)

All abilities are registered under the `aipatch-security` category and require the `manage_options` capability (filterable via `aipatch_abilities_required_capability`).

### At a Glance

| # | Ability | Type | Description |
|---|---------|------|-------------|
| 1 | `aipatch/audit-site` | read | Full site security audit |
| 2 | `aipatch/audit-suspicious` | read | Suspicious file scan |
| 3 | `aipatch/get-async-job-status` | read | Async job polling |
| 4 | `aipatch/list-findings` | read | Query persistent findings |
| 5 | `aipatch/findings-stats` | read | Aggregate findings statistics |
| 6 | `aipatch/findings-diff` | read | Changes since a point in time |
| 7 | `aipatch/dismiss-finding` | **write** | Dismiss a finding (accepted risk) |
| 8 | `aipatch/start-file-scan` | read | Start malware scan job |
| 9 | `aipatch/file-scan-progress` | read | Scan job progress |
| 10 | `aipatch/file-scan-results` | read | Enriched scan results |
| 11 | `aipatch/process-file-scan-batch` | read | Process next file batch |
| 12 | `aipatch/baseline-build` | read | Build/refresh file baseline |
| 13 | `aipatch/baseline-diff` | read | Baseline integrity diff |
| 14 | `aipatch/baseline-stats` | read | Baseline statistics |
| 15 | `aipatch/list-jobs` | read | List scan/audit jobs |
| 16 | `aipatch/apply-remediation` | **write** | Apply security fix |
| 17 | `aipatch/rollback-remediation` | **write** | Rollback a remediation |
| 18 | `aipatch/list-remediations` | read | List remediation records |
| 19 | `aipatch/verify-core-integrity` | read | WordPress core checksum verification |
| 20 | `aipatch/list-suspicious-files` | read | Enriched suspicious files from latest scan |
| 21 | `aipatch/get-file-finding-detail` | read | Single finding with decoded metadata |
| 22 | `aipatch/get-scan-summary` | read | Comprehensive latest scan summary |
| 23 | `aipatch/get-baseline-drift` | read | Combined baseline + core integrity report |

**Read-only:** 20 · **Write:** 3

---

### Detailed Ability Reference

#### 1. `aipatch/audit-site`

Full site security audit via the 36-check audit engine. Returns scored issues, site info, hardening status, and optionally vulnerabilities.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `refresh_scan` | boolean | `true` | Run a fresh scan vs. return cached results |
| `include_dismissed` | boolean | `false` | Include dismissed issues |
| `include_vulnerabilities` | boolean | `true` | Include vulnerability provider data |
| `include_summary` | boolean | `true` | Include dashboard summary metrics |
| `async` | boolean | `false` | Queue in background, return job_id |

**Response:** `{ success, score, issues[], issues_by_severity, site{}, hardening{}, vulnerabilities[], summary{} }`

---

#### 2. `aipatch/audit-suspicious`

Quick heuristic scan for suspicious files in selected directories. Lightweight alternative to full file scan.

| Parameter | Type | Default | Enum | Description |
|-----------|------|---------|------|-------------|
| `scope` | string | `uploads` | `uploads`, `plugins`, `themes`, `all` | Directories to scan |
| `max_files` | integer | `25` | — | Max results (1–200) |
| `max_file_size` | integer | `262144` | — | Max file size in bytes (4KB–1MB) |
| `with_hashes` | boolean | `true` | — | Include SHA-256 hashes |
| `with_excerpt` | boolean | `false` | — | Include safe text excerpt |
| `async` | boolean | `false` | — | Queue in background |

**Response:** `{ success, scope, suspicious_count, items[]{path, size, risk_level, reasons[], sha256?} }`

---

#### 3. `aipatch/get-async-job-status`

Poll for the status and result of an async ability execution.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `job_id` | string | yes | Job ID from an async ability call |

**Response:** `{ success, job_id, status, result?, error? }`

---

#### 4. `aipatch/list-findings`

Query the persistent findings store with filters. Findings are deduplicated by SHA-256 fingerprint and tracked across scans.

| Parameter | Type | Default | Enum | Description |
|-----------|------|---------|------|-------------|
| `status` | string | `open` | `open`, `dismissed`, `resolved` | Finding lifecycle status |
| `severity` | string | — | `critical`, `high`, `medium`, `low`, `info` | Filter by severity |
| `category` | string | — | — | Filter by category/family |
| `limit` | integer | `50` | — | Max results (1–200) |

**Response:** `{ success, count, findings[] }`

---

#### 5. `aipatch/findings-stats`

Aggregate statistics across all findings — counts by status, severity, source, and category.

**Parameters:** none

**Response:** `{ success, stats{} }`

---

#### 6. `aipatch/findings-diff`

Compare findings over time: new findings appeared and findings resolved since a given datetime. Useful for monitoring scan-to-scan changes.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `since` | string | 24h ago | UTC datetime (`Y-m-d H:i:s`) |
| `source` | string | all | `file_scanner`, `scanner`, or empty for all |

**Response:** `{ success, new{count, findings[]}, resolved{count, findings[]} }`

---

#### 7. `aipatch/dismiss-finding` *(write)*

Mark a finding as dismissed (accepted risk). Finding status changes from `open` to `dismissed`.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fingerprint` | string | yes | SHA-256 fingerprint of the finding |

**Response:** `{ success, fingerprint }`

---

#### 8. `aipatch/start-file-scan`

Create a new malware/heuristic file scan job. Files are enumerated and stored as job items. Use `process-file-scan-batch` to advance.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `root` | string | ABSPATH | Scan root directory |
| `max_files` | integer | `10000` | Maximum files to enumerate |

**Response:** `{ success, job_id, message }`

---

#### 9. `aipatch/file-scan-progress`

Get progress percentage and status of a running file scan job.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `job_id` | string | yes | Job UUID |

**Response:** `{ success, job{status, progress, total_items, completed_items} }`

---

#### 10. `aipatch/file-scan-results`

Retrieve enriched results from a completed file scan. Each result includes decoded signals with family classification, layer scores, integrity flags, and core tampering indicators.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `job_id` | string | — | Job UUID (required) |
| `min_risk` | integer | `15` | Minimum risk score threshold |
| `limit` | integer | `100` | Max results (1–500) |

**Response per result:**
```json
{
  "file_path": "wp-includes/compromised.php",
  "risk_score": 92,
  "classification": "malicious",
  "family": "webshell",
  "family_label": "Web Shell",
  "family_confidence": "high",
  "risk_level": "malicious",
  "reasons": ["eval_base64_decode", "shell_exec_call"],
  "matched_rules": ["eval_obfuscated", "system_exec"],
  "context_flags": ["uploads_php"],
  "integrity_flags": ["core_file_modified"],
  "layer_scores": {"content": 85, "context": 60, "integrity": 80},
  "core_tampered": true,
  "unexpected_in_core": false,
  "core_checksum": "modified",
  "is_new": false,
  "is_modified": true
}
```

---

#### 11. `aipatch/process-file-scan-batch`

Process the next batch of files in a running scan job. Call repeatedly until job status is `completed`.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `job_id` | string | — | Job UUID (required) |
| `batch_size` | integer | `50` | Files per batch (1–200) |

**Response:** `{ success, processed, job{status, progress} }`

---

#### 12. `aipatch/baseline-build`

Build or refresh the known-good file hash baseline. Captures SHA-256 of every file with origin detection (core, plugin, theme, uploads, other).

**Parameters:** none

**Response:** `{ success, build_stats{}, baseline_stats{} }`

---

#### 13. `aipatch/baseline-diff`

Compare the current filesystem against the stored baseline. Detects modified, missing, and new files since the baseline was built.

**Parameters:** none

**Response:** `{ success, modified_count, missing_count, new_count, diff{modified[], missing[], new[]} }`

---

#### 14. `aipatch/baseline-stats`

Statistics about the stored file baseline: total entries, breakdown by origin type, last build time.

**Parameters:** none

**Response:** `{ success, stats{} }`

---

#### 15. `aipatch/list-jobs`

List scan and audit jobs with optional filters on type and status.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `job_type` | string | — | Filter by job type (e.g. `file_scan`) |
| `status` | string | — | Filter by status (e.g. `completed`) |
| `limit` | integer | `20` | Max results |

**Response:** `{ success, count, jobs[] }`

---

#### 16. `aipatch/apply-remediation` *(write)*

Apply a security fix for a finding. The engine stores a full rollback snapshot before applying any changes.

| Parameter | Type | Required | Enum | Description |
|-----------|------|----------|------|-------------|
| `finding_fingerprint` | string | yes | — | SHA-256 fingerprint of the finding |
| `action_type` | string | yes | `wp_option`, `delete_file`, `rename_file`, `file_patch`, `htaccess_rule`, `manual` | Fix type |
| `description` | string | — | — | Human-readable description |
| `params` | object | — | — | Action-specific parameters |

**Response:** `{ success, remediation{id, status, action_type} }`

---

#### 17. `aipatch/rollback-remediation` *(write)*

Undo a previously applied remediation. Restores the original state from stored rollback data and reopens the linked finding.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `remediation_id` | integer | yes | Remediation record ID |

**Response:** `{ success, remediation{id, status} }`

---

#### 18. `aipatch/list-remediations`

List remediation records with optional filters.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `finding_fingerprint` | string | — | Filter by finding |
| `action_type` | string | — | Filter by action type |
| `status` | string | — | Filter by status |
| `limit` | integer | `50` | Max results |
| `offset` | integer | `0` | Pagination offset |

**Response:** `{ success, count, remediations[] }`

---

#### 19. `aipatch/verify-core-integrity`

Verify all WordPress core files against official checksums downloaded from `api.wordpress.org/core/checksums/1.0/`. Detects modified core files, missing core files, and unexpected files planted in `wp-admin/` or `wp-includes/`.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `force_refresh` | boolean | `false` | Bypass cached checksums (12h TTL) |

**Response:**
```json
{
  "success": true,
  "wp_version": "6.7.1",
  "checksums_available": true,
  "verified": false,
  "modified_count": 1,
  "missing_count": 0,
  "unexpected_count": 2,
  "modified": [{"file": "wp-includes/version.php", "expected_md5": "abc...", "actual_md5": "def..."}],
  "missing": [],
  "unexpected": ["wp-includes/backdoor.php", "wp-admin/shell.php"]
}
```

---

#### 20. `aipatch/list-suspicious-files`

Retrieve enriched suspicious files from the latest completed file scan. Automatically finds the most recent `file_scan` job — no job_id needed.

| Parameter | Type | Default | Enum | Description |
|-----------|------|---------|------|-------------|
| `min_risk` | integer | `30` | — | Minimum risk score (1–100) |
| `classification` | string | — | `suspicious`, `risky`, `malicious` | Filter by classification |
| `limit` | integer | `50` | — | Max results (1–200) |

**Response:** `{ success, job_id, scan_completed_at, filters{}, count, files[], stats{} }`

Each file includes: family, family_label, family_confidence, reasons, matched_rules, context_flags, integrity_flags, layer_scores, core_tampered, unexpected_in_core.

---

#### 21. `aipatch/get-file-finding-detail`

Get full detail for a single finding by its fingerprint. Returns all stored fields plus decoded `meta` object with family classification, layer scores, integrity flags, and core tampering data.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fingerprint` | string | yes | SHA-256 fingerprint of the finding |

**Response:**
```json
{
  "success": true,
  "finding": {
    "finding_id": "file_scan:wp-includes/compromised.php",
    "fingerprint": "a1b2c3...",
    "title": "Core file tampered — wp-includes/compromised.php",
    "severity": "critical",
    "confidence": "high",
    "category": "modified_core",
    "status": "open",
    "source": "file_scanner",
    "description": "WordPress core file has been modified...",
    "why_it_matters": "Modified core files are a strong indicator of compromise...",
    "recommendation": "Reinstall WordPress core files immediately...",
    "evidence": "eval_obfuscated, system_exec",
    "fixable": 1,
    "false_positive_likelihood": "none",
    "meta": {
      "risk_score": 92,
      "family": "modified_core",
      "family_label": "Modified Core File",
      "core_tampered": true,
      "layer_scores": {"content": 85, "context": 60, "integrity": 80}
    }
  }
}
```

---

#### 22. `aipatch/get-scan-summary`

Comprehensive summary of the latest completed file scan: job metadata, classification breakdown, findings synchronization stats, and core integrity status.

**Parameters:** none

**Response:**
```json
{
  "success": true,
  "job_id": "uuid",
  "job_status": "completed",
  "started_at": "2026-04-17 10:00:00",
  "completed_at": "2026-04-17 10:02:34",
  "scan_stats": {
    "total_files": 4521,
    "max_risk_score": 92,
    "by_classification": {"clean": 4510, "suspicious": 6, "risky": 3, "malicious": 2}
  },
  "findings_stats": {"open": 11, "critical": 2, "high": 3},
  "core_integrity": {"verified": false, "modified_count": 1, "unexpected_count": 2}
}
```

---

#### 23. `aipatch/get-baseline-drift`

Combined integrity report merging file baseline drift detection with official WordPress core integrity verification.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_core_check` | boolean | `true` | Include WP core checksum verification |

**Response:**
```json
{
  "success": true,
  "baseline_stats": {"total_entries": 4521, "last_built": "2026-04-16"},
  "drift": {
    "modified_count": 3,
    "missing_count": 0,
    "new_count": 7,
    "modified": ["..."],
    "new": ["..."]
  },
  "core_integrity": {
    "wp_version": "6.7.1",
    "verified": false,
    "modified_count": 1,
    "unexpected_count": 2,
    "modified": ["..."],
    "unexpected": ["..."]
  }
}
```

---

## Typical AI Agent Workflows

### Full Site Assessment

```
1. aipatch/audit-site                    → Site score + 36-check issues
2. aipatch/verify-core-integrity         → Core file tampering check
3. aipatch/list-findings {severity:critical} → Critical open findings
```

### Deep Malware Scan

```
1. aipatch/baseline-build                → Establish known-good state
2. aipatch/start-file-scan               → Create scan job
3. aipatch/process-file-scan-batch (×N)  → Process all files
4. aipatch/get-scan-summary              → Overview of results
5. aipatch/list-suspicious-files         → Enriched suspicious files
6. aipatch/get-file-finding-detail       → Deep-dive on specific finding
7. aipatch/apply-remediation             → Fix the issue
```

### Ongoing Monitoring

```
1. aipatch/get-baseline-drift            → What changed since baseline?
2. aipatch/findings-diff {since: "..."}  → New/resolved findings since last check
3. aipatch/findings-stats                → Current security posture
```

---

## File Structure

```
aipatch-security-scanner/
├── aipatch-security-scanner.php          Main plugin file
├── uninstall.php                         Clean uninstall (drops all 9 tables)
├── readme.txt                            WordPress.org readme
├── admin/
│   └── partials/                         Admin dashboard templates
├── assets/
│   ├── css/admin.css                     Admin styles
│   └── js/admin.js                       Admin JavaScript
├── includes/
│   ├── class-aipsc-loader.php            Module orchestrator
│   ├── class-aipsc-abilities.php         23 MCP abilities
│   ├── class-aipsc-scanner.php           Audit engine bridge
│   ├── class-aipsc-file-scanner.php      Multi-layer file scanner
│   ├── class-aipsc-file-heuristics.php   Content pattern analysis
│   ├── class-aipsc-file-classifier.php   Family classification engine
│   ├── class-aipsc-core-verifier.php     WP core checksum verification
│   ├── class-aipsc-file-baseline.php     File hash baseline
│   ├── class-aipsc-findings-store.php    Persistent findings store
│   ├── class-aipsc-remediation-engine.php  Apply/rollback fixes
│   ├── class-aipsc-job-manager.php       Async batch processing
│   ├── class-aipsc-hardening.php         5 hardening rules
│   ├── class-aipsc-vulnerabilities.php   Vulnerability tracking
│   ├── class-aipsc-rest.php              REST API endpoints
│   ├── class-aipsc-settings.php          Module toggles
│   ├── class-aipsc-logger.php            Event logging
│   ├── class-aipsc-installer.php         DB migrations
│   ├── class-aipsc-dashboard.php         Admin dashboard
│   ├── class-aipsc-admin.php             Admin pages
│   ├── class-aipsc-cron.php              Scheduled scans
│   ├── class-aipsc-site-health.php       WP Site Health integration
│   └── audit/
│       ├── class-aipsc-audit-engine.php  Check runner
│       ├── class-aipsc-score-engine.php  Score calculator
│       ├── class-aipsc-audit-check-registry.php
│       └── checks/                       36 individual check classes
└── languages/                            i18n files
```
