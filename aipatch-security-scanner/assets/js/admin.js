/**
 * Aipatch Security Scanner – Admin JavaScript
 *
 * AJAX-first dashboard, step-by-step scan with progress, lazy chart.
 *
 * @package AipatchSecurityScanner
 */

(function () {
    'use strict';

    var config = window.aipatchAdmin || {};
    var i18n   = config.i18n || {};

    /* -----------------------------------------------------------
     * Helpers
     * --------------------------------------------------------- */

    function apiRequest(endpoint, method, body) {
        var options = {
            method: method || 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-WP-Nonce': config.nonce
            }
        };
        if (body && method === 'POST') {
            options.body = JSON.stringify(body);
        }
        return fetch(config.restUrl + endpoint, options)
            .then(function (r) {
                if (!r.ok) throw new Error(r.statusText);
                return r.json();
            });
    }

    function esc(str) {
        var d = document.createElement('div');
        d.textContent = String(str);
        return d.innerHTML;
    }

    function $(id) { return document.getElementById(id); }

    /* -----------------------------------------------------------
     * Scan step definitions (client-side)
     * --------------------------------------------------------- */

    var SCAN_STEPS = {
        quick: [
            { id: 'software', categories: ['core', 'plugins', 'themes'] },
            { id: 'users',    categories: ['users', 'access_control'] }
        ],
        standard: [
            { id: 'software', categories: ['core', 'plugins', 'themes'] },
            { id: 'users',    categories: ['users', 'access_control'] },
            { id: 'config',   categories: ['configuration'] },
            { id: 'server',   categories: ['server'] },
            { id: 'surface',  categories: ['malware_surface'] }
        ],
        deep: [
            { id: 'software', categories: ['core', 'plugins', 'themes'] },
            { id: 'users',    categories: ['users', 'access_control'] },
            { id: 'config',   categories: ['configuration'] },
            { id: 'server',   categories: ['server'] },
            { id: 'surface',  categories: ['malware_surface'] }
        ]
    };

    var STEP_LABELS = {
        software: 'stepSoftware',
        users:    'stepUsers',
        config:   'stepConfig',
        server:   'stepServer',
        surface:  'stepSurface',
        files:    'stepFiles'
    };

    /* -----------------------------------------------------------
     * AJAX Dashboard Load
     * --------------------------------------------------------- */

    function initDashboard() {
        if (!$('aipatch-score-card')) return;

        apiRequest('/get-summary', 'GET')
            .then(function (res) {
                if (res.success && res.data) {
                    populateDashboard(res.data);
                }
            })
            .catch(function () {
                var n = $('aipatch-notices');
                if (n) n.innerHTML = '<div class="notice notice-error"><p>' + esc(i18n.error) + '</p></div>';
            });
    }

    function populateDashboard(data) {
        // Score card
        var scoreCard = $('aipatch-score-card');
        if (scoreCard) {
            scoreCard.className = 'aipatch-score-card ' + (data.score_class || '');
            var circle = scoreCard.querySelector('.aipatch-score-circle');
            if (circle) circle.classList.remove('aipatch-skeleton-pulse');
        }

        var sn = $('aipatch-score-number');
        if (sn) sn.textContent = data.score;

        var sl = $('aipatch-score-label');
        if (sl) sl.textContent = data.score_label || '';

        var sd = $('aipatch-score-date');
        if (sd) {
            sd.textContent = data.has_scan
                ? (i18n.lastScan + ': ' + data.last_scan_formatted)
                : i18n.noScanYet;
        }

        // Next scan
        var ns = $('aipatch-next-scan');
        if (ns && data.next_scan_formatted) {
            ns.textContent = i18n.nextScan + ': ' + data.next_scan_formatted;
        }

        // Summary cards
        populateCards(data.summary);

        // Recommendations
        if (data.recommendations && data.recommendations.length > 0) {
            populateRecommendations(data.recommendations);
        } else if (data.has_scan) {
            var ac = $('aipatch-all-clear');
            if (ac) ac.style.display = '';
        }

        // Dismissed
        if (data.dismissed_issues && data.dismissed_issues.length > 0) {
            populateDismissed(data.dismissed_issues);
        }

        // Chart
        initScoreChart();
    }

    /* -----------------------------------------------------------
     * Summary Cards
     * --------------------------------------------------------- */

    function populateCards(s) {
        if (!s) return;
        var grid = $('aipatch-cards-grid');
        if (!grid) return;

        var cards = [
            { icon: 'admin-plugins',    val: s.active_plugins,    lbl: i18n.activePlugins },
            { icon: 'warning',          val: s.outdated_plugins,  lbl: i18n.pluginsOutdated,  warn: s.outdated_plugins > 0 },
            { icon: 'plugins-checked',  val: s.inactive_plugins || 0, lbl: i18n.inactivePlugins, warn: (s.inactive_plugins || 0) > 3 },
            { icon: 'admin-appearance', val: s.outdated_themes,   lbl: i18n.themesOutdated,   warn: s.outdated_themes > 0 },
            { icon: 'wordpress',        val: s.wp_version,        lbl: i18n.wpVersion },
            { icon: 'admin-users',      val: s.admin_count,       lbl: i18n.adminUsers },
            { icon: 'database',         val: s.db_prefix_default ? i18n.default_ : i18n.custom, lbl: i18n.dbPrefix, warn: s.db_prefix_default },
            { icon: s.xmlrpc_disabled ? 'lock' : 'unlock', val: s.xmlrpc_disabled ? i18n.disabled : i18n.enabled, lbl: i18n.xmlrpc, warn: !s.xmlrpc_disabled },
            { icon: 'rest-api',         val: s.rest_restricted ? i18n.restricted : i18n.public_, lbl: i18n.restApi, info: !s.rest_restricted },
            { icon: s.debug_active ? 'warning' : 'yes-alt', val: s.debug_active ? i18n.active : i18n.off, lbl: i18n.debugMode, danger: s.debug_active },
            { icon: 'editor-code',      val: s.file_editor_off ? i18n.disabled : i18n.enabled, lbl: i18n.fileEditor, warn: !s.file_editor_off },
            { icon: s.login_protected ? 'shield' : 'shield-alt', val: s.login_protected ? i18n.protected_ : i18n.open, lbl: i18n.loginProtection, warn: !s.login_protected },
            { icon: 'update',           val: s.auto_updates_core ? i18n.on : i18n.off, lbl: i18n.coreAutoUpdates, warn: !s.auto_updates_core }
        ];

        if (s.total_checks) {
            cards.push({ icon: 'search', val: s.total_checks, lbl: i18n.securityChecks });
        }

        var html = '';
        cards.forEach(function (c) {
            var cls = 'aipatch-card';
            if (c.warn)   cls += ' aipatch-card-warning';
            if (c.danger) cls += ' aipatch-card-danger';
            if (c.info)   cls += ' aipatch-card-info';
            html += '<div class="' + cls + '">'
                + '<div class="aipatch-card-icon dashicons dashicons-' + esc(c.icon) + '"></div>'
                + '<div class="aipatch-card-content">'
                + '<span class="aipatch-card-value">' + esc(c.val) + '</span>'
                + '<span class="aipatch-card-label">' + esc(c.lbl) + '</span>'
                + '</div></div>';
        });

        grid.innerHTML = html;
    }

    /* -----------------------------------------------------------
     * Recommendations
     * --------------------------------------------------------- */

    function populateRecommendations(recs) {
        var section = $('aipatch-recommendations-section');
        var el = $('aipatch-recommendations');
        if (!section || !el) return;

        var sevClasses = { critical: 'aipatch-severity-critical', high: 'aipatch-severity-high', medium: 'aipatch-severity-medium', low: 'aipatch-severity-low', info: 'aipatch-severity-info' };

        var html = '';
        recs.forEach(function (r) {
            var badgeCls = sevClasses[r.severity] || sevClasses.info;
            html += '<div class="aipatch-recommendation">'
                + '<div class="aipatch-rec-header">'
                + '<span class="aipatch-badge ' + badgeCls + '">' + esc(r.severity) + '</span>'
                + '<strong>' + esc(r.title) + '</strong>'
                + '</div>'
                + '<p>' + esc(r.recommendation) + '</p>';
            if (r.dismissible) {
                html += '<div class="aipatch-rec-actions">'
                    + '<button type="button" class="button button-small" data-dismiss-id="' + esc(r.id) + '">' + esc(i18n.dismiss) + '</button>'
                    + '</div>';
            }
            html += '</div>';
        });

        el.innerHTML = html;
        section.style.display = '';

        // Bind dismiss buttons
        el.querySelectorAll('[data-dismiss-id]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var issueId = btn.getAttribute('data-dismiss-id');
                btn.disabled = true;
                apiRequest('/dismiss-issue', 'POST', { issue_id: issueId })
                    .then(function (res) {
                        if (res.success) {
                            var item = btn.closest('.aipatch-recommendation');
                            if (item) { item.style.opacity = '0.4'; item.style.pointerEvents = 'none'; }
                        }
                    })
                    .catch(function () { btn.disabled = false; });
            });
        });
    }

    /* -----------------------------------------------------------
     * Dismissed Issues
     * --------------------------------------------------------- */

    function populateDismissed(issues) {
        var section = $('aipatch-dismissed-section');
        var title   = $('aipatch-dismissed-title');
        var list    = $('aipatch-dismissed-list');
        if (!section || !list || !issues.length) return;

        if (title) {
            title.textContent = i18n.dismissedCount.replace('%d', issues.length);
        }

        var html = '';
        issues.forEach(function (iss) {
            html += '<div class="aipatch-dismissed-item">'
                + '<span>' + esc(iss.title) + '</span>'
                + '<button type="button" class="button button-small button-link" data-restore-id="' + esc(iss.id) + '">' + esc(i18n.restore) + '</button>'
                + '</div>';
        });
        list.innerHTML = html;
        section.style.display = '';

        list.querySelectorAll('[data-restore-id]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                btn.disabled = true;
                apiRequest('/restore-issue', 'POST', { issue_id: btn.getAttribute('data-restore-id') })
                    .then(function () { initDashboard(); })
                    .catch(function () { btn.disabled = false; });
            });
        });
    }

    /* -----------------------------------------------------------
     * Step-by-Step Scan Engine
     * --------------------------------------------------------- */

    var currentScanId = null;
    var scanCancelled = false;

    function initScanPanel() {
        var btn = $('aipatch-run-scan');
        if (!btn) return;

        // Level selector highlight
        var levels = document.querySelectorAll('.aipatch-scan-level input');
        levels.forEach(function (radio) {
            radio.addEventListener('change', function () {
                document.querySelectorAll('.aipatch-scan-level-card').forEach(function (c) { c.classList.remove('aipatch-scan-level-selected'); });
                var card = radio.nextElementSibling;
                if (card) card.classList.add('aipatch-scan-level-selected');
            });
            // Set initial selection
            if (radio.checked) {
                var card = radio.nextElementSibling;
                if (card) card.classList.add('aipatch-scan-level-selected');
            }
        });

        btn.addEventListener('click', function () {
            var checked = document.querySelector('input[name="aipatch_scan_level"]:checked');
            if (!checked) return;
            startScan(checked.value);
        });
    }

    function startScan(level) {
        var steps = SCAN_STEPS[level];
        if (!steps) return;

        scanCancelled = false;

        // Hide scan panel, show progress
        var panel = $('aipatch-scan-panel');
        var prog  = $('aipatch-scan-progress');
        if (panel) panel.style.display = 'none';
        if (prog)  prog.style.display = '';

        // Reset progress
        updateProgressBar(0);
        var titleEl = $('aipatch-progress-title');
        if (titleEl) titleEl.textContent = i18n.initializing;
        var iconEl = $('aipatch-progress-icon');
        if (iconEl) { iconEl.className = 'dashicons dashicons-update aipatch-spin'; }

        // Build step list UI
        var stepsEl = $('aipatch-progress-steps');
        if (stepsEl) {
            var html = '';
            steps.forEach(function (step, i) {
                var label = i18n[STEP_LABELS[step.id]] || step.id;
                html += '<div class="aipatch-step aipatch-step-pending" id="aipatch-step-' + i + '">'
                    + '<span class="aipatch-step-icon dashicons dashicons-marker"></span>'
                    + '<span class="aipatch-step-label">' + esc(label) + '</span>'
                    + '<span class="aipatch-step-time"></span>'
                    + '</div>';
            });
            stepsEl.innerHTML = html;
        }

        // Start scan session
        apiRequest('/start-scan', 'POST', { level: level })
            .then(function (res) {
                if (!res.success) throw new Error(res.message || i18n.error);
                currentScanId = res.scan_id;
                return runSteps(steps, res.scan_id, 0);
            })
            .then(function () {
                if (scanCancelled) return;
                return finishScan(currentScanId);
            })
            .catch(function (err) {
                showScanError(err.message || i18n.scanFailed);
            });
    }

    function runSteps(steps, scanId, index) {
        if (scanCancelled || index >= steps.length) return Promise.resolve();

        var step = steps[index];
        var total = steps.length;

        // Mark step as running
        var stepEl = $('aipatch-step-' + index);
        if (stepEl) {
            stepEl.className = 'aipatch-step aipatch-step-running';
            var icon = stepEl.querySelector('.aipatch-step-icon');
            if (icon) icon.className = 'aipatch-step-icon dashicons dashicons-update aipatch-spin';
        }

        var titleEl = $('aipatch-progress-title');
        if (titleEl) titleEl.textContent = i18n[STEP_LABELS[step.id]] || step.id;

        return apiRequest('/scan-step', 'POST', {
            scan_id: scanId,
            categories: step.categories,
            step_index: index,
            total_steps: total
        }).then(function (res) {
            if (!res.success) throw new Error(res.message || i18n.error);

            // Mark step done
            if (stepEl) {
                stepEl.className = 'aipatch-step aipatch-step-done';
                var ic = stepEl.querySelector('.aipatch-step-icon');
                if (ic) ic.className = 'aipatch-step-icon dashicons dashicons-yes-alt';
                var timeEl = stepEl.querySelector('.aipatch-step-time');
                if (timeEl) {
                    var parts = [];
                    if (res.checks_run) parts.push(res.checks_run + ' ' + i18n.checks);
                    if (res.issues_found) parts.push(res.issues_found + ' ' + i18n.issues);
                    if (res.step_duration_ms) parts.push((res.step_duration_ms / 1000).toFixed(1) + 's');
                    timeEl.textContent = parts.join(' \u00b7 ');
                }
            }

            updateProgressBar(res.progress);

            // Next step
            return runSteps(steps, scanId, index + 1);
        });
    }

    function finishScan(scanId) {
        var titleEl = $('aipatch-progress-title');
        if (titleEl) titleEl.textContent = i18n.computing;
        updateProgressBar(100);

        return apiRequest('/finish-scan', 'POST', { scan_id: scanId })
            .then(function (res) {
                if (!res.success) throw new Error(res.message || i18n.error);
                showScanComplete(res);
                // Reload dashboard data after a brief moment
                setTimeout(function () {
                    initDashboard();
                    resetScanPanel();
                }, 2500);
            });
    }

    function updateProgressBar(pct) {
        var bar = $('aipatch-progress-bar');
        var pctEl = $('aipatch-progress-pct');
        if (bar) bar.style.width = pct + '%';
        if (pctEl) pctEl.textContent = pct + '%';
    }

    function showScanComplete(res) {
        var titleEl = $('aipatch-progress-title');
        var iconEl  = $('aipatch-progress-icon');
        if (titleEl) {
            titleEl.textContent = i18n.scanComplete + ' \u2014 Score: ' + res.score
                + ' (' + res.issues_count + ' ' + i18n.issues + ', '
                + (res.duration_ms / 1000).toFixed(1) + 's)';
        }
        if (iconEl) iconEl.className = 'dashicons dashicons-yes-alt';
    }

    function showScanError(msg) {
        var titleEl = $('aipatch-progress-title');
        var iconEl  = $('aipatch-progress-icon');
        if (titleEl) titleEl.textContent = i18n.scanFailed + ': ' + msg;
        if (iconEl) iconEl.className = 'dashicons dashicons-warning';
        setTimeout(resetScanPanel, 4000);
    }

    function resetScanPanel() {
        var panel = $('aipatch-scan-panel');
        var prog  = $('aipatch-scan-progress');
        if (panel) panel.style.display = '';
        if (prog)  prog.style.display = 'none';
        currentScanId = null;
    }

    /* -----------------------------------------------------------
     * Score Trend Chart (lightweight canvas)
     * --------------------------------------------------------- */

    function initScoreChart() {
        var canvas = $('aipatch-score-chart');
        var section = $('aipatch-chart-section');
        if (!canvas || !section) return;

        var emptyMsg = document.querySelector('.aipatch-chart-empty');

        apiRequest('/scan-history', 'GET')
            .then(function (res) {
                if (!res.success || !res.data || res.data.length < 2) {
                    // Hide chart section entirely — no blank space
                    section.style.display = 'none';
                    return;
                }
                // Show section with animation
                section.style.display = '';
                requestAnimationFrame(function () {
                    section.classList.add('aipatch-chart-visible');
                });
                drawChart(canvas, res.data);
            })
            .catch(function () {
                section.style.display = 'none';
            });
    }

    function drawChart(canvas, data) {
        var ctx = canvas.getContext('2d');
        var dpr = window.devicePixelRatio || 1;
        var rect = canvas.parentElement.getBoundingClientRect();

        canvas.width = rect.width * dpr;
        canvas.height = 200 * dpr;
        canvas.style.width = rect.width + 'px';
        canvas.style.height = '200px';
        ctx.scale(dpr, dpr);

        var W = rect.width;
        var H = 200;
        var pad = { top: 20, right: 20, bottom: 30, left: 40 };
        var chartW = W - pad.left - pad.right;
        var chartH = H - pad.top - pad.bottom;

        var scores = data.map(function (d) { return parseInt(d.score, 10); });
        var issues = data.map(function (d) { return parseInt(d.issues_count, 10); });
        var labels = data.map(function (d) {
            var dt = new Date(d.created_at.replace(' ', 'T') + 'Z');
            return (dt.getMonth() + 1) + '/' + dt.getDate();
        });

        var maxIssues = Math.max.apply(null, issues) || 1;

        ctx.fillStyle = '#fff';
        ctx.fillRect(0, 0, W, H);

        // Grid lines
        ctx.strokeStyle = '#e2e4e7';
        ctx.lineWidth = 1;
        for (var g = 0; g <= 4; g++) {
            var gy = pad.top + (chartH / 4) * g;
            ctx.beginPath();
            ctx.moveTo(pad.left, gy);
            ctx.lineTo(W - pad.right, gy);
            ctx.stroke();
        }

        // Y-axis labels
        ctx.fillStyle = '#50575e';
        ctx.font = '11px -apple-system, BlinkMacSystemFont, sans-serif';
        ctx.textAlign = 'right';
        for (var l = 0; l <= 4; l++) {
            ctx.fillText(100 - l * 25, pad.left - 6, pad.top + (chartH / 4) * l + 4);
        }

        // X-axis labels
        ctx.textAlign = 'center';
        var step = Math.max(1, Math.floor(labels.length / 8));
        for (var xi = 0; xi < labels.length; xi += step) {
            var lx = pad.left + (chartW / (labels.length - 1)) * xi;
            ctx.fillText(labels[xi], lx, H - 6);
        }

        // Issues bars
        var barW = Math.max(2, (chartW / labels.length) * 0.4);
        ctx.fillStyle = 'rgba(219, 166, 23, 0.25)';
        for (var bi = 0; bi < issues.length; bi++) {
            var bx = pad.left + (chartW / (issues.length - 1)) * bi - barW / 2;
            var bh = (issues[bi] / maxIssues) * chartH;
            ctx.fillRect(bx, pad.top + chartH - bh, barW, bh);
        }

        // Score line
        ctx.strokeStyle = '#2271b1';
        ctx.lineWidth = 2.5;
        ctx.lineJoin = 'round';
        ctx.beginPath();
        for (var si = 0; si < scores.length; si++) {
            var sx = pad.left + (chartW / (scores.length - 1)) * si;
            var sy = pad.top + chartH - (scores[si] / 100) * chartH;
            if (si === 0) ctx.moveTo(sx, sy);
            else ctx.lineTo(sx, sy);
        }
        ctx.stroke();

        // Score dots
        ctx.fillStyle = '#2271b1';
        for (var di = 0; di < scores.length; di++) {
            var dx = pad.left + (chartW / (scores.length - 1)) * di;
            var dy = pad.top + chartH - (scores[di] / 100) * chartH;
            ctx.beginPath();
            ctx.arc(dx, dy, 3.5, 0, Math.PI * 2);
            ctx.fill();
        }

        // Legend
        ctx.font = '11px -apple-system, BlinkMacSystemFont, sans-serif';
        ctx.textAlign = 'left';
        ctx.fillStyle = '#2271b1';
        ctx.fillRect(pad.left, 4, 12, 3);
        ctx.fillText('Score', pad.left + 16, 10);
        ctx.fillStyle = 'rgba(219, 166, 23, 0.5)';
        ctx.fillRect(pad.left + 70, 4, 12, 8);
        ctx.fillStyle = '#50575e';
        ctx.fillText('Issues', pad.left + 86, 10);
    }

    /* -----------------------------------------------------------
     * CSV Export
     * --------------------------------------------------------- */

    function downloadCsv(filename, rows) {
        var csv = rows.map(function (row) {
            return row.map(function (cell) {
                var str = String(cell).replace(/"/g, '""');
                return '"' + str + '"';
            }).join(',');
        }).join('\r\n');

        var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        var link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = filename;
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

    function initExportButtons() {
        var exportScans = $('aipatch-export-scans');
        if (exportScans) {
            exportScans.addEventListener('click', function () {
                exportScans.disabled = true;
                apiRequest('/export-scans', 'GET')
                    .then(function (res) {
                        if (res.success) downloadCsv(res.filename, res.data);
                    })
                    .catch(function () { alert(i18n.error); })
                    .finally(function () { exportScans.disabled = false; });
            });
        }

        var exportLogs = $('aipatch-export-logs');
        if (exportLogs) {
            exportLogs.addEventListener('click', function () {
                exportLogs.disabled = true;
                apiRequest('/export-logs', 'GET')
                    .then(function (res) {
                        if (res.success) downloadCsv(res.filename, res.data);
                    })
                    .catch(function () { alert(i18n.error); })
                    .finally(function () { exportLogs.disabled = false; });
            });
        }
    }

    /* -----------------------------------------------------------
     * Hardening Toggles (progressive enhancement)
     * --------------------------------------------------------- */

    function initHardeningToggles() {
        var toggles = document.querySelectorAll('.aipatch-toggle-btn[data-rest]');

        toggles.forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.preventDefault();

                var key = btn.dataset.key;
                var currentValue = btn.classList.contains('aipatch-toggle-on');
                var newValue = !currentValue;

                btn.disabled = true;

                apiRequest('/toggle-hardening', 'POST', { key: key, value: newValue })
                    .then(function (data) {
                        if (data.success) {
                            btn.classList.toggle('aipatch-toggle-on', newValue);
                            btn.classList.toggle('aipatch-toggle-off', !newValue);
                            var item = btn.closest('.aipatch-hardening-item');
                            if (item) item.classList.toggle('aipatch-hardening-active', newValue);
                        }
                    })
                    .catch(function () {
                        var form = btn.closest('form');
                        if (form) form.submit();
                    })
                    .finally(function () { btn.disabled = false; });
            });
        });
    }

    /* -----------------------------------------------------------
     * Performance Run Button
     * --------------------------------------------------------- */

    function initRunPerformance() {
        var btn = $('aipatch-run-perf');
        if (!btn) return;
        btn.closest('form').addEventListener('submit', function () {
            btn.disabled = true;
            btn.innerHTML = '<span class="dashicons dashicons-update aipatch-spin"></span> ' + i18n.scanning;
        });
    }

    /* -----------------------------------------------------------
     * Init
     * --------------------------------------------------------- */

    function addSpinnerStyle() {
        var style = document.createElement('style');
        style.textContent = '@keyframes aipatch-spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}.aipatch-spin{animation:aipatch-spin 1s linear infinite;}';
        document.head.appendChild(style);
    }

    function init() {
        addSpinnerStyle();
        initDashboard();
        initScanPanel();
        initRunPerformance();
        initHardeningToggles();
        initExportButtons();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
