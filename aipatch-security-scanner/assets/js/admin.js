/**
 * Aipatch Security Scanner – Admin JavaScript
 *
 * @package AipatchSecurityScanner
 */

(function () {
    'use strict';

    var config = window.aipatchAdmin || {};

    /**
     * Make a REST API request.
     *
     * @param {string} endpoint  Endpoint path (e.g., '/run-scan').
     * @param {string} method    HTTP method.
     * @param {Object} body      Request body (for POST).
     * @return {Promise}
     */
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
            .then(function (response) {
                if (!response.ok) {
                    throw new Error(response.statusText);
                }
                return response.json();
            });
    }

    /**
     * Initialize run scan button behavior.
     */
    function initRunScan() {
        var btn = document.getElementById('aipatch-run-scan');
        if (!btn) return;

        // The scan uses a form POST, but add a loading state.
        btn.closest('form').addEventListener('submit', function () {
            btn.disabled = true;
            btn.innerHTML = '<span class="dashicons dashicons-update aipatch-spin"></span> ' + config.i18n.scanning;
        });
    }

    /**
     * Initialize run performance diagnostics button behavior.
     */
    function initRunPerformance() {
        var btn = document.getElementById('aipatch-run-perf');
        if (!btn) return;

        btn.closest('form').addEventListener('submit', function () {
            btn.disabled = true;
            btn.innerHTML = '<span class="dashicons dashicons-update aipatch-spin"></span> ' + config.i18n.scanning;
        });
    }

    /**
     * Initialize REST-based hardening toggles (progressive enhancement).
     * Falls back to form POST if JS fails.
     */
    function initHardeningToggles() {
        var toggles = document.querySelectorAll('.aipatch-toggle-btn[data-rest]');

        toggles.forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.preventDefault();

                var key = btn.dataset.key;
                var currentValue = btn.classList.contains('aipatch-toggle-on');
                var newValue = !currentValue;

                btn.disabled = true;

                apiRequest('/toggle-hardening', 'POST', {
                    key: key,
                    value: newValue
                })
                .then(function (data) {
                    if (data.success) {
                        btn.classList.toggle('aipatch-toggle-on', newValue);
                        btn.classList.toggle('aipatch-toggle-off', !newValue);

                        // Update the parent container's active state.
                        var item = btn.closest('.aipatch-hardening-item');
                        if (item) {
                            item.classList.toggle('aipatch-hardening-active', newValue);
                        }
                    }
                })
                .catch(function () {
                    // Fall back to form submission.
                    var form = btn.closest('form');
                    if (form) form.submit();
                })
                .finally(function () {
                    btn.disabled = false;
                });
            });
        });
    }

    /**
     * Initialize dismiss buttons via REST (progressive enhancement).
     */
    function initDismissButtons() {
        var dismissBtns = document.querySelectorAll('[data-dismiss-rest]');

        dismissBtns.forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.preventDefault();

                var issueId = btn.dataset.issueId;

                apiRequest('/dismiss-issue', 'POST', {
                    issue_id: issueId
                })
                .then(function (data) {
                    if (data.success) {
                        var item = btn.closest('.aipatch-recommendation');
                        if (item) {
                            item.style.opacity = '0.5';
                            item.style.pointerEvents = 'none';
                        }
                    }
                })
                .catch(function () {
                    // Fall back to form submission.
                    var form = btn.closest('form');
                    if (form) form.submit();
                });
            });
        });
    }

    /* ---------------------------------------------------------------
     * Score Trend Chart (lightweight – no external library)
     * Uses <canvas> to draw a simple line chart.
     * ------------------------------------------------------------- */

    function initScoreChart() {
        var canvas = document.getElementById('aipatch-score-chart');
        if (!canvas) return;

        var emptyMsg = document.querySelector('.aipatch-chart-empty');

        apiRequest('/scan-history', 'GET')
            .then(function (res) {
                if (!res.success || !res.data || res.data.length < 2) {
                    canvas.style.display = 'none';
                    if (emptyMsg) emptyMsg.style.display = '';
                    return;
                }
                drawChart(canvas, res.data);
            })
            .catch(function () {
                canvas.style.display = 'none';
                if (emptyMsg) emptyMsg.style.display = '';
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

        // Background.
        ctx.fillStyle = '#fff';
        ctx.fillRect(0, 0, W, H);

        // Grid lines.
        ctx.strokeStyle = '#e2e4e7';
        ctx.lineWidth = 1;
        for (var g = 0; g <= 4; g++) {
            var gy = pad.top + (chartH / 4) * g;
            ctx.beginPath();
            ctx.moveTo(pad.left, gy);
            ctx.lineTo(W - pad.right, gy);
            ctx.stroke();
        }

        // Y-axis labels (score).
        ctx.fillStyle = '#50575e';
        ctx.font = '11px -apple-system, BlinkMacSystemFont, sans-serif';
        ctx.textAlign = 'right';
        for (var l = 0; l <= 4; l++) {
            ctx.fillText(100 - l * 25, pad.left - 6, pad.top + (chartH / 4) * l + 4);
        }

        // X-axis labels.
        ctx.textAlign = 'center';
        var step = Math.max(1, Math.floor(labels.length / 8));
        for (var xi = 0; xi < labels.length; xi += step) {
            var lx = pad.left + (chartW / (labels.length - 1)) * xi;
            ctx.fillText(labels[xi], lx, H - 6);
        }

        // Issues bars.
        var barW = Math.max(2, (chartW / labels.length) * 0.4);
        ctx.fillStyle = 'rgba(219, 166, 23, 0.25)';
        for (var bi = 0; bi < issues.length; bi++) {
            var bx = pad.left + (chartW / (issues.length - 1)) * bi - barW / 2;
            var bh = (issues[bi] / maxIssues) * chartH;
            ctx.fillRect(bx, pad.top + chartH - bh, barW, bh);
        }

        // Score line.
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

        // Score dots.
        ctx.fillStyle = '#2271b1';
        for (var di = 0; di < scores.length; di++) {
            var dx = pad.left + (chartW / (scores.length - 1)) * di;
            var dy = pad.top + chartH - (scores[di] / 100) * chartH;
            ctx.beginPath();
            ctx.arc(dx, dy, 3.5, 0, Math.PI * 2);
            ctx.fill();
        }

        // Legend.
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

    /* ---------------------------------------------------------------
     * CSV Export
     * ------------------------------------------------------------- */

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
        var exportScans = document.getElementById('aipatch-export-scans');
        if (exportScans) {
            exportScans.addEventListener('click', function () {
                exportScans.disabled = true;
                apiRequest('/export-scans', 'GET')
                    .then(function (res) {
                        if (res.success) {
                            downloadCsv(res.filename, res.data);
                        }
                    })
                    .catch(function () { alert(config.i18n.error); })
                    .finally(function () { exportScans.disabled = false; });
            });
        }

        var exportLogs = document.getElementById('aipatch-export-logs');
        if (exportLogs) {
            exportLogs.addEventListener('click', function () {
                exportLogs.disabled = true;
                apiRequest('/export-logs', 'GET')
                    .then(function (res) {
                        if (res.success) {
                            downloadCsv(res.filename, res.data);
                        }
                    })
                    .catch(function () { alert(config.i18n.error); })
                    .finally(function () { exportLogs.disabled = false; });
            });
        }
    }

    /**
     * Add a loading spinner animation.
     */
    function addSpinnerStyle() {
        var style = document.createElement('style');
        style.textContent = '@keyframes aipatch-spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}.aipatch-spin{animation:aipatch-spin 1s linear infinite;}';
        document.head.appendChild(style);
    }

    /**
     * Initialize on DOM ready.
     */
    function init() {
        addSpinnerStyle();
        initRunScan();
        initRunPerformance();
        initHardeningToggles();
        initDismissButtons();
        initScoreChart();
        initExportButtons();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
