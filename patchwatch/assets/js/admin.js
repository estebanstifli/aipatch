/**
 * AI PatchWatch – Admin JavaScript
 *
 * @package PatchWatch
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
     * Initialize REST-based hardening toggles (optional enhancement).
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
                    }
                })
                .catch(function () {
                    alert(config.i18n.error);
                })
                .finally(function () {
                    btn.disabled = false;
                });
            });
        });
    }

    /**
     * Initialize dismiss/restore buttons via REST (progressive enhancement).
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
        initHardeningToggles();
        initDismissButtons();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
