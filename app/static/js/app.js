/* WaaS Self-Service Portal - Application JavaScript */

document.addEventListener('DOMContentLoaded', function () {

    // -------------------------------------------------------
    // Toast Notifications (7.9)
    // Initialize server-rendered toasts and provide global showToast()
    // -------------------------------------------------------
    document.querySelectorAll('.toast').forEach(function (el) {
        new bootstrap.Toast(el).show();
    });

    /**
     * Show a toast notification from JavaScript.
     * @param {string} message - The message to display
     * @param {string} [category='info'] - Bootstrap category: success, danger, warning, info
     */
    window.showToast = function (message, category) {
        category = category || 'info';
        var icons = {
            danger: '<i class="bi bi-exclamation-triangle"></i> ',
            success: '<i class="bi bi-check-circle"></i> ',
            warning: '<i class="bi bi-exclamation-circle"></i> ',
            info: '<i class="bi bi-info-circle"></i> '
        };
        var delay = category === 'danger' ? 8000 : 5000;
        var container = document.getElementById('toastContainer');
        if (!container) return;

        var toastEl = document.createElement('div');
        toastEl.className = 'toast align-items-center border-0 toast-' + category;
        toastEl.setAttribute('role', 'alert');
        toastEl.setAttribute('aria-live', 'assertive');
        toastEl.setAttribute('aria-atomic', 'true');
        toastEl.setAttribute('data-bs-autohide', 'true');
        toastEl.setAttribute('data-bs-delay', delay);
        toastEl.innerHTML =
            '<div class="d-flex">' +
                '<div class="toast-body">' + (icons[category] || '') + message + '</div>' +
                '<button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>' +
            '</div>';
        container.appendChild(toastEl);

        toastEl.addEventListener('hidden.bs.toast', function () {
            toastEl.remove();
        });
        new bootstrap.Toast(toastEl).show();
    };

    // -------------------------------------------------------
    // Loading Indicators (7.8)
    // Global overlay spinner for form submissions and AJAX
    // -------------------------------------------------------
    var loadingOverlay = document.getElementById('globalLoadingOverlay');
    var loadingMessage = loadingOverlay ? loadingOverlay.querySelector('.loading-message') : null;

    window.showLoading = function (message) {
        if (!loadingOverlay) return;
        if (loadingMessage) loadingMessage.textContent = message || 'Loading...';
        loadingOverlay.classList.remove('d-none');
    };

    window.hideLoading = function () {
        if (!loadingOverlay) return;
        loadingOverlay.classList.add('d-none');
    };

    // Dismiss loading overlay on page load — catches cases where a form
    // POST returns the same page (e.g. validation/API error) instead of
    // redirecting, which would otherwise leave the overlay stuck on screen.
    window.hideLoading();

    // Auto-wire forms with data-loading attribute
    document.querySelectorAll('form[data-loading]').forEach(function (form) {
        form.addEventListener('submit', function () {
            // Skip if form has validation and is invalid
            if (form.classList.contains('needs-validation') && !form.checkValidity()) return;
            var msg = form.getAttribute('data-loading') || 'Loading...';
            window.showLoading(msg);
        });
    });

    // -------------------------------------------------------
    // Confirmation Modal (Task A)
    // Intercept form submit when form has data-confirm-message
    // -------------------------------------------------------
    const confirmModal = document.getElementById('confirmModal');
    if (confirmModal) {
        const modalInstance = new bootstrap.Modal(confirmModal);
        const modalBody = document.getElementById('confirmModalBody');
        const modalBtn = document.getElementById('confirmModalBtn');
        let pendingForm = null;

        document.querySelectorAll('form[data-confirm-message]').forEach(function (form) {
            form.addEventListener('submit', function (e) {
                e.preventDefault();
                pendingForm = form;
                modalBody.textContent = form.getAttribute('data-confirm-message');
                modalInstance.show();
            });
        });

        // Also handle button-level data-confirm (for non-form elements)
        document.querySelectorAll('[data-confirm]').forEach(function (el) {
            el.addEventListener('click', function (e) {
                const form = el.closest('form');
                if (form) {
                    e.preventDefault();
                    pendingForm = form;
                    modalBody.textContent = el.getAttribute('data-confirm');
                    modalInstance.show();
                }
            });
        });

        modalBtn.addEventListener('click', function () {
            if (pendingForm) {
                // Remove the data-confirm-message temporarily so re-submit doesn't loop
                const msg = pendingForm.getAttribute('data-confirm-message');
                pendingForm.removeAttribute('data-confirm-message');
                pendingForm.submit();
                if (msg) pendingForm.setAttribute('data-confirm-message', msg);
                pendingForm = null;
            }
            modalInstance.hide();
        });

        confirmModal.addEventListener('hidden.bs.modal', function () {
            pendingForm = null;
            if (pendingResolve) { pendingResolve(false); pendingResolve = null; }
        });

        let pendingResolve = null;
        window.confirmAction = function (message) {
            return new Promise(function (resolve) {
                pendingResolve = resolve;
                modalBody.textContent = message;
                modalInstance.show();
            });
        };

        var origClickHandler = modalBtn.onclick;
        modalBtn.addEventListener('click', function () {
            if (pendingResolve) { pendingResolve(true); pendingResolve = null; }
        });
    }

    // -------------------------------------------------------
    // Client-Side Form Validation (Task C)
    // Bootstrap "was-validated" pattern for .needs-validation
    // -------------------------------------------------------
    document.querySelectorAll('form.needs-validation').forEach(function (form) {
        form.addEventListener('submit', function (e) {
            if (!form.checkValidity()) {
                e.preventDefault();
                e.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });

    // -------------------------------------------------------
    // Client-Side Search/Filter on Lists (Task D)
    // -------------------------------------------------------
    document.querySelectorAll('[data-search-target]').forEach(function (input) {
        var tbodyId = input.getAttribute('data-search-target');
        var tbody = document.getElementById(tbodyId);
        var countEl = input.closest('.search-filter-wrapper') ?
            input.closest('.search-filter-wrapper').querySelector('.search-count') : null;
        if (!tbody) return;

        var rows = tbody.querySelectorAll('tr');
        var totalRows = rows.length;

        input.addEventListener('input', function () {
            var query = input.value.toLowerCase().trim();
            var visibleCount = 0;
            rows.forEach(function (row) {
                var text = row.textContent.toLowerCase();
                if (!query || text.indexOf(query) !== -1) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });
            if (countEl) {
                if (query) {
                    var msg = (window.i18n && window.i18n.showing_x_of_y)
                        ? window.i18n.showing_x_of_y.replace('%(visible)s', visibleCount).replace('%(total)s', totalRows)
                        : 'Showing ' + visibleCount + ' of ' + totalRows;
                    countEl.textContent = msg;
                    countEl.style.display = '';
                } else {
                    countEl.style.display = 'none';
                }
            }
        });
    });

    // -------------------------------------------------------
    // Session Timeout Warning (Task E)
    // -------------------------------------------------------
    var isAuthenticated = document.body.getAttribute('data-authenticated') === 'true';
    if (isAuthenticated) {
        var WARNING_MS = 28 * 60 * 1000;   // 28 minutes
        var LOGOUT_MS = 30 * 60 * 1000;    // 30 minutes
        var warningTimer, logoutTimer;
        var sessionWarningModal = document.getElementById('sessionWarningModal');
        var sessionModalInstance = sessionWarningModal ? new bootstrap.Modal(sessionWarningModal) : null;

        function resetSessionTimers() {
            clearTimeout(warningTimer);
            clearTimeout(logoutTimer);
            warningTimer = setTimeout(showSessionWarning, WARNING_MS);
            logoutTimer = setTimeout(doSessionLogout, LOGOUT_MS);
        }

        function showSessionWarning() {
            if (sessionModalInstance) {
                sessionModalInstance.show();
            }
        }

        function doSessionLogout() {
            window.location.href = '/auth/logout';
        }

        function keepAlive() {
            fetch('/auth/keepalive', { method: 'POST', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                .then(function () { resetSessionTimers(); })
                .catch(function () {});
            if (sessionModalInstance) sessionModalInstance.hide();
        }

        // Continue Session button
        var continueBtn = document.getElementById('sessionContinueBtn');
        if (continueBtn) {
            continueBtn.addEventListener('click', keepAlive);
        }

        // Reset timers on user activity
        ['click', 'keypress', 'mousemove', 'scroll'].forEach(function (evt) {
            document.addEventListener(evt, function () {
                resetSessionTimers();
            }, { passive: true });
        });

        resetSessionTimers();
    }

    // Enable Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (el) {
        return new bootstrap.Tooltip(el);
    });

    // Active nav link highlighting
    var currentPath = window.location.pathname;
    document.querySelectorAll('.navbar-nav .nav-link').forEach(function (link) {
        var href = link.getAttribute('href');
        if (href && currentPath.startsWith(href) && href !== '/') {
            link.classList.add('active');
        } else if (href === '/' && currentPath === '/') {
            link.classList.add('active');
        }
    });

    // -------------------------------------------------------
    // Theme Toggle (Dark/Light Mode)
    // -------------------------------------------------------
    function updateThemeIcons() {
        var isDark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
        document.querySelectorAll('#themeIconLight, .theme-icon-light').forEach(function(el) {
            el.style.display = isDark ? 'none' : 'inline';
        });
        document.querySelectorAll('#themeIconDark, .theme-icon-dark').forEach(function(el) {
            el.style.display = isDark ? 'inline' : 'none';
        });
    }

    function toggleTheme() {
        var html = document.documentElement;
        var current = html.getAttribute('data-bs-theme');
        var newTheme = current === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-bs-theme', newTheme);
        localStorage.setItem('waas_theme', newTheme);
        updateThemeIcons();

        // Fire-and-forget POST to persist on server
        var csrfMeta = document.querySelector('meta[name="csrf-token"]');
        var csrfVal = csrfMeta ? csrfMeta.getAttribute('content') : '';
        var formData = new FormData();
        formData.append('theme', newTheme);
        formData.append('csrf_token', csrfVal);
        fetch('/auth/set-theme', {
            method: 'POST',
            body: formData
        }).catch(function() {});
    }

    document.querySelectorAll('#themeToggle, #themeToggleAnon').forEach(function(btn) {
        btn.addEventListener('click', toggleTheme);
    });
    updateThemeIcons();

    // -------------------------------------------------------
    // Copy to Clipboard (for curl display)
    // -------------------------------------------------------
    window.copyToClipboard = function(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function() {
                if (window.showToast) window.showToast('Copied to clipboard!', 'success');
            }).catch(function() {
                fallbackCopy(text);
            });
        } else {
            fallbackCopy(text);
        }
    };

    function fallbackCopy(text) {
        var textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            if (window.showToast) window.showToast('Copied to clipboard!', 'success');
        } catch (e) {
            if (window.showToast) window.showToast('Failed to copy.', 'danger');
        }
        document.body.removeChild(textarea);
    }

    // -------------------------------------------------------
    // Module Info Cards (Phase 10.1)
    // Dismissible per-module landing cards persisted in localStorage.
    // -------------------------------------------------------
    document.querySelectorAll('.module-info-card[data-info-key]').forEach(function (card) {
        var key = 'waas_info_dismissed_' + card.getAttribute('data-info-key');
        if (localStorage.getItem(key) === '1') {
            card.remove();
            return;
        }
        card.addEventListener('closed.bs.alert', function () {
            try { localStorage.setItem(key, '1'); } catch (e) { /* ignore quota */ }
        });
    });

    // Onboarding checklist dismissal
    document.querySelectorAll('.onboarding-dismiss').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var card = btn.closest('.onboarding-checklist');
            if (card) {
                card.remove();
                try { localStorage.setItem('waas_info_dismissed_onboarding-checklist', '1'); } catch (e) {}
            }
        });
    });

    console.log('WaaS Portal initialized.');
});
