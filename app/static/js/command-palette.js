/* Command palette (Ctrl+K / Cmd+K) — goal 5.
 * Static nav commands filter instantly client-side; anything else is a
 * debounced call to /search/api merged in by category.
 */
document.addEventListener('DOMContentLoaded', function () {
    var backdrop = document.getElementById('commandPalette');
    if (!backdrop) return; // anonymous pages don't render the palette

    var input = document.getElementById('commandPaletteInput');
    var resultsEl = document.getElementById('commandPaletteResults');
    var trigger = document.getElementById('paletteTrigger');
    var switchForm = document.getElementById('paletteSwitchAccountForm');
    var switchAccountIdField = document.getElementById('paletteSwitchAccountId');

    var RECENT_KEY = 'waas_palette_recent';
    var MAX_RECENT = 5;
    var DEBOUNCE_MS = 250;

    var staticCommands = (window.paletteStaticCommands || []).map(function (c) {
        return { category: 'Go to', title: c.title, subtitle: null, icon: c.icon || 'arrow-right-short', url: c.url, action: null };
    });

    var items = [];       // flat, currently-rendered rows
    var activeIndex = -1;
    var debounceTimer = null;
    var requestSeq = 0;

    function getRecent() {
        try {
            return JSON.parse(localStorage.getItem(RECENT_KEY) || '[]');
        } catch (e) {
            return [];
        }
    }

    function pushRecent(entry) {
        var recent = getRecent().filter(function (r) { return r.url !== entry.url; });
        recent.unshift(entry);
        try {
            localStorage.setItem(RECENT_KEY, JSON.stringify(recent.slice(0, MAX_RECENT)));
        } catch (e) { /* ignore quota */ }
    }

    function escapeHtml(s) {
        var d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    function render(rows) {
        items = rows;
        activeIndex = rows.length ? 0 : -1;

        if (!rows.length) {
            resultsEl.innerHTML = '<div class="command-palette-empty text-muted">No matches.</div>';
            return;
        }

        var html = '';
        var lastCategory = null;
        rows.forEach(function (row, i) {
            if (row.category !== lastCategory) {
                html += '<div class="command-palette-category">' + escapeHtml(row.category) + '</div>';
                lastCategory = row.category;
            }
            html +=
                '<div class="command-palette-item' + (i === activeIndex ? ' active' : '') + '" data-index="' + i + '">' +
                    '<i class="bi bi-' + (row.icon || 'arrow-right-short') + '"></i>' +
                    '<div class="command-palette-item-text">' +
                        '<div class="command-palette-item-title">' + escapeHtml(row.title) + '</div>' +
                        (row.subtitle ? '<div class="command-palette-item-subtitle">' + escapeHtml(row.subtitle) + '</div>' : '') +
                    '</div>' +
                '</div>';
        });
        resultsEl.innerHTML = html;

        resultsEl.querySelectorAll('.command-palette-item').forEach(function (el) {
            el.addEventListener('mouseenter', function () {
                setActive(parseInt(el.getAttribute('data-index'), 10));
            });
            el.addEventListener('click', function () {
                selectItem(parseInt(el.getAttribute('data-index'), 10));
            });
        });
    }

    function setActive(index) {
        activeIndex = index;
        resultsEl.querySelectorAll('.command-palette-item').forEach(function (el) {
            el.classList.toggle('active', parseInt(el.getAttribute('data-index'), 10) === index);
        });
        var activeEl = resultsEl.querySelector('.command-palette-item.active');
        if (activeEl) activeEl.scrollIntoView({ block: 'nearest' });
    }

    function selectItem(index) {
        var item = items[index];
        if (!item) return;

        if (item.action === 'switch_account') {
            switchAccountIdField.value = item.account_id;
            switchForm.submit();
            return;
        }
        if (item.url) {
            pushRecent({ title: item.title, url: item.url, icon: item.icon });
            window.location.href = item.url;
        }
    }

    function renderDefault() {
        var recent = getRecent().map(function (r) {
            return { category: 'Recent', title: r.title, subtitle: null, icon: r.icon, url: r.url, action: null };
        });
        render(recent.concat(staticCommands));
    }

    function runSearch(q) {
        var matchedStatic = staticCommands.filter(function (c) {
            return c.title.toLowerCase().indexOf(q) !== -1;
        });
        render(matchedStatic);

        var seq = ++requestSeq;
        fetch(window.paletteSearchUrl + '?q=' + encodeURIComponent(q), {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        })
            .then(function (resp) { return resp.ok ? resp.json() : { results: [] }; })
            .then(function (data) {
                if (seq !== requestSeq) return; // stale response — a newer keystroke already fired
                render(matchedStatic.concat(data.results || []));
            })
            .catch(function () { /* leave static matches showing */ });
    }

    function onInput() {
        var q = input.value.trim().toLowerCase();
        clearTimeout(debounceTimer);
        if (!q) {
            renderDefault();
            return;
        }
        if (q.length < 2) {
            render(staticCommands.filter(function (c) { return c.title.toLowerCase().indexOf(q) !== -1; }));
            return;
        }
        debounceTimer = setTimeout(function () { runSearch(q); }, DEBOUNCE_MS);
    }

    function open() {
        backdrop.classList.remove('d-none');
        input.value = '';
        renderDefault();
        setTimeout(function () { input.focus(); }, 0);
    }

    function close() {
        backdrop.classList.add('d-none');
    }

    function isOpen() {
        return !backdrop.classList.contains('d-none');
    }

    document.addEventListener('keydown', function (e) {
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
            e.preventDefault();
            isOpen() ? close() : open();
            return;
        }
        if (!isOpen()) return;
        if (e.key === 'Escape') {
            close();
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (items.length) setActive((activeIndex + 1) % items.length);
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (items.length) setActive((activeIndex - 1 + items.length) % items.length);
        } else if (e.key === 'Enter') {
            e.preventDefault();
            selectItem(activeIndex);
        }
    });

    backdrop.addEventListener('mousedown', function (e) {
        if (e.target === backdrop) close();
    });

    if (trigger) trigger.addEventListener('click', open);
    input.addEventListener('input', onInput);
});
