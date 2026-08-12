# Phase 10 — UX Improvement Plan

*Drafted: 2026-05-11 — based on full codebase review (every blueprint, template, and static asset).*

---

## Guiding Principles (per user direction)

1. **Fixes first, new features last.** Phases 10.1–10.10 stabilize the UX; Phase 11 adds capability.
2. **Breaking changes are acceptable** where they improve clarity. URLs, nav labels, and module names are fair game.
3. **Differentiate Features vs. Templates** — keep both modules but make their roles unmistakable.
4. **Target persona: technical operator / security admin.** Optimize for density, efficiency, and raw-API access — not hand-holding.
5. **Address the "hodge podge" feeling** by enforcing a small set of repeating patterns (page header, breadcrumb, empty state, action footer, confirm modal, badge palette).

---

## Diagnosis — Why It Feels "Hodge Podge"

Across ~50 templates the report agents found:

- **9 top-level nav items** (plus 4 utility) with no grouping. The brain has to scan a flat list every time.
- **Mixed iconography** — Bootstrap Icons, raw emoji, and occasional Unicode glyphs side by side.
- **Inconsistent page headers** — some pages have an `<h2>` + actions row, others a card-header, others nothing.
- **Inconsistent breadcrumbs** — present on roughly half the pages; missing on most create/edit/bulk pages.
- **Inconsistent confirmations** — a global confirm modal exists in `base.html` *and* roughly a dozen routes still use raw `confirm()`.
- **Inconsistent badge semantics** — `bg-info` is used for "Active", "Shared", "Read permission", and "Apply" actions, often within the same view.
- **Duplicate code paths** — `templates/add.html` and `edit.html` are byte-similar, security.html re-defines the same form four times, admin has two dashboards (`index.html` and `panel.html`).
- **Form widget inconsistency** — some forms use the Bootstrap `form-control` class; admin forms render bare inputs.
- **API version (v2/v4) leakage** — power-user info is exposed unconditionally next to user-facing labels, adding noise.
- **Help is decoupled from work** — six of seven `/help/*` pages have a missing `<div class="row">` wrapper, and no operational page links to its help topic.

The plan below systematically removes each of these.

---

# Phase 10.1 — Information Architecture & Navigation ✅ COMPLETE

**Status (2026-05-11):** All 5 subtasks implemented. Navbar regrouped into 4 dropdowns + Dashboard + Help. `macros/page.html` provides `page_header`, `breadcrumbs`, `empty_state`, and `module_info` macros. Module info cards added to 7 list pages (Accounts, Applications, Certs, Logs, Templates, Raw Configs, Reports). Features → Raw Configs rename complete with `/features/*` → `/raw-configs/*` 301 redirect. Breadcrumbs added to 27 previously-bare pages across accounts/, applications/, auth/, admin/, reports/.

**Goal:** Cut perceived complexity in half by grouping the 9+ navbar items into 4 functional clusters, and give every page a uniform header + breadcrumb spine so users always know where they are.

### 10.1.1 Group the navbar into 4 dropdowns
Reorganize `base.html` navbar:

| Group | Items |
|-------|-------|
| **Resources** | Accounts, Applications, Certificates |
| **Configuration** | Features (renamed → "Raw Configs"), Templates |
| **Observability** | Dashboard, Logs, Reports |
| **Admin** | Users, Audit Log, Settings *(admin-only)* |

Utility cluster on the right stays flat: Help, Theme toggle, Language, Profile dropdown.

**Why this helps:** Reduces visual scanning from 9 to 4 top-level entry points. The grouping mirrors the user's mental model (manage resources → configure them → observe them → administer the portal).

### 10.1.2 Universal page header macro
Create `app/templates/_macros/page_header.html`:

```jinja
{% macro page_header(icon, title, subtitle=None, actions=[]) %}
<div class="page-header d-flex justify-content-between align-items-start mt-4 mb-3">
  <div>
    <h2 class="mb-1"><i class="bi bi-{{ icon }}"></i> {{ title }}</h2>
    {% if subtitle %}<p class="text-muted mb-0 small">{{ subtitle }}</p>{% endif %}
  </div>
  <div class="btn-group">{{ actions|safe }}</div>
</div>
{% endmacro %}
```

Every page imports and uses it. **Why this helps:** A user landing on any page gets the same visual anchor — icon, title, optional one-line description, action cluster top-right. Today every page invents this layout.

### 10.1.3 Mandatory breadcrumbs
Add breadcrumbs to **every** page that is more than one level deep. The base template already has a `{% block breadcrumbs %}` — just enforce it. Create a `breadcrumb(items)` macro so callers pass a Python list instead of hand-rolling `<ol class="breadcrumb">`.

Pages currently missing breadcrumbs (per agent reports): `applications/create.html`, `clone.html`, `dns.html`, `bulk_delete.html`, all of `accounts/*`, all of `auth/*`, all of `admin/*`, all of `reports/*`, `templates/save_as.html`, `templates/bulk_apply.html`, `templates/bulk_results.html`, `templates/import.html`.

**Why this helps:** Deep-link recovery (the user lands on `/applications/12/security` from a notification) needs to show the trail without forcing a hunt.

### 10.1.4 Rename "Features" → "Raw Configs"
The `features` blueprint exposes raw v4 API payloads. The label "Features" is meaningless to a new operator — it sounds like a product feature flag.

Rename to **"Raw Configs"** (route: `/raw-configs/`). Add a 30(0)-301 redirect from `/features/*` for bookmarks.

**Why this helps:** Solves half of the Features vs Templates confusion in one move. "Raw" signals power-user / API-payload territory; "Templates" signals named/reusable.

### 10.1.5 Module landing cards
Each module list page (Accounts, Applications, Certs, Logs, Raw Configs, Templates, Reports) gets a small `alert alert-info border-0` info card at the top explaining the module in one paragraph and a link to its help page.

**Why this helps:** New operators learn the module's purpose without leaving the page; experienced users can dismiss (sticky-cookie) once seen.

---

# Phase 10.2 — Visual Consistency & Pattern Library

**Goal:** Lock down a tiny pattern library so every page feels like part of the same product.

### 10.2.1 Iconography audit
Replace every emoji (🔑 🌐 📊 ⚙️ etc.) with the Bootstrap Icon equivalent (`bi-key`, `bi-globe`, etc.). Audit `templates/templates/list.html`, `templates/applications/*`, and any others where emoji slipped in.

**Why this helps:** Bootstrap Icons render consistently across OS/browser; emoji rendering varies wildly and clashes with the rest of the chrome.

### 10.2.2 Badge palette policy
Codify badge semantics in CSS comments + a help page section:

| Color | Meaning | Examples |
|-------|---------|----------|
| `bg-success` | Healthy / Active / Configured | account active, cert valid, key configured |
| `bg-secondary` | Neutral / Not set / N/A | "Not set", "Never verified" |
| `bg-warning text-dark` | Attention needed (within 30d, write perm) | expiring soon, write permission |
| `bg-danger` | Failure / Expired / Critical | expired, inactive, critical severity, admin perm |
| `bg-info` | Informational / Read perm / API ver | API version, read permission, "Shared" tag |
| `bg-primary` | Active selection / Current | "current page", primary action |

Sweep every template and recolor anything off-palette. Today `bg-info` is overloaded.

**Why this helps:** Color becomes a reliable signal instead of decoration.

### 10.2.3 Empty-state component
Create `_macros/empty_state.html` taking `(icon, title, message, cta_label, cta_url)`. Reuse on every list page (Accounts, Apps, Certs, Templates, Reports, Logs, Notifications, Sharing).

**Why this helps:** Today `accounts/list.html` has a nice empty state; most others show a blank table or a one-line "No items". Consistency turns this into a teaching moment instead of dead air.

### 10.2.4 Action button conventions
- Primary action = blue filled (`btn-primary`)
- Secondary navigation back = outline grey (`btn-outline-secondary`)
- Destructive action = red outline (`btn-outline-danger`), confirmed via global modal (never raw `confirm()`)
- Icon-only buttons in tables = `btn-sm btn-outline-*` with `title=""` AND `aria-label=""`

Sweep every page and align.

### 10.2.5 Eliminate duplicate templates
- `templates/templates/add.html` and `templates/templates/edit.html` are nearly identical → factor a shared `_form.html` partial included by both.
- `applications/security.html` re-defines the same 4-section form multiple times → extract `_security_form.html`.
- Admin `index.html` and `panel.html` are duplicate dashboards → delete `panel.html`, redirect to `/admin/`.

**Why this helps:** Cuts maintenance surface and prevents drift. The "edit" page silently diverging from "add" is a classic bug source.

### 10.2.6 Consolidate the bulk-operation JS
`applications/bulk_delete.html` and `templates/bulk_apply.html` have near-identical SocketIO progress JS. Extract to `static/js/bulk_progress.js` driven by a small data-attribute API.

---

# Phase 10.3 — Forms & Validation Standardization

**Goal:** One way to render a form field, one way to confirm a destructive action, one way to surface validation errors.

### 10.3.1 Field-rendering macro
```jinja
{% macro field(f, help=None, autofocus=False) %}
<div class="mb-3">
  {{ f.label(class="form-label") }}
  {{ f(class="form-control" + (" is-invalid" if f.errors else ""), autofocus=autofocus) }}
  {% if help %}<div class="form-text">{{ help }}</div>{% endif %}
  {% for e in f.errors %}<div class="invalid-feedback d-block">{{ e }}</div>{% endfor %}
</div>
{% endmacro %}
```

All forms switch to this. **Why this helps:** Today admin forms render bare inputs without `form-control`; auth forms use one pattern; account forms use another. One macro = one look.

### 10.3.2 Confirm modal everywhere
Audit every `onclick="return confirm(...)"` and every `<form>` with inline JS confirm, and convert to the global `confirm-modal` pattern already in `base.html` (use `data-confirm` attribute on the submit button).

Pages to update (from agent reports): `accounts/sharing.html`, `admin/users.html`, `applications/list.html` (delete buttons), `certificates/view.html`, `reports/list.html`, `templates/list.html`, `auth/notifications.html` (delete).

**Why this helps:** Native `confirm()` is style-less, can't be themed, and looks unprofessional. The global modal is already built — just use it.

### 10.3.3 Cancel/Submit footer macro
```jinja
{% macro form_footer(submit, cancel_url, cancel_label="Cancel") %}
<div class="d-flex gap-2 justify-content-end mt-4">
  <a href="{{ cancel_url }}" class="btn btn-outline-secondary">{{ cancel_label }}</a>
  {{ submit(class="btn btn-primary") }}
</div>
{% endmacro %}
```
Apply to all create/edit forms. Today some have buttons left, some right, some no cancel button.

### 10.3.4 Inline validation hints
For complex fields add `data-validate` rules and use Bootstrap's `:invalid` styling so the user knows *before* submitting. Focus on: cert PEM (must contain `-----BEGIN`), CNAMEs (FQDN regex), API key length, password confirm match.

### 10.3.5 Standardize "loading" UX on slow forms
The `data-loading` attribute already exists on some forms (it triggers the global overlay). Apply consistently to: account verify, key rotate, template apply, bulk apply, cert upload, scheduled-report run-now.

---

# Phase 10.4 — Contextual Help & Onboarding

**Goal:** A technical operator should never have to leave the page to learn what a field means or what an action will do.

### 10.4.1 Fix the help layout bug
Six of seven `/help/*` templates are missing the `<div class="row">` wrapper that the seventh has, leaving them full-width and unreadable on wide monitors. Wrap them.

### 10.4.2 Inline `?` help links
Next to every page-header title, add a small `<a href="/help/<topic>" class="text-muted small" data-bs-toggle="tooltip" title="Open help">`<i class="bi bi-question-circle"></i></a>` link. Operational pages map to topics:

| Page | Help topic |
|------|-----------|
| `accounts/*` | `/help/accounts` |
| `applications/list` | `/help/applications` |
| `applications/security` | `/help/security-config` |
| `certificates/*` | `/help/certificates` |
| `logs/waf` | `/help/waf-logs` |
| `logs/fp_analysis` | `/help/false-positives` |
| `templates/*` | `/help/templates` |
| `features/*` (Raw Configs) | `/help/raw-configs` |
| `reports/*` | `/help/reports` |

**Why this helps:** The help system already exists; it's just orphaned. Linking it inline turns "help" from a fallback into the natural next click.

### 10.4.3 Field-level tooltips for jargon
Bootstrap tooltips on every technical term the first time it appears on a page: CNAME, SNI, FP (false positive), v2/v4, "endpoint", "origin", "WAF policy". Use `data-bs-toggle="tooltip"` + a small `<i class="bi bi-info-circle text-muted small"></i>` icon.

### 10.4.4 First-run onboarding for empty state
When a user has zero accounts, the Dashboard shows a 3-step checklist card:

1. **Add a WaaS account** → button to `/accounts/add`
2. **Verify the account** → only enables after step 1
3. **Browse your applications** → only enables after step 2

After all three are done the card auto-dismisses (and a "Show getting-started" link reappears in the help dropdown).

**Why this helps:** New operators currently land on an empty dashboard with no obvious next step.

### 10.4.5 Help page index
`/help` should list all topics in a 2-column grid with an icon per topic and a one-line description. Currently it's a flat link list.

---

# Phase 10.5 — Logs UX Overhaul

**Goal:** Logs is the highest-frequency power-user workflow. Today it's a dense unfiltered table; this phase makes it a real investigation tool.

### 10.5.1 Row expansion for full event detail
Each table row becomes a `data-bs-toggle="collapse"` row that expands to a definition list showing every field of the raw event (currently hidden). Keep the row dense; reveal on demand.

**Why this helps:** Today the only way to see all fields is CSV export. Investigators need to drill into one event without leaving the list.

### 10.5.2 Timestamp clarity
- Label the column header explicitly as **"Time (UTC)"**
- Add a toggle in the toolbar: **"UTC / Local"** that re-renders timestamps client-side (using `Intl.DateTimeFormat`)
- Persist the choice in localStorage

**Why this helps:** Right now timestamps are silent UTC, which causes timezone errors when matching against client-side incident reports.

### 10.5.3 Expanded filter set
Beyond Client IP, add server-side filters for: severity, attack type, URI substring, status code, action (allow/block/log), application (when at account-scope).

Render filters as a collapsible "Filters" card above the table with active filters shown as dismissible chips.

### 10.5.4 Real pagination
Show "Page N of M (≈X events)" plus first/prev/next/last + a "Jump to page" input. Today only prev/next exists.

### 10.5.5 Severity decoding
The WaaS API returns codes like `ALER`, `CRIT`, `EMER`, `WARN`, `INFO`. Display them as human-readable badges:

| Code | Label | Badge |
|------|-------|-------|
| `EMER`/`CRIT` | Critical | `bg-danger` |
| `ALER` | Alert | `bg-danger` |
| `WARN` | Warning | `bg-warning text-dark` |
| `NOTI`/`INFO` | Info | `bg-info` |
| `DBUG` | Debug | `bg-secondary` |

Show the raw code on hover (`title=`).

### 10.5.6 Export ALL pages
Add a checkbox to the export modal: **"Export all matching events (not just this page)"**. Default off (current behavior). When on, the server iterates and streams a CSV/JSON.

### 10.5.7 FP analysis 1000-event cap surfaced
Today the FP analyzer silently caps at 1000 events. Show a banner at the top: *"Analysis based on most-recent 1000 events in the selected time window. [Adjust time window]"* + add a time-window picker.

### 10.5.8 Allow multi-row expansion in FP accordion
The current FP analysis accordion forces single-open behavior. Switch to multi-open so an operator can compare two false positives side-by-side.

### 10.5.9 Saved filter presets (carry-over to Phase 11)
Stub now: persist the last-used filter set per user (localStorage). Full named presets in Phase 11.

---

# Phase 10.6 — Accounts, Applications & Certificates Polish

### 10.6.1 Account-scoped resource pages: show account context
On `/applications/?account_id=N`, `/certificates/?account_id=N`, `/logs/?account_id=N` show a sticky small chip at the top: **"Account: {account_name}  [Switch account ▾]"** with a dropdown to switch quickly.

**Why this helps:** Today you have to back out to /accounts to switch context; this is the most common multi-account workflow.

### 10.6.2 Copy-to-clipboard everywhere it matters
Add a one-click copy icon next to: CNAME values (app DNS page), WaaS account IDs, application IDs, API key in the rotate page (after generation), template IDs, log event IDs. The clipboard helper already exists in `static/js/app.js`.

### 10.6.3 API version disclosure as "advanced toggle"
Today every list page shows "v2"/"v4" badges next to everything. Hide them by default; surface via a **"Show technical details"** toggle in the user profile (persisted per-user). Power users keep their badges; new operators see clean labels.

### 10.6.4 Application clone wizard
The clone route exists but the form is a single page. Make it a 3-step wizard: (1) Source app, (2) Target account, (3) What to copy (security, DNS, certs, all). Show a summary preview before submit.

### 10.6.5 Bulk-delete confirmation upgrade
Today's bulk delete asks for type-the-count confirmation. Add a preview list of what will be deleted (truncated to 10) plus a "I understand this is irreversible" checkbox — same pattern GitHub uses for repo delete.

### 10.6.6 Certificate fields: show SAN and expiry-derived "lifetime"
Parse the cert (server-side once at upload) and display: subject CN, all SANs, issuer, validity period, days remaining, key algorithm + size. Today only filename + expiry is shown.

### 10.6.7 Sharing UI: pending invitations
Show a "Pending" badge for shares whose target user has never logged in since being granted. Helps owners chase up onboarding.

---

# Phase 10.7 — Configuration: Raw Configs vs Templates

(Per your direction: differentiate, don't merge.)

### 10.7.1 Side-by-side intro cards on Configuration nav-group landing
On any Configuration page, show a thin header explaining the two modules:

> **Raw Configs** — view and edit the raw v4 API payload for any application (advanced, full control).
> **Templates** — named, reusable configurations you can apply to multiple applications (recommended).

### 10.7.2 Templates: show "Applied to" history
Today there's no record of which applications a template was applied to. Add `TemplateApplication` model (template_id, app_id, account_id, applied_by, applied_at). On the template view page, show a "Recently applied to" list. This also enables a "Re-apply to all previous targets" action.

### 10.7.3 Templates: condition `day_of_week` on `frequency`
On schedule fields the `day_of_week` selector is always visible; only show it when `frequency=weekly`. Same for `day_of_month` ↔ `monthly`.

### 10.7.4 Templates: split "Apply" into single + bulk on the list page
Today "Apply" opens a separate flow. Add an inline-action button on each list row: "▾" → "Apply to one app" / "Bulk apply".

### 10.7.5 Raw Configs: diff before save
When editing a raw payload, show a unified diff vs. the current server state on submit (the diff CSS is already in `style.css`). Confirm-modal wraps the apply.

### 10.7.6 Raw Configs: export ↔ import pairing
Make export and import discoverable from the same toolbar (today they're in separate menus).

---

# Phase 10.8 — Reports & Notifications

### 10.8.1 Reports: missing breadcrumbs on every page
Add breadcrumbs (Phase 10.1 macro).

### 10.8.2 Reports: edit.html missing the report-types sidebar that add.html has
Copy the sidebar from `add.html` to `edit.html` so the user can change report type during edit.

### 10.8.3 Reports: schedule preview
After picking frequency + time + day, show a "Next 3 runs:" preview list (Mon 2026-05-11 09:00 UTC, Mon 2026-05-18 09:00 UTC, ...). Removes ambiguity.

### 10.8.4 Reports: history & re-run
Add a `ReportRun` table; show last 10 runs per report with download links and a "Re-run now" button.

### 10.8.5 Notification preferences: group + explain
Today's three sections (Reports, Cert Expiry, API Key Expiry) are bare toggles. Add a one-line explainer under each section header explaining when the notification fires. Add a "Test notification" button per section to verify delivery.

### 10.8.6 Notification bell: "Mark all read" + filter by type
Bell dropdown today shows last 5 unread. Expand to a full `/notifications` page with type-filter chips and mark-all-read.

---

# Phase 10.9 — Auth, Admin & Profile

### 10.9.1 Editable profile
Today profile is read-only. Allow editing: first_name, last_name, email, preferred language, theme default, notification prefs (link to existing page), "show technical details" toggle from 10.6.3.

### 10.9.2 Password change UX
Add a password-strength meter (zxcvbn-style, client-side library or simple heuristic), and show explicit rules ("≥ 12 chars, one digit, one symbol"). Today rules are server-side only and surface as a generic flash message.

### 10.9.3 Admin: consolidate dashboards
Delete `admin/panel.html` (duplicate of `admin/index.html`), redirect `/admin/panel` → `/admin/`.

### 10.9.4 Admin users page: search + filter + sort
Today the users page is a plain table. Add a top-bar with search (username/email), filter (active/inactive/admin), and sortable columns (last login, created).

### 10.9.5 Admin audit log: filters & saved views
Add filters for actor, action type, target type, date range. Persist filter sets per user.

### 10.9.6 Admin: bulk user actions
Checkbox column + bulk activate/deactivate. Useful when onboarding/offboarding teams.

### 10.9.7 Login page: forgot-password flow
Currently no password reset. Add email-based reset using the existing Flask-Mail integration.

---

# Phase 10.10 — Errors, Resilience, Accessibility

### 10.10.1 Useful error pages
404/403/500 pages today are dead-ends. Add: a back button, a "Go to dashboard" button, a search box, a "Report this" mailto. For 403 specifically, name the missing permission.

### 10.10.2 API error display
`WaasApiError` flash messages today dump the raw WaaS response. Wrap in a friendlier display: "WaaS API returned: {status}. Suggested next steps: …" with collapsed raw payload.

### 10.10.3 Session-expired soft handling
Today an expired session causes a flash + redirect. Detect via AJAX response code and pop the session-warning modal in-place so the user doesn't lose form state.

### 10.10.4 Rate-limit messaging
The login rate limiter today returns a generic 429. Render a friendly page: "Too many attempts. Try again in N seconds." with a countdown.

### 10.10.5 Accessibility audit
Run Lighthouse + axe. Targeted fixes:
- `aria-label` on every icon-only button
- `<label for>` association for every input (some forms rely on placeholder only)
- Focus-visible outline on interactive elements
- Color contrast on `bg-warning text-dark` combinations
- Skip-to-main-content link in `base.html`
- `<table>`s have `<caption>` or `aria-label`

### 10.10.6 Responsive table strategy
Wide tables (Logs, Apps, Users) overflow on tablet. Either: (a) hide non-essential columns at `< md` with `d-none d-md-table-cell`, or (b) switch to a card view at `< md`. Pick one strategy and apply uniformly.

### 10.10.7 Loading skeletons for AJAX
Dashboard cards today show a spinner; switch to content-shaped skeletons (CSS-only) so layout doesn't reflow when data arrives.

---

# Phase 11 — New Features (Post-Polish)

Only after 10.1–10.10 land. Each unlocks new value once the foundation is solid.

### 11.1 Global search bar in navbar
Cmd/Ctrl-K opens a quickfind: searches accounts, applications, certificates, templates, raw configs, log events (by ID), users. Routes to the right detail page on Enter.

### 11.2 Saved log-filter presets (named)
Builds on 10.5. User saves a filter set as e.g. "Production critical events" — appears in the Logs sidebar.

### 11.3 Application dependency / overview graph
On the application detail page, render a small graph: app → backend origin(s) → cert(s) → DNS endpoint(s). Single visual that orients the operator instantly.

### 11.4 Multi-account compare view
Pick 2–4 applications across accounts; show their security settings side-by-side with drift highlighted. Built on top of the existing single-pair compare.

### 11.5 Bulk configuration deploy with preview
Pick a template + N target apps → show a per-app diff preview → apply with progress (reuses the SocketIO bulk-progress component).

### 11.6 Scheduled report previews & exports
Click "Preview" on any report definition to render a sample run with the last completed period's data — without committing or emailing.

### 11.7 Cert auto-renewal reminders & action suggestions
On the cert detail page, if expiry ≤ 30d, show a context-aware action panel: Let's-Encrypt instructions (if domain matches), a "Generate CSR" tool, links to the upload page.

### 11.8 Density toggle (Comfortable / Compact)
Per-user pref. Comfortable = current spacing; Compact = ~70% padding, smaller font in tables. Power users want compact.

### 11.9 Two-factor auth (TOTP)
For admin and shared accounts. Library: `pyotp`. QR code via `qrcode`.

### 11.10 Per-user API token (programmatic access to the Portal)
Read-only tokens scoped to the user's own accounts, for scripting (curl/Ansible). Different from WaaS API keys.

---

## Suggested Sequencing

| Phase | Theme | Approx. size | Why this order |
|-------|-------|--------------|----------------|
| 10.1 | IA & navigation | Medium | Touches every page; do it once before re-templating anything else |
| 10.2 | Visual consistency | Medium | Builds on 10.1 macros |
| 10.3 | Forms & validation | Medium | Independent of 10.1/10.2 visuals |
| 10.4 | Help & onboarding | Small | Cheap, big perceived-quality lift |
| 10.5 | Logs overhaul | Large | Single-module deep dive; safe to slot anywhere after 10.2 |
| 10.6 | Resources polish | Medium | Per-module cleanup |
| 10.7 | Configuration modules | Medium | Per-module cleanup |
| 10.8 | Reports & notifications | Small | Per-module cleanup |
| 10.9 | Auth/Admin/Profile | Medium | Per-module cleanup |
| 10.10 | Errors & a11y | Medium | Final pass before features |
| 11.x | New features | Per item | Each independently shippable |

---

## Verification Strategy

Every phase ends with:
1. **Visual sweep** — open every page in light + dark mode + mobile width; screenshot diff against pre-phase.
2. **Template compile check** — `flask shell` → `app.jinja_env.get_template(name)` for every template (already automatable).
3. **Accessibility spot-check** — Lighthouse on dashboard + one list page + one detail page; track score over time.
4. **Manual smoke test** — login as admin, regular user, and shared-account user; click through every nav item.

