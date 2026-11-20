# CLAUDE.md — WaaS Self-Service Portal v2

This file provides guidance to Claude Code when working in this repository.

## What v2 is

**v2 is the WaaS Self-Service Portal.** It is no longer a parallel rewrite running
beside v1 — since the cutover on **2026-11-20** it serves every portal hostname and
v1 is decommissioned. Full record in `docs/CUTOVER.md`.

- **v2 (this repo, prod):** `/home/admin/waas-ss-portal-v2`. Answers on
  `v2.ssportal.waaslab.com`, `ssportal.waaslab.com`, `portal.waaslab.com` and the
  nginx `_` catch-all — all the same app. The `v2.` prefix is the one people use;
  retiring it needs a WaaS edge change upstream of this host.
- **v1 (decommissioned):** `/home/admin/waas-ss-portal`. Service stopped and
  disabled, nginx site disabled, archived to
  `/home/admin/archives/waas-ss-portal-v1-2026-11-20/`. The tree is kept as a
  rollback window and is **scheduled for deletion on or after 2026-12-20** — after
  that date it is gone and the archive is the only copy on this host (the code also
  lives at `github.com/mercutioviz/waas-ss-portal` at `304026a`).

v2 was seeded from v1 on 2026-08-12 and the two diverged from there; v2's database
has been the live one ever since. Nothing was migrated out of v1's DB at cutover.

## Overhaul goals (top-5 target features)

1. **Web app profiler + guided "new site" wizard** — probe a customer's site (TLS, headers, tech stack, auth surface, content types) and generate a suggested starter WaaS config with plain-English rationale. Onboarding centerpiece.
2. **Config history + rollback** — snapshot every template apply / raw-config apply / bulk op / inline edit; one-click revert. Foundational safety net.
3. **Per-app security dashboard** — real-time-ish counters (blocks in last hour, top rules, top IPs, top URLs), sparklines.
4. **One-click FP exception + auto-tuning** — from the FP analysis page, pre-fill an exception with confidence scoring.
5. **Command palette + global search + persistent account scope** — cheap UX wins that make everything faster.

Framing themes (from the brainstorm): guided outcomes over exposed API surface; show me what's happening; configuration as a product (not a form); first-class onboarding.

**All five shipped as of `v2.0.0` (2026-10-20)**, along with an unplanned sixth track —
traffic reduction analysis (log pulls, cache/crawler/abuse analysis, robots.txt
proposals, before/after comparison). See `CHANGELOG.md`. The goals above are now the
record of what v2 set out to do, not a to-do list.

## Running v2

```bash
cd /home/admin/waas-ss-portal-v2
source venv/bin/activate
python3 run.py                   # Dev mode on 0.0.0.0:5000
```

**In production (systemd):**
```bash
sudo systemctl status waas-portal-v2
sudo systemctl restart waas-portal-v2
sudo journalctl -u waas-portal-v2 -f
```

**Logs:** application output (anything the app or a traceback writes) goes to the journal — `journalctl -u waas-portal-v2 -f`. Gunicorn's own two files stay on disk: `logs/gunicorn-error.log` (startup and signals) and `logs/gunicorn-access.log` (always empty — `GeventWebSocketWorker` never calls the access logger; per-request logging comes from nginx). Both are rotated daily by `/etc/logrotate.d/waas-portal-v2`; the source of truth for that config is `deploy/logrotate/`. `logs/gunicorn-stdout.log` and `logs/gunicorn-stderr.log` are historical — nothing has written to them since stdio moved to the journal on 2026-10-03.

The `app.waas_client` logger runs at INFO in production and DEBUG only under `app.debug`. Do not pin it back to DEBUG unconditionally: at DEBUG it logs full request headers and 500 characters of every response body, which during a log pull is customer traffic data at hundreds of lines per minute.

**URL:** https://v2.ssportal.waaslab.com (self-signed cert). `ssportal.waaslab.com` and `portal.waaslab.com` reach the same app; see "Hostnames" below.

## Paths & names

| Thing | Value |
|-------|-------|
| Working directory | `/home/admin/waas-ss-portal-v2` |
| Hostnames | `v2.ssportal.waaslab.com`, `ssportal.waaslab.com`, `portal.waaslab.com`, nginx `_` catch-all |
| Unix socket | `waas-portal-v2.sock` |
| systemd unit | `waas-portal-v2.service` |
| nginx site | `/etc/nginx/sites-enabled/v2.ssportal.waaslab.com` → `sites-available/`; source of truth is `deploy/nginx/` in this repo |
| TLS cert | `/etc/ssl/self-signed/v2.ssportal.waaslab.com.{crt,key}` |
| SQLite DB | `instance/waas-portal-v2.db` |
| DB URL env | `DATABASE_URL=sqlite:////home/admin/waas-ss-portal-v2/instance/waas-portal-v2.db` |
| Gunicorn proc_name | `waas-portal-v2` |
| SECRET_KEY | (systemd env) — still the inherited `dev-secret-key-change-in-production`. It derives the Fernet key for stored API keys, so **rotating it makes every stored credential undecryptable** unless they are decrypted with the old key and re-encrypted with the new one in one operation. |

### Hostnames

All four names serve this same app; none of them redirect. `portal.waaslab.com` is
in the nginx `server_name` list deliberately — the **WaaS edge rewrites the Host
header**, so a request a user sends to `ssportal.waaslab.com` arrives at this origin
as `Host: portal.waaslab.com`. `/var/log/nginx/debug-host.log` is the only log that
records `$host`, so it is the one to check when hostname routing is in question.

v2's block also holds `default_server` for `:80` and `:443`. Only one block may, so
anything that adds a competing `default_server` will make `nginx -t` fail.

## Rules

- **`/home/admin/waas-ss-portal/` (v1) is decommissioned, not prod.** Still don't
  edit it — it exists only as the rollback window until 2026-12-20, and changes to
  it are pointless rather than dangerous. `grep`/`Read` for reference is fine.
- **Don't re-enable `waas-portal.service` or the disabled v1 nginx site**
  (`/etc/nginx/sites-available/ssportal.waaslab.com.disabled-2026-11-20`) without
  reading `docs/CUTOVER.md` first. Both reclaim hostnames v2 now holds, and the
  duplicate `default_server` will stop nginx from loading.
- **Confirm before touching systemd, nginx, or `/etc/`.** Changes to the nginx site
  go in `deploy/nginx/` first, then get installed from there — don't hand-edit
  `/etc/nginx/sites-available/` and leave the repo stale.
- Reload nginx (`systemctl reload nginx`), don't restart it — long-running log pulls
  and SocketIO sessions survive a reload.
- v2 writes against the **real upstream WaaS API**. Creating an app, editing a rule,
  or applying a template affects live customer accounts.

## Architecture (inherited from v1)

Flask 3.1 / Python 3.13. Application factory in `app/__init__.py` → `create_app()`. Blueprints:

| Blueprint | Prefix | Purpose |
|-----------|--------|---------|
| `main` | `/` | Landing page, dashboard |
| `auth` | `/auth` | Login, logout, profile, password reset, notifications |
| `admin` | `/admin` | User management, audit log |
| `accounts` | `/accounts` | WaaS API account CRUD, sharing |
| `applications` | `/applications` | Browse WaaS apps, security config, rewrites, response pages, clone, bulk ops |
| `certificates` | `/certificates` | Browse, upload, replace SNI certs |
| `logs` | `/logs` | WAF logs, access logs, false positive analysis |
| `proxy` | `/proxy` | noVNC-backed test-as-user sessions |
| `reports` | `/reports` | Scheduled email reports |
| `templates` | `/templates` | Config templates (CRUD, apply, bulk-apply) |
| `features` (a.k.a. `/raw-configs`) | `/raw-configs` | Raw-config library, predefined configs |
| `features_legacy` | `/features` | 301 redirect to `/raw-configs/*` |
| `help` | `/help` | Contextual help pages |
| `profiler` | `/profiler` | Web app profiler + guided "new site" wizard (goal 1) |
| `config_history` | `/config-history` | Config snapshots, diffs, one-click rollback (goal 2) |
| `review` | `/review` | Account/config review report |
| `search` | `/search` | Global search backing the command palette (goal 5) |
| `traffic` | `/traffic` | Log pulls, cache/crawler/abuse analysis, robots.txt proposals |
| `traffic_compare` | `/traffic/compare` | Before/after traffic comparison across a config change |

Note the registration order for the two traffic blueprints: `traffic` owns `/traffic`
and `traffic_compare` owns the more specific `/traffic/compare`.

**Key modules:**
- `app/waas_client.py` — `WaasClient` wrapping WaaS v2 + v4
- `app/models.py` — `User`, `WaasAccount`, `AuditLog`, `ProxySession`, `SystemSettings`, `Feature`, notifications, reports, templates
- `app/forms.py` — WTForms
- `app/encryption.py` — Fernet encrypt/decrypt for API keys at rest

## WaaS API Documentation

- **v4 API (Swagger UI):** https://api.waas.barracudanetworks.com/v4/swagger/#/
- **v2 API (Swagger UI):** https://api.waas.barracudanetworks.com/swagger/#/

Consult these when adding new API integrations. Swagger UIs are JavaScript-rendered; underlying specs are not publicly accessible without auth, but all field names, types, and endpoint paths can be found there.

## WaaS API Integration (Dual Versions)

| API | Base URL | Auth Header | Used For |
|-----|----------|-------------|----------|
| **v4** (primary) | `.../v4/waasapi` | `Authorization: Bearer <api_key>` | Applications, certs, logs, proxy, security config |
| **v2** (legacy) | `.../v2/waasapi` | `auth-api: <token>` (no Bearer prefix) | Account verification, some app CRUD |

- `WaasClient.from_account(account)` picks auth method (API key or v2 email/password).
- v2 tokens cached encrypted on `WaasAccount`, auto-refresh when expired.
- All API calls go through `_make_request()`; pass `api_version='v2'` for v2-only endpoints.
- Errors raised as `WaasApiError`.

### Traffic Rewrites (v4 API)

Four rewrite types under `/applications/{app_id}/`:

| Type | Swagger Section | Key Fields |
|------|----------------|------------|
| **Request Rewrite** | `App \| Request Rewrite` | name, sequence_number (1–1500), action, header, rewrite_value_type, old_value, rewrite_value, condition, continue_processing, comments |
| **Response Rewrite** | `App \| Response Rewrite` | name, sequence_number (1–1500), action, header, old_value, rewrite_value, condition, continue_processing, comments |
| **Response Body Rewrite** | `App \| Response Body Rewrite` | name, sequence_number (1–1500), url, host, search_string, replace_string, comments. `text/*` only. `\r`/`\n` unsupported. |
| **URL Translation** | `App \| Url Translation` | name, inside_prefix, outside_prefix, inside_domain, outside_domain, comments. No sequence number. |

**Sequence numbers:** 1–1500; lowest runs first. Once a rule matches, no subsequent rules run unless `continue_processing=true`.

**Request Rewrite macros:** `$SRC_ADDR`, `$URI`, `$COUNTRY_CODE`, `$X509_VERSION`, `$X509_SERIAL_NUMBER`, `$X509_SIGNATURE_ALGORITHM`, `$X509_ISSUER`, `$X509_NOT_VALID_BEFORE`, `$X509_NOT_VALID_AFTER`, `$X509_SUBJECT`, `$X509_SUBJECT_PUBLIC_KEY_TYPE`, `$X509_SUBJECT_PUBLIC_KEY`, `$X509_SUBJECT_PUBLIC_KEY_RSA_BITS`, `$X509_EXTENSIONS`, `$X509_HASH`, `$X509_WHOLE`, `X509_SAN_EMAIL`, `X509_IAN_EMAIL`.

### Response Pages (v4 API)

Swagger: `App | Response Pages`. Endpoint: `/applications/{app_id}/response_pages/`.

Macros: `%action-id`, `%attack-name`, `%attack-time`, `%client-ip`, `%host`, `%log-id`, `%s`.

CAPTCHA pages use hardcoded resources (`captcha.gif`, `captcha_resp`, `captcha_resp_txt`) — do not alter. Images may be embedded as base64 data URIs (max 12KB each).

## Critical Patterns & Pitfalls (inherited from v1 — still apply)

- **`User.display_name` is a read-only @property** — computed from first_name/last_name/username. Never set it directly.
- **`AuditLog.timestamp`** is the datetime field, NOT `created_at`.
- **`WaasAccount` has no `description` field.** Requires at least one credential type (API key OR email+password).
- **Account ownership** — always filter by `user_id=current_user.id` when querying WaasAccount.
- **Encrypted properties** — use `account.api_key` (auto-encrypts/decrypts), never `api_key_encrypted` directly. Same for `waas_email`, `waas_password`, `v2_auth_token`.
- **Form-template sync** — every `form.field_name` in a template must exist on the form class, and vice versa.
- **POST-only actions** — delete/verify/toggle routes must be POST; use form buttons, not `<a>` tags.
- **CSRF for non-WTForms POSTs** — use `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`.

## Route Pattern: Account-Scoped Resources

Applications, certificates, logs, and proxy settings are scoped to a WaaS account:
- List views take `?account_id=N` as query parameter
- Detail views use `/<int:account_id>/<resource_id>` in URL path
- Helper `get_client_for_account(account_id)` verifies ownership and returns `(WaasClient, account)`

## Frontend (inherited)

Bootstrap 5.3.3 + Bootstrap Icons 1.11.3 (CDN). Templates extend `base.html`. Cards + `table table-hover`. Custom CSS in `app/static/css/style.css`, JS in `app/static/js/app.js`. Template filters: `datetime_format`, `filesizeformat`, `epoch_ms`, `null_dash`.

v2 may replace or overhaul the frontend as part of the redesign — decisions to be made per feature.

## Migration path — done

Completed 2026-11-20. Steps 1 and 2 (snapshot v1's DB, build an import wizard) were
dropped as unnecessary: v2's database had been the live one since 2026-08-12 and was
ahead of v1's, which by then held four-month-old data nobody wanted. Step 3 was done
by having v2 answer on every hostname rather than by redirecting. Step 4 (v1 disabled
but present ~30 days) is in effect until **2026-12-20**.

See `docs/CUTOVER.md` for what was done and how to roll it back.

**Open after cutover:** `SECRET_KEY` is still the dev default; the TLS cert covers
only `v2.ssportal.waaslab.com` (a SAN cert for all three names is staged at
`/home/admin/staged-certs/`); retiring the `v2.` prefix needs a WaaS edge change.
Details under "Known limitations" in `CHANGELOG.md`.

## Notes for Claude in this repo

- Assume the WaaS API surface is the source of truth for what's possible — read `app/waas_client.py` before proposing new integrations, and consult the Swagger UIs above for field-level detail.
- Don't preserve v1 behavior for its own sake. v2 exists to change things — if a v1 pattern is bad, redesign it.
- Confirm before touching systemd, nginx, or `/etc/`.
- A pytest suite lives in `tests/` (38 files, ~1200 tests; `python -m pytest -q`, about two minutes). Extend it alongside new features — don't bootstrap a second one.
