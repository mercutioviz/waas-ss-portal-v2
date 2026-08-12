# CLAUDE.md — WaaS Self-Service Portal v2

This file provides guidance to Claude Code when working in this repository.

## What v2 is

A parallel rewrite / overhaul of the WaaS Self-Service Portal. It runs alongside v1 on the same host without affecting it. Both portals talk to the same upstream Barracuda WaaS API — they only differ in the portal-local layer (UI, workflows, portal DB, dashboards).

- **v1 (prod):** `/home/admin/waas-ss-portal`, `https://ssportal.waaslab.com` — do not touch.
- **v2 (this repo):** `/home/admin/waas-ss-portal-v2`, `https://v2.ssportal.waaslab.com` — active development.

v2 was seeded from v1 on 2026-08-12 as a working baseline. From this point on the two codebases diverge — v2 is where the overhaul happens.

## Overhaul goals (top-5 target features)

1. **Web app profiler + guided "new site" wizard** — probe a customer's site (TLS, headers, tech stack, auth surface, content types) and generate a suggested starter WaaS config with plain-English rationale. Onboarding centerpiece.
2. **Config history + rollback** — snapshot every template apply / raw-config apply / bulk op / inline edit; one-click revert. Foundational safety net.
3. **Per-app security dashboard** — real-time-ish counters (blocks in last hour, top rules, top IPs, top URLs), sparklines.
4. **One-click FP exception + auto-tuning** — from the FP analysis page, pre-fill an exception with confidence scoring.
5. **Command palette + global search + persistent account scope** — cheap UX wins that make everything faster.

Framing themes (from the brainstorm): guided outcomes over exposed API surface; show me what's happening; configuration as a product (not a form); first-class onboarding.

## Running v2

```bash
cd /home/admin/waas-ss-portal-v2
source venv/bin/activate
python3 run.py                   # Dev mode on 0.0.0.0:5000 — conflicts with v1 dev server if both running
```

**In production (systemd):**
```bash
sudo systemctl status waas-portal-v2
sudo systemctl restart waas-portal-v2
sudo journalctl -u waas-portal-v2 -f
```

**Logs:** `logs/gunicorn-access.log`, `logs/gunicorn-error.log`, `logs/gunicorn-stdout.log`, `logs/gunicorn-stderr.log`.

**URL:** https://v2.ssportal.waaslab.com (self-signed cert).

## v2-specific paths & names

| Thing | v1 | v2 |
|-------|----|----|
| Working directory | `/home/admin/waas-ss-portal` | `/home/admin/waas-ss-portal-v2` |
| Hostname | `ssportal.waaslab.com` | `v2.ssportal.waaslab.com` |
| Unix socket | `waas-portal.sock` | `waas-portal-v2.sock` |
| systemd unit | `waas-portal.service` | `waas-portal-v2.service` |
| nginx site | `/etc/nginx/sites-enabled/ssportal.waaslab.com` | `/etc/nginx/sites-enabled/v2.ssportal.waaslab.com` |
| TLS cert | `/etc/ssl/self-signed/ssportal.waaslab.com.{crt,key}` | `/etc/ssl/self-signed/v2.ssportal.waaslab.com.{crt,key}` |
| SQLite DB | `instance/waas-portal.db` | `instance/waas-portal-v2.db` |
| DB URL env | (default) | `DATABASE_URL=sqlite:////home/admin/waas-ss-portal-v2/instance/waas-portal-v2.db` |
| Gunicorn proc_name | `waas-portal` | `waas-portal-v2` |
| SECRET_KEY | (systemd env) | (systemd env — same value as v1 so Fernet-encrypted API keys in the DB snapshot still decrypt) |

## Isolation rules

- **Never edit anything under `/home/admin/waas-ss-portal/`.** v1 is prod. Read-only reference only.
- **Never touch `/etc/systemd/system/waas-portal.service`** (v1 unit) or `/etc/nginx/sites-enabled/ssportal.waaslab.com` (v1 nginx site). Only `waas-portal-v2.*` is fair game.
- **Do not share the DB.** v2 has its own snapshot; they will diverge.
- Both portals hit the same real WaaS API upstream. Be aware that write operations you make from v2 (create app, edit rule, apply template) will affect real WaaS accounts and are visible in v1 too.
- If you need a v1 detail for reference, `grep`/`Read` from `/home/admin/waas-ss-portal/` is fine — just don't write there.

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
| `help` | `/help` | Contextual help pages |

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

## Migration path (for future reference)

When v2 reaches feature parity + the new features:
1. Snapshot v1 DB into v2 one more time at cutover.
2. Optionally, build an "import from v1" wizard.
3. Redirect `ssportal.waaslab.com` → `v2.ssportal.waaslab.com`, or swap the systemd/nginx names.
4. Keep v1 disabled but present for ~30 days as rollback.

## Notes for Claude in this repo

- Assume the WaaS API surface is the source of truth for what's possible — read `app/waas_client.py` before proposing new integrations, and consult the Swagger UIs above for field-level detail.
- Don't preserve v1 behavior for its own sake. v2 exists to change things — if a v1 pattern is bad, redesign it.
- Confirm before touching systemd, nginx, or `/etc/`.
- No test suite exists yet; the first substantial new feature is a good moment to introduce pytest.
