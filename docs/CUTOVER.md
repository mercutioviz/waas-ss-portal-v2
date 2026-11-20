# v1 → v2 Cutover

**Executed 2026-11-20.** v2 now serves every portal hostname. v1 is archived and
decommissioned.

This document records what was done, what it assumed, and how to undo it.

---

## What the cutover actually was

Less dramatic than the migration path in `CLAUDE.md` anticipated, because **v1 was
already dead before it started**:

- `waas-portal.service` had been inactive since 2026-07-14 — roughly four months.
- Every request to the old hostname for the preceding two weeks returned **502**,
  because nginx was proxying to a Unix socket with nothing listening on it.
- All 148 of those requests were bots and scanners (`wpbot`, `CMS-Checker`, and
  probes for `key.json` / `application_default_credentials.json`). No human
  traffic. Nothing was in use that could be interrupted.

So there was no drain, no maintenance window and no dual-run period to manage.
The work was: archive v1, stop it from ever coming back, and move the hostnames
onto v2 so the old URL serves something again instead of a 502.

**No data was migrated.** v2's database has been the live one since 2026-08-12 and
holds real working data; it is ahead of v1's in every respect. v1's database was
archived for reference only.

## Steps performed

### 1. Archive

`/home/admin/archives/waas-ss-portal-v1-2026-11-20/` — 4.6 MB total.

Full tree tarball (minus `venv/`), the SQLite DB extracted via the backup API with
`integrity_check: ok`, the deployed systemd unit and nginx site, the v1 TLS
keypair, v2's pre-cutover nginx site for rollback, and `SHA256SUMS` over all of it.
`MANIFEST.md` in that directory is the authoritative description.

v1's git tree was clean and fully pushed to `github.com/mercutioviz/waas-ss-portal`
at `304026a`, so the code was never at risk; the archive covers what existed only
on this host.

### 2. Decommission v1

```
sudo systemctl stop waas-portal      # already inactive
sudo systemctl disable waas-portal   # removed from multi-user.target.wants
```

The unit file remains at `/etc/systemd/system/waas-portal.service`, and
`/home/admin/waas-ss-portal` remains on disk, as the rollback window.

**Both are scheduled for deletion on or after 2026-12-20.**

### 3. Hostnames onto v2

v1's nginx site held `default_server` for `:80` and `:443` and answered for
`ssportal.waaslab.com` plus the `_` catch-all. v2's block now holds all of it:

```nginx
server_name v2.ssportal.waaslab.com
            ssportal.waaslab.com
            portal.waaslab.com
            _;

listen 80 default_server;
listen 443 ssl default_server;
```

The v1 site file was moved to
`/etc/nginx/sites-available/ssportal.waaslab.com.disabled-2026-11-20` rather than
deleted. It was a regular file in `sites-enabled`, not a symlink — unlike v2's.

**`portal.waaslab.com` is listed deliberately and is not a typo.** The WaaS edge
rewrites the Host header for the old-hostname application, so requests that a user
sends to `ssportal.waaslab.com` arrive at this origin with
`Host: portal.waaslab.com`. Omitting it would have left the old URL falling through
to the `_` catch-all — which works, but only by accident. Both are listed so the
intent is explicit.

These two changes had to land together: nginx refuses to start with two blocks
claiming `default_server` on the same listen address.

### 4. The 60-second proxy timeout

`location /` had no `proxy_read_timeout`, so nginx's 60s default applied and
gunicorn's 120s timeout could never fire. Slow endpoints returned a 504 **HTML**
page, which broke every caller that expected JSON. Now:

```nginx
proxy_connect_timeout 10s;
proxy_send_timeout 180s;
proxy_read_timeout 180s;
```

180s is above gunicorn's 120s on purpose: gunicorn times out first, so the app's
own error handling produces the response instead of nginx substituting an error
page. `/socket.io/` and `/vnc/` keep their 86400s — they are long-lived upgrades,
not request/response.

### 5. Source of truth moved into the repo

The nginx site is now version-controlled at `deploy/nginx/v2.ssportal.waaslab.com`,
matching the existing `deploy/logrotate/` pattern. Install with:

```
sudo cp deploy/nginx/v2.ssportal.waaslab.com \
        /etc/nginx/sites-available/v2.ssportal.waaslab.com
sudo nginx -t && sudo systemctl reload nginx
```

nginx was **reloaded, not restarted** — a user was mid-session on a traffic-pull
watch page at the time, and reload is graceful. The v2 app service was not touched
at all.

## Verification

`nginx -t` passed before reload. After reload, all four hostnames — including an
unmatched name exercising the catch-all — returned `302 → /auth/login` over both
HTTP and HTTPS, and `/auth/login` itself returned `200` with the v2 title. The
v2-only routes `/profiler/`, `/traffic/` and `/config-history/` all returned `302`
rather than `404`, confirming v2 is the app behind the old hostname.

(`/search/` returns 404 by design — that blueprint only registers `/search/api`.)

## Known gaps

**TLS certificate name mismatch.** The block still presents
`v2.ssportal.waaslab.com.crt`, which has no SAN for the other two names. This does
not affect normal traffic: the edge reaches this origin over plain HTTP on `:80`
(access logs record `ssl_sni=-`), so the cert is only consulted on direct-to-origin
HTTPS — the security-group-gated debugging path, where the cert is already
self-signed and click-through.

A replacement with SANs for all three names is generated and staged at
`/home/admin/staged-certs/waas-portal-multi.{crt,key}` (CN
`ssportal.waaslab.com`, expires 2036-11-17). Installing it needs two commands:

```
sudo install -o root -g root -m 644 \
  /home/admin/staged-certs/waas-portal-multi.crt /etc/ssl/self-signed/
sudo install -o root -g root -m 600 \
  /home/admin/staged-certs/waas-portal-multi.key /etc/ssl/self-signed/
```

then repoint `ssl_certificate` / `ssl_certificate_key` in
`deploy/nginx/v2.ssportal.waaslab.com` and reinstall.

**`SECRET_KEY` is still `dev-secret-key-change-in-production`.** It derives the
Fernet key for stored WaaS API keys, so rotating it makes every stored credential
undecryptable unless they are decrypted with the old key and re-encrypted with the
new one in the same operation. Deliberately left alone during the cutover rather
than risk breaking working credentials. See `CHANGELOG.md` → Known limitations.

**Retiring the `v2.` prefix was not attempted.** Making `ssportal.waaslab.com` the
sole canonical name requires a change to the WaaS edge application config, which
is upstream of this host and not reachable from it. Today all names serve the same
app, which is the useful half of that outcome.

## Rollback

Within the 30-day window, v1 can be brought back by reversing step 3 and
re-enabling the unit. The ordering constraint is the same in reverse — restore
v2's pre-cutover site from
`archives/.../config/nginx-v2.ssportal.waaslab.com.conf.pre-cutover` *before*
re-enabling v1's site, or `nginx -t` will reject the duplicate `default_server`.
Full procedure in the archive's `MANIFEST.md`.

Note that v1 and v2 share the same upstream WaaS API. Running both at once means
two portals issuing writes against the same real WaaS accounts.
