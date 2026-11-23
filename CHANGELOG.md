# Changelog

All notable changes to the WaaS Self-Service Portal v2.

Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Cutover — v2 is now the production portal (2026-11-20)

v2 took over every portal hostname; v1 is archived and decommissioned. Full
record in `docs/CUTOVER.md`.

v1 had been inactive since 2026-07-14 and was returning 502 to the ~148 bot
requests that still reached the old hostname, so there was no live service to
drain and no maintenance window. **No data was migrated** — v2's database has
been the live one since 2026-08-12 and is ahead of v1's in every respect.

- v1 archived to `/home/admin/archives/waas-ss-portal-v1-2026-11-20/` (4.6 MB):
  tree tarball minus `venv/`, SQLite DB via the backup API (`integrity_check:
  ok`), deployed systemd unit and nginx site, TLS keypair, v2's pre-cutover
  nginx site, `SHA256SUMS`, and a `MANIFEST.md` describing all of it. v1's git
  tree was clean and fully pushed to `mercutioviz/waas-ss-portal` at `304026a`.
- `waas-portal.service` stopped and disabled. The unit file and
  `/home/admin/waas-ss-portal` are kept as a rollback window and are
  **scheduled for deletion on or after 2026-12-20**.
- v2's nginx block now answers for `v2.ssportal.waaslab.com`,
  `ssportal.waaslab.com`, `portal.waaslab.com` and the `_` catch-all, and holds
  `default_server` for `:80` and `:443`. `portal.waaslab.com` is listed
  deliberately — the WaaS edge rewrites the Host header, so old-hostname
  requests arrive under that name.
- v1's nginx site moved to
  `/etc/nginx/sites-available/ssportal.waaslab.com.disabled-2026-11-20`.
- nginx reloaded rather than restarted (a user was mid-session); the v2 app
  service was not touched.

### Added — nightly database backups (2026-11-23)

Nothing was backing up the production database. The only copy on disk was a
manual `.bak` from 2026-10-07, taken when the database was a fifth its current
size. Full detail in `docs/BACKUPS.md`.

- `scripts/backup_db.py`, run by `waas-portal-v2-backup.timer` at 02:41.
  Two artifacts from one snapshot: the whole database gzipped (~50 MB, kept 14)
  and a SQL dump of everything except regenerable caches (~300 KB, kept 90).
  ~95% of the database is `security_metric_snapshots`, which the hourly capture
  job rebuilds by itself, so the small artifact is the one worth keeping for a
  quarter.
- Runs as a systemd timer rather than in APScheduler: copying 230 MB inside the
  single gevent worker would stall every request for ten seconds, and a backup
  that only runs while the app is healthy is the wrong shape. This host has no
  cron despite the leftovers in `/etc/cron.d`.
- Uses the SQLite backup API, not `cp` — the database is in WAL mode and under
  write. Every snapshot is `integrity_check`ed before compression.
- Both restore paths exercised end to end, including confirming all 12
  accounts' API keys decrypt out of a restored core dump.

### Fixed — one active log pull, enforced by the database (2026-11-23)

`create_pull` and `resume_pull` already refused to start while another pull was
active, so the v2.0.0 note claiming pulls were "not serialized" was out of date.
The real gap was narrower and harder to see: the check is check-then-act across
a gevent yield. `wsgi.py` calls `monkey.patch_all()`, and `create_pull` runs
`preflight()` — which talks to the WaaS API — between its `active_pull()` check
and its INSERT. Two overlapping submissions could both pass.

- Migration `e5b2c70f41aa` adds a partial unique index permitting one active
  standalone pull. `_claim_pull_slot()` turns the resulting `IntegrityError`
  into the same "already running" message, rather than a 500.
- The index is **scoped to `comparison_id IS NULL`**. A comparison arms every
  immediately-collectable window at once as several `pending` children and
  drains them sequentially, so pending children are a queue, not contention.
  The first draft of the index omitted this and broke arming outright; 20 tests
  in `test_traffic_comparison.py` caught it.
- Declared on the model as well as in the migration, because `wsgi.py` calls
  `db.create_all()` at import and a deployment built that way would otherwise
  have no index at all.

### Added — route-level coverage for template apply (2026-11-23)

`config_snapshots` was empty in production a month after config history
shipped. The cause was benign — every template apply failed before `f04e9a0`,
so `wrote_something` was never true — but nothing tested the route that records
the snapshot, only the module it calls.

- `tests/test_template_apply_route.py`: 13 tests covering snapshot recorded on
  success, on partial success, and *not* recorded when every part fails or the
  pre-state can't be read; section routing; permissions.
- The stub rejects keys `/import/` does not accept, so a test cannot pass
  against a payload the live API would have refused. Verified by reverting
  `f04e9a0` locally: 7 of the 13 fail, including the snapshot ones.

### Fixed

- **nginx no longer caps v2 requests at 60s.** `location /` had no
  `proxy_read_timeout`, so the 60s default applied and gunicorn's 120s timeout
  could never fire — slow endpoints returned a 504 *HTML* page that broke
  callers expecting JSON. Now `proxy_read_timeout` / `proxy_send_timeout` are
  180s, above gunicorn's 120s, so gunicorn times out first and the app's own
  error handling produces the response. `/socket.io/` and `/vnc/` keep 86400s.
  This resolves the second "Also of note" item under v2.0.0's known limitations.
- Applying a template sent every section to `/import/`, which rejects on the
  first unrecognised key — three of the four components `get_security_config()`
  produces have no counterpart in the import schema, so the apply failed with
  400 and wrote nothing. Each section now goes to the endpoint that owns it
  (`f04e9a0`).
- Bulk pages carrying both `data-loading` and `data-confirm-message` opened the
  confirm modal *underneath* the loading overlay, so bulk template apply
  appeared to hang forever and never issued the POST (`708c131`).

### Added

- `deploy/nginx/v2.ssportal.waaslab.com` — the nginx site is now
  version-controlled, matching the `deploy/logrotate/` pattern.
- `docs/CUTOVER.md`.

### Known limitations

- **Backups are local-only.** They sit on the same filesystem as the database,
  so they cover a bad migration or an accidental delete but not loss of the
  host. An off-host copy was deliberately deferred; the push step is the
  obvious next addition.
- **Two concurrent comparison armings are still unserialized.** Each creates
  its own set of child rows, which the index deliberately does not constrain.
  The scheduler that drains them is a single job, so they queue rather than
  collide — but nothing stops two users arming at the same moment.
- **`SECRET_KEY` is still `dev-secret-key-change-in-production`** on both units.
  It derives the Fernet key for stored WaaS API keys, so rotating it makes every
  stored credential undecryptable unless they are decrypted with the old key and
  re-encrypted with the new one in a single operation. Left alone during the
  cutover rather than risk breaking working credentials; worth scheduling
  deliberately, with a DB backup first.
- **The TLS cert still covers only `v2.ssportal.waaslab.com`.** Harmless for
  normal traffic — the edge reaches this origin over plain HTTP on `:80` — but
  direct-to-origin HTTPS on the other two names gives a name mismatch on an
  already self-signed cert. A SAN cert for all three names is staged at
  `/home/admin/staged-certs/waas-portal-multi.{crt,key}`; installing it needs
  write access to `/etc/ssl/self-signed/`.
- **The `v2.` prefix was not retired.** Making `ssportal.waaslab.com` the sole
  canonical name needs a WaaS edge application change, which is upstream of this
  host.

---

## [v2.0.0] — 2026-10-20

First tagged release of v2. Marks the point where all five overhaul goals have
shipped, plus an unplanned sixth track (traffic reduction analysis) that grew out
of real customer bandwidth work.

This is a **development milestone, not a production cutover.** v1 remains the
`ssportal.waaslab.com` hostname and v2 continues to run alongside it at
`v2.ssportal.waaslab.com`. See "Migration path" in `CLAUDE.md` for the eventual
cutover sequence.

Seeded from v1 on 2026-08-12 (`d20747d`); 46 commits to `043e522`.

### Goal 1 — Web app profiler + guided "new site" wizard

Probes a customer's site and generates a suggested starter WaaS config with
plain-English rationale.

- Profiler backend: model, probe engine, recommender, migration (`4765301`)
- Wizard UI, blueprint, live SocketIO progress, nav entry (`fe32c5d`)
- Probe expanded to security headers, cookies, subresources, DNS (`6dfafa6`)
- Recommender expanded with descriptions and advisories driven by the new probe
  data (`47523e6`)
- Results page redesigned into three sections (`643d355`)
- History view with re-run and delete (`28b6ca9`)
- Apex/www redirect-direction check (`ee2c927`)
- Cache-policy analysis (`e99b95e`)
- robots.txt analysis (`a445e66`)

### Goal 2 — Config history + rollback

Snapshots every config-changing operation; one-click revert.

- `ConfigSnapshot` model, revert engine, diff UI (`f79e7b2`)

### Goal 3 — Per-app security dashboard

- Blocks in last hour, top rules/IPs/URLs, sparklines (`a155bc9`)
- Charts no longer time out behind nginx's 60s proxy cap (`925da98`)

### Goal 4 — One-click FP exception + auto-tuning

- Pre-filled exceptions with confidence scoring from the FP analysis page
  (`app/fp_scoring.py`, covered by `test_fp_scoring.py` / `test_fp_action.py`)

### Goal 5 — Command palette + global search + persistent account scope

- Account/Config Review plan phases 1–6, command palette, global search, and
  account scope that persists across views (`ae2424e`)

### Traffic reduction analysis (unplanned track)

Added to answer "what is actually consuming this account's metered bandwidth,
and what would cut it." Development plan in `docs/TRAFFIC_ANALYSIS_PLAN.md`;
all seven phases complete.

- Development plan (`16dfe65`)
- `traffic_insights.py` + truncation-aware config advisor (`64f34e5`, `bc1167f`)
- Log pull engine: bisect fetcher, pre-flight estimate, storage, retention,
  durable progress (`8382804`)
- Cache analysis over a completed pull + live origin header audit (`60f79e9`)
- Crawler classification, IP verification, URL-space cross-tab (`32b5f8e`)
- robots.txt proposal engine measured by replay (`dcd18e7`)
- Customer-facing report + standalone export (`ad53d83`)
- Per-app traffic hints on the application list (`a9a9d70`, `cfc183d`)
- Before/after traffic comparison across a config change (`a476c21`)
- Comparison UI with custom date ranges (`ec28724`)
- Abusive-client detection by behaviour rather than requested path (`2792778`)
- Origin follow-ups run automatically on request (`043e522`)

### Other changes

- Alembic migrations and pytest scaffolding (`6b593b6`)
- WaaS account deletion, working end to end (`4c23efa`)
- Application output moved to the systemd journal; remaining gunicorn files
  rotated daily via `/etc/logrotate.d/waas-portal-v2`, with `deploy/logrotate/`
  as the source of truth (`fceacde`, `0b4547c`)
- Bandwidth report verified to describe the account being viewed (`16c44f8`)
- Report "how" lines point at buttons that actually exist (`c9c9971`)
- Navbar no longer clips its right-hand end (`3927dc4`)
- Favicons (`9073476`, `356047c`)

### Fixed

- Profiler account-selection dead-end (`7b32528`)
- Profiler watch page receiving no live progress (`57c2d7d`)
- Profiler live progress wiped by wsgi double-init clearing SocketIO handlers
  (`50ac1d6`)
- Alert card rendering (`51f4ea7`, `6496613`, `faf9f7b`)

### Known limitations

Open design calls recorded in `docs/TRAFFIC_ANALYSIS_PLAN.md` §8 — deliberately
not resolved for this release:

1. **Full-mode pulls on very large apps** are impractical (~37 h for a 30-day
   ICC pull). No hard refusal threshold or typed-confirmation gate exists yet;
   the pre-flight estimate is the only guard.
2. **Concurrent pulls are not serialized.** One gevent worker, one event loop —
   starting a second pull while one is running is not prevented.
3. **Pulls are on-demand only.** APScheduler is already present, so recurring
   pulls are feasible, but nothing is scheduled.

Also of note:

- SQLite foreign-key cascades are inert in this deployment (`PRAGMA
  foreign_keys=0`), so `ondelete='CASCADE'` never fires; deletion paths handle
  children explicitly.
- nginx's `location /` for v2 has no `proxy_read_timeout`, so requests are
  capped at the 60s default regardless of gunicorn's 120s timeout.

### Test suite

1204 tests passing at tag time (`python -m pytest -q`, ~2 minutes). The
`datetime.utcnow()` deprecation warnings under Python 3.13 are known and
non-fatal.
