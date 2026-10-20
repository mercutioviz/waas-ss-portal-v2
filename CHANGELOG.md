# Changelog

All notable changes to the WaaS Self-Service Portal v2.

Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
