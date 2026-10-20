# WaaS Self-Service Portal v2

A parallel rewrite of the Barracuda WAFaaS self-service portal, running alongside v1 on the same host. Both portals talk to the same upstream Barracuda WaaS API — they differ only in the portal-local layer (UI, workflows, portal DB, dashboards).

- **v2** (active development): `https://v2.ssportal.waaslab.com` — this repo, `/home/admin/waas-ss-portal-v2`.
- **v1** (production): `https://ssportal.waaslab.com` — `/home/admin/waas-ss-portal`, read-only reference.

Current release: **v2.0.0** (2026-10-20) — all five overhaul goals shipped, plus the
traffic reduction analysis track. A development milestone, not a production cutover:
v1 still owns the `ssportal.waaslab.com` hostname.

See [`CLAUDE.md`](CLAUDE.md) for architecture, isolation rules, run instructions, and
target features, and [`CHANGELOG.md`](CHANGELOG.md) for what landed in each release.

## Tests

```bash
source venv/bin/activate
python -m pytest -q          # ~1200 tests, about two minutes
```
