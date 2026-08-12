# WaaS Self-Service Portal v2

A parallel rewrite of the Barracuda WAFaaS self-service portal, running alongside v1 on the same host. Both portals talk to the same upstream Barracuda WaaS API — they differ only in the portal-local layer (UI, workflows, portal DB, dashboards).

- **v2** (active development): `https://v2.ssportal.waaslab.com` — this repo, `/home/admin/waas-ss-portal-v2`.
- **v1** (production): `https://ssportal.waaslab.com` — `/home/admin/waas-ss-portal`, read-only reference.

See [`CLAUDE.md`](CLAUDE.md) for architecture, isolation rules, run instructions, and target features.
