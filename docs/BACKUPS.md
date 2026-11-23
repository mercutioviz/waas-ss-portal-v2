# Database backups

The portal's SQLite database is backed up nightly at **02:41** by a systemd
timer. Added 2026-11-23, after the cutover made this database the only copy of
anything that matters.

```
systemctl list-timers waas-portal-v2-backup.timer   # when it next runs
journalctl -u waas-portal-v2-backup -n 20           # what the last run did
sudo systemctl start waas-portal-v2-backup.service  # run one now
```

## What gets written

`/home/admin/backups/waas-portal-v2/` — mode 700, because these files carry
Fernet-encrypted WaaS credentials.

| Path | What | Size | Kept |
|------|------|------|------|
| `full/waas-portal-v2-<date>.db.gz` | Whole database, gzipped | ~50 MB | 14 |
| `core/core-<date>.sql.gz` | SQL dump of everything except regenerable caches | ~300 KB | 90 |
| `manual/` | A one-off `.bak` from 2026-10-07, moved out of `instance/` at setup. Not managed by the job; delete when you're happy it's redundant. | 46 MB | — |

Both artifacts come from **one** snapshot, so they describe the same instant.

**Why two.** The full copy makes recent recovery a two-command operation, but
~95% of its bytes are `security_metric_snapshots` — 500k rows the hourly capture
job rebuilds from the WaaS API by itself. The core dump drops that and is small
enough to keep for a quarter, so a mistake found late is still recoverable for
the data that can't be rebuilt: accounts and their credentials, templates, raw
configs, config history, and the audit trail.

Excluded from the core dump (`EXCLUDED_FROM_CORE` in `scripts/backup_db.py`):
`security_metric_snapshots`, `app_traffic_snapshots`, `proxy_sessions`.

The exclusion list is **deny-list, not allow-list**: a table added by a future
migration is backed up automatically. Leaving a table out is a decision someone
has to make explicitly, rather than something that happens by forgetting.

Note the core dump still contains the *schema* for excluded tables, so a restore
from it gives correctly-shaped empty tables that the app's own jobs refill.

## Restoring

### From a full backup — the usual case

```bash
sudo systemctl stop waas-portal-v2
cd /home/admin/waas-ss-portal-v2/instance
mv waas-portal-v2.db waas-portal-v2.db.before-restore      # keep the bad one
gunzip -c /home/admin/backups/waas-portal-v2/full/waas-portal-v2-<date>.db.gz \
      > waas-portal-v2.db
sudo systemctl start waas-portal-v2
```

Check it came up: `journalctl -u waas-portal-v2 -n 30`.

Don't delete the database you replaced until the restored one has been used.

### From a core dump — when the full backups are too old

```bash
sudo systemctl stop waas-portal-v2
cd /home/admin/waas-ss-portal-v2/instance
mv waas-portal-v2.db waas-portal-v2.db.before-restore
gunzip -c /home/admin/backups/waas-portal-v2/core/core-<date>.sql.gz \
  | /home/admin/waas-ss-portal-v2/venv/bin/python -c \
      "import sqlite3,sys; c=sqlite3.connect('waas-portal-v2.db'); \
       c.executescript(sys.stdin.read()); c.commit()"
sudo systemctl start waas-portal-v2
```

The dashboard's history will be empty and refill over the following days as the
hourly capture job runs. Everything else is immediately present.

### Verifying a restore before you trust it

```bash
cd /home/admin/waas-ss-portal-v2
venv/bin/python - <<'PY'
import sqlite3
from flask import Flask
from app.encryption import decrypt_value
app = Flask(__name__); app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
c = sqlite3.connect('file:instance/waas-portal-v2.db?mode=ro', uri=True)
with app.app_context():
    for i, name, blob in c.execute(
            'SELECT id, account_name, api_key_encrypted FROM waas_accounts ORDER BY id'):
        ok = bool(blob) and bool(decrypt_value(blob))
        print(f'  [{i}] {name:<22} api_key={"OK" if ok else "MISSING/UNREADABLE"}')
PY
```

If credentials come back unreadable, the `SECRET_KEY` the app is running under
does not match the one in force when that backup was taken. **This is the single
way these backups can quietly become worthless** — see below.

## The SECRET_KEY dependency

`app/encryption.py` derives the Fernet key from `SECRET_KEY` (set in
`/etc/systemd/system/waas-portal-v2.service`). Every encrypted column in every
backup is readable only with the key in force when it was written.

So **rotating `SECRET_KEY` invalidates every existing backup's credentials**,
silently — nothing errors at rotation time, and you find out only when a restore
produces accounts that can't talk to the WaaS API.

If `SECRET_KEY` is ever rotated:

1. Take a backup first.
2. Decrypt every encrypted column with the old key and re-encrypt with the new
   one **in the same operation** — not as two separate steps.
3. Take a fresh backup immediately after, and note in this file which backups
   predate the rotation. Those older ones still restore, but their credentials
   need re-entering by hand.

The key is currently still the inherited `dev-secret-key-change-in-production`.
Rotating it is tracked under "Known limitations" in `CHANGELOG.md`.

## What this does and doesn't protect against

**Does:** a bad migration, an accidental delete, a corrupted write, a wrong bulk
operation, or anything else that damages the database while the host survives.

**Doesn't:** loss of the host or its disk. Backups sit on the same filesystem as
the database. An off-host copy was deliberately deferred at setup — see
`CHANGELOG.md`. The push step is the obvious next addition; everything else is
already in place.

Disk headroom as of setup: 96 GB free, and the job's full retention tops out
around 700 MB.

## Design notes

- **Runs outside the app, not in APScheduler.** The portal runs a single gevent
  worker; copying a 230 MB file inside it would stall every request for ten
  seconds. A backup that only runs while the app is healthy is also the wrong
  shape — a wedged app is exactly when you want the backup to have happened.
- **Uses the SQLite backup API**, not `cp`. The database is in WAL mode and
  being written to; a plain copy mid-write yields a torn file that may appear
  fine and fail much later, when it's needed.
- **Every snapshot is `PRAGMA integrity_check`ed** before it's compressed. A
  backup that doesn't open isn't a backup.
- **Retention prunes by count, not age.** If the timer is down for a month, age
  pruning would delete everything while no new backups arrived.
- **`Persistent=true`** on the timer, so a run missed while the host was off
  fires at next boot rather than being skipped.
- Both restore paths above were exercised end to end at setup, including
  confirming all 12 accounts' API keys decrypt out of a restored core dump.
