#!/usr/bin/env python3
"""Nightly backup of the portal's SQLite database.

Writes two artifacts per run, from a single consistent snapshot:

  full/waas-portal-v2-<date>.db.gz   whole database, gzipped. Restore by
                                     gunzipping it over instance/. Kept 14.
  core/core-<date>.sql.gz            SQL dump of everything EXCEPT the
                                     regenerable caches. ~200 KB. Kept 90.

Why both: the full copy makes recent recovery a two-command operation, but
~95% of its bytes are `security_metric_snapshots`, which the hourly capture
job rebuilds from the WaaS API anyway. The core dump is small enough to keep
for a quarter, so a mistake discovered late is still recoverable for the data
that actually matters — accounts, credentials, templates, config history and
the audit trail.

Run from cron as the `admin` user, NOT from the app's APScheduler: copying a
230 MB file inside the single gevent worker would stall the portal for the
duration, and a backup that only runs while the app is healthy is the wrong
shape. See docs/BACKUPS.md.

    venv/bin/python scripts/backup_db.py            # normal nightly run
    venv/bin/python scripts/backup_db.py --dry-run  # report, write nothing

Exits non-zero on any failure, so cron mails/logs it.
"""
import argparse
import gzip
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path('/home/admin/waas-ss-portal-v2/instance/waas-portal-v2.db')
#: Own namespace under the shared backups directory — /home/admin/backups also
#: holds other projects' output, so this must not assume the whole tree is its
#: own, and in particular must not restrict permissions on the shared parent.
BACKUP_ROOT = Path('/home/admin/backups/waas-portal-v2')

KEEP_FULL = 14
KEEP_CORE = 90

#: Tables deliberately left OUT of the core dump. Everything else is included,
#: including tables added in future migrations — the default is to back a table
#: up, and excluding one is a decision someone has to make here on purpose.
#:
#: Each of these is rebuildable from the WaaS API or meaningless across a
#: restart, and together they are ~95% of the database by size.
EXCLUDED_FROM_CORE = {
    'security_metric_snapshots',  # hourly capture, 90d retention, ~484k rows
    'app_traffic_snapshots',      # per-app traffic hint cache, 7d retention
    'proxy_sessions',             # live noVNC sessions; dead on restart anyway
}


def log(msg):
    print(f'{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} {msg}', flush=True)


def snapshot(db_path, dest):
    """Copy the live database using the SQLite backup API.

    Safe against a running portal: the backup API takes a read lock per page
    batch and copes with concurrent writers, which a plain file copy does not
    — `cp` of a WAL-mode database mid-write yields a torn file that may only
    fail much later, when someone needs it.
    """
    src = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
    try:
        dst = sqlite3.connect(str(dest))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def verify(path):
    """Integrity-check a snapshot. A backup that is not readable is not a backup."""
    conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
    try:
        result = conn.execute('PRAGMA integrity_check').fetchone()[0]
        if result != 'ok':
            raise RuntimeError(f'integrity_check on {path} returned: {result}')
        return conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
    finally:
        conn.close()


def gzip_file(src, dest):
    with open(src, 'rb') as fh_in, gzip.open(dest, 'wb', compresslevel=6) as fh_out:
        shutil.copyfileobj(fh_in, fh_out, length=1024 * 1024)
    return dest.stat().st_size


def core_dump(snapshot_path, dest):
    """Dump every table except EXCLUDED_FROM_CORE, as gzipped SQL.

    Works on the snapshot, not the live database, so the dump describes exactly
    the same instant as the full backup beside it. Rows are deleted from the
    throwaway snapshot copy rather than filtered during the dump, so
    `iterdump()` still emits correct schema and index statements for the
    excluded tables — a restore gets empty tables of the right shape, and the
    app's own jobs refill them.
    """
    conn = sqlite3.connect(str(snapshot_path))
    try:
        present = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        dropped = {}
        for table in sorted(EXCLUDED_FROM_CORE & present):
            n = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            conn.execute(f'DELETE FROM "{table}"')
            dropped[table] = n
        conn.commit()

        missing = EXCLUDED_FROM_CORE - present
        if missing:
            log(f'  note: excluded tables not in schema (renamed/dropped?): '
                f'{", ".join(sorted(missing))}')

        with gzip.open(dest, 'wt', encoding='utf-8', compresslevel=6) as fh:
            for line in conn.iterdump():
                fh.write(line + '\n')
        return dropped
    finally:
        conn.close()


def prune(directory, pattern, keep):
    """Keep the `keep` newest matching files, delete the rest.

    By count rather than by age on purpose: if cron is down for a week, age
    pruning would delete everything while no new backups were arriving.
    """
    files = sorted(directory.glob(pattern), key=lambda p: p.stat().st_mtime,
                   reverse=True)
    removed = 0
    for stale in files[keep:]:
        stale.unlink()
        removed += 1
    return len(files) - removed, removed


def human(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return f'{n:.1f}{unit}' if unit != 'B' else f'{n}B'
        n /= 1024


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--db', type=Path, default=DB_PATH)
    ap.add_argument('--dest', type=Path, default=BACKUP_ROOT)
    ap.add_argument('--keep-full', type=int, default=KEEP_FULL)
    ap.add_argument('--keep-core', type=int, default=KEEP_CORE)
    ap.add_argument('--dry-run', action='store_true',
                    help='report what would happen; write nothing')
    args = ap.parse_args()

    started = time.monotonic()

    if not args.db.exists():
        log(f'FATAL: database not found at {args.db}')
        return 1

    live_size = args.db.stat().st_size
    log(f'backup starting — source {args.db} ({human(live_size)})')

    if args.dry_run:
        log(f'DRY RUN: would write to {args.dest}/full and {args.dest}/core')
        log(f'DRY RUN: would exclude from core dump: '
            f'{", ".join(sorted(EXCLUDED_FROM_CORE))}')
        log(f'DRY RUN: would keep {args.keep_full} full, {args.keep_core} core')
        return 0

    full_dir = args.dest / 'full'
    core_dir = args.dest / 'core'
    for d in (full_dir, core_dir):
        d.mkdir(parents=True, exist_ok=True)
    # Backups carry Fernet-encrypted WaaS credentials, so these are owner-only.
    # Scoped to this tool's own directories: the parent is shared with other
    # projects' backups and its permissions are not ours to change.
    for d in (args.dest, full_dir, core_dir):
        os.chmod(d, 0o700)

    stamp = datetime.now(timezone.utc).strftime('%Y%m%d')
    full_dest = full_dir / f'waas-portal-v2-{stamp}.db.gz'
    core_dest = core_dir / f'core-{stamp}.sql.gz'

    tmp_dir = Path(tempfile.mkdtemp(prefix='waas-backup-', dir=str(args.dest)))
    tmp_snap = tmp_dir / 'snapshot.db'
    try:
        snapshot(args.db, tmp_snap)
        tables = verify(tmp_snap)
        log(f'  snapshot taken and verified — {tables} tables, '
            f'{human(tmp_snap.stat().st_size)}')

        size = gzip_file(tmp_snap, full_dest)
        log(f'  full  -> {full_dest.name} ({human(size)}, '
            f'{size / live_size:.1%} of source)')

        dropped = core_dump(tmp_snap, core_dest)
        core_size = core_dest.stat().st_size
        excluded = ', '.join(f'{t} ({n:,} rows)' for t, n in sorted(dropped.items()))
        log(f'  core  -> {core_dest.name} ({human(core_size)})')
        log(f'          excluded: {excluded or "nothing"}')
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    kept, removed = prune(full_dir, 'waas-portal-v2-*.db.gz', args.keep_full)
    log(f'  retention: {kept} full kept, {removed} pruned')
    kept, removed = prune(core_dir, 'core-*.sql.gz', args.keep_core)
    log(f'  retention: {kept} core kept, {removed} pruned')

    total = sum(p.stat().st_size for p in args.dest.rglob('*.gz'))
    log(f'backup complete in {time.monotonic() - started:.1f}s — '
        f'{human(total)} on disk at {args.dest}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
