#!/usr/bin/env python3
"""Import an ad-hoc `traffic_compare.py` run as a portal TrafficComparison.

The CLI writes one gzip file per window, keyed by label, into a single
directory. The portal gives each window its own `LogPull` and its own store,
keyed by calendar date. This copies the former into the latter so a run that
was collected by hand can be opened in the UI.

    venv/bin/python scripts/backfill_comparison.py \\
        --run-id steelpro-media-404 \\
        --account BunzlUSA --app tuportal.steelprocolombia.com \\
        --change-at 2026-10-06T17:17:00Z \\
        --duration 2h --guard 3m --control-days 3 \\
        --focus-url /media/mageplaza/search/default_0_history.js

It exists mainly to check the two paths agree: the UI reading back-filled rows
should print the same figures the CLI printed from the same bytes. A
disagreement there is a real bug in one of them.
"""
import argparse
import gzip
import os
import shutil
import sys
import uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app, db                                  # noqa: E402
from app.logpull.compare import (                               # noqa: E402
    parse_duration,
    plan_comparison,
    plan_labels,
)
from app.logpull.store import PullStore                         # noqa: E402
from app.models import LogPull, TrafficComparison, WaasAccount  # noqa: E402
from app.traffic_comparison import analyze                      # noqa: E402


def parse_instant(text):
    raw = str(text).strip().replace('Z', '+00:00')
    moment = datetime.fromisoformat(raw)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp())


def count_rows(path):
    with gzip.open(path, 'rt', encoding='utf-8') as fh:
        return sum(1 for line in fh if line.strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--account', required=True)
    parser.add_argument('--app', required=True)
    parser.add_argument('--change-at', required=True)
    parser.add_argument('--duration', default='2h')
    parser.add_argument('--guard', default='3m')
    parser.add_argument('--control-days', type=int, default=3)
    parser.add_argument('--focus-url', default=None)
    parser.add_argument('--segment', action='append', default=None)
    parser.add_argument('--user-id', type=int, default=None)
    parser.add_argument('--move', action='store_true',
                        help='move the gzip files instead of copying them')
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        query = WaasAccount.query.filter_by(account_name=args.account)
        if args.user_id is not None:
            query = query.filter_by(user_id=args.user_id)
        matches = query.all()
        if len(matches) != 1:
            parser.error(f'{len(matches)} accounts named {args.account!r}')
        account = matches[0]

        source_root = PullStore(app.instance_path,
                                os.path.join('compare', args.run_id)).root
        if not os.path.isdir(source_root):
            parser.error(f'no collected run at {source_root}')

        change_at = parse_instant(args.change_at)
        duration = parse_duration(args.duration)
        guard = parse_duration(args.guard) if args.guard else 0
        plan = plan_comparison(change_at, duration, guard=guard,
                               control_days=args.control_days,
                               allow_future=True)

        comparison = TrafficComparison(
            user_id=account.user_id, account_id=account.id,
            app_id=args.app, app_name=args.app,
            change_at=change_at, duration_seconds=duration,
            guard_seconds=guard, control_days=args.control_days,
            focus_url=args.focus_url,
            change_note=f'back-filled from scripts/traffic_compare run '
                        f'{args.run_id}',
            session_id=str(uuid.uuid4()),
            status=TrafficComparison.STATUS_ANALYZING,
            # Back-filled rows are the evidence for a run that cannot be
            # re-collected, so they are pinned rather than left to the sweep.
            pinned=True,
            started_at=datetime.utcnow(),
        )
        comparison.segments = args.segment or []
        db.session.add(comparison)
        db.session.flush()

        total = 0
        labels = plan_labels(plan)
        comparison.windows_total = len(labels)

        for label, window in labels:
            src = os.path.join(source_root, f'day-{label}.jsonl.gz')
            if not os.path.exists(src):
                print(f'  {label:<22} missing — skipped')
                continue

            rows = count_rows(src)
            total += rows
            pull = LogPull(
                user_id=account.user_id, account_id=account.id,
                app_id=args.app, app_name=args.app, mode='full',
                window_days=max(1, round(window.width / 86400)),
                range_start=window.start, range_end=window.end,
                session_id=str(uuid.uuid4()),
                rows_expected=rows, rows_fetched=rows,
                status=LogPull.STATUS_COMPLETE, phase=LogPull.PHASE_DONE,
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
                comparison_id=comparison.id, window_label=label,
                pinned=True, raw_expires_at=None,
                days_total=1, days_done=1,
            )
            db.session.add(pull)
            db.session.flush()

            # The portal keys a window's files by calendar date, so the label
            # name does not survive the move.
            store = PullStore(app.instance_path, pull.id)
            store.ensure()
            date = datetime.fromtimestamp(window.start,
                                          tz=timezone.utc).strftime('%Y-%m-%d')
            dest = store.day_path(date)
            (shutil.move if args.move else shutil.copy2)(src, dest)
            store.mark_day_done(date, {
                'date': date, 'day_start': window.start,
                'day_end': window.end, 'day_total': rows,
                'sampled_rows': rows, 'scale': 1.0, 'windows': 1,
                'truncated': [],
                'completed_at': datetime.utcnow().isoformat(),
            })
            pull.result = {
                'mode': 'full', 'range_start': window.start,
                'range_end': window.end, 'days_collected': 1,
                'rows_sampled': rows, 'rows_total_exact': rows, 'scale': 1.0,
                'truncated_windows': 0, 'bytes_on_disk': store.size_bytes(),
            }
            pull.bytes_on_disk = store.size_bytes()
            print(f'  {label:<22} {rows:>9,} rows  → pull #{pull.id}')

        comparison.rows_expected = total
        db.session.commit()

        print('Analysing...')
        from app.logpull.crawlers import RangeVerifier, load_ranges, ranges_cache_dir
        networks, _meta = load_ranges(ranges_cache_dir(app.instance_path))
        comparison.result = analyze(comparison, app.instance_path,
                                    verifier=RangeVerifier(networks))
        comparison.status = TrafficComparison.STATUS_COMPLETE
        comparison.completed_at = datetime.utcnow()
        db.session.commit()

        print(f'Comparison #{comparison.id} ready: '
              f'/traffic/compare/{comparison.id}/results')


if __name__ == '__main__':
    main()
