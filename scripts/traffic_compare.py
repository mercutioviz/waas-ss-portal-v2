#!/usr/bin/env python3
"""Measure what a configuration change did to traffic, before vs after.

Collects the access-log window either side of a change — plus the same two
windows on prior days, as a control — and reports the per-segment change in
bandwidth and request volume, with the control days' own movement subtracted.

    venv/bin/python scripts/traffic_compare.py \\
        --account BunzlUSA \\
        --app tuportal.steelprocolombia.com \\
        --change-at 2026-10-06T17:17:00Z \\
        --duration 2h --guard 3m --control-days 3 \\
        --focus-url /media/mageplaza/search/default_0_history.js \\
        --segment Googlebot

Windows are collected in full (no sampling): a before/after comparison over a
couple of hours is small enough that sampling would add extrapolation error
to the one number the whole exercise is trying to measure.

Rows land under `instance/log_pulls/compare/<run-id>/`, one gzipped JSONL file
per window with a done-marker, so re-running skips what is already collected.
Nothing is written to the `log_pulls` table and nothing is applied to the
application — this reads logs and reports.

Re-render a finished run without touching the API:

    venv/bin/python scripts/traffic_compare.py --run-id <id> --no-collect ...
"""
import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app                                    # noqa: E402
from app.logpull.compare import (                             # noqa: E402
    SEGMENT_HUMAN,
    aggregate_window,
    attribute_change,
    attribute_segment,
    collect_window,
    compare_windows,
    crawler_segment,
    field_segment,
    parse_duration,
    plan_comparison,
    plan_labels,
    timeline,
)
from app.logpull.crawlers import RangeVerifier, load_ranges, ranges_cache_dir  # noqa: E402
from app.logpull.source import LogSource                      # noqa: E402
from app.logpull.store import PullStore                       # noqa: E402
from app.models import WaasAccount                            # noqa: E402
from app.waas_client import WaasClient                        # noqa: E402

WIDTH = 78


# --- formatting ------------------------------------------------------------


def fmt_bytes(value):
    if value is None:
        return '—'
    value = float(value)
    sign = '-' if value < 0 else ''
    value = abs(value)
    for limit, unit in ((1e12, 'TB'), (1e9, 'GB'), (1e6, 'MB'), (1e3, 'kB')):
        if value >= limit:
            return f'{sign}{value / limit:.2f} {unit}'
    return f'{sign}{value:,.0f} B'


def fmt_int(value):
    return '—' if value is None else f'{value:,.0f}'


def fmt_pct(value, *, signed=False):
    if value is None:
        return '—'
    return f'{value * 100:+.1f}%' if signed else f'{value * 100:.1f}%'


def fmt_ratio(value):
    return '—' if value is None else f'{value:.3f}'


def fmt_time(epoch):
    if epoch is None:
        return '—'
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime('%m-%d %H:%M')


def rule(char='-'):
    return char * WIDTH


def heading(text):
    return f'\n{text}\n{rule("=") if text.isupper() else rule()}'


def status_mix(counts, limit=4):
    if not counts:
        return '—'
    top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return '  '.join(f'{k} {v:,}' for k, v in top)


# --- plan / collection -----------------------------------------------------


def parse_instant(text):
    """Epoch seconds from an ISO-8601 instant. Naive input is read as UTC."""
    raw = str(text).strip().replace('Z', '+00:00')
    moment = datetime.fromisoformat(raw)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp())


def collect(args, client, store, plan):
    """Collect every planned window, reporting progress to stderr."""
    markers = {}
    for label, window in plan_labels(plan):
        source = LogSource(client, args.app)
        seen = [0]

        def on_page(rows, _window, seen=seen, label=label):
            seen[0] += rows
            print(f'\r  {label:<22} {seen[0]:>9,} rows', end='', file=sys.stderr)

        print(f'  {label:<22} {"...":>9}', end='', file=sys.stderr)
        marker = collect_window(source, store, label, window,
                                force=args.force, on_page=on_page)
        markers[label] = marker
        note = 'cached' if marker.get('reused') else 'collected'
        print(f'\r  {label:<22} {marker.get("rows", 0):>9,} rows  '
              f'{fmt_time(window.start)}→{fmt_time(window.end)}  {note}',
              file=sys.stderr)
    return markers


def build_verifier(instance_path, enabled):
    if not enabled:
        return None, {}
    networks, meta = load_ranges(ranges_cache_dir(instance_path))
    return RangeVerifier(networks), meta


# --- report sections -------------------------------------------------------


def section_windows(windows, markers):
    lines = [heading('WINDOWS'),
             f'  {"label":<22}{"span (UTC)":<20}{"requests":>12}'
             f'{"bytes":>12}{"bytes/hour":>14}']
    for label in order_labels(windows):
        w = windows[label]
        span = f'{fmt_time(w["start"])}→{fmt_time(w["end"])}'
        lines.append(f'  {label:<22}{span:<20}{fmt_int(w["rows"]):>12}'
                     f'{fmt_bytes(w["bytes"]):>12}'
                     f'{fmt_bytes(w["bytes_per_hour"]):>14}')
        truncated = (markers.get(label) or {}).get('truncated') or []
        if truncated:
            lines.append(f'  {"":<22}!! {len(truncated)} window(s) hit the 10k '
                         f'pagination cap — this window is under-counted')
    return lines


def order_labels(windows):
    head = [l for l in ('before', 'after') if l in windows]
    rest = sorted(l for l in windows if l not in head)
    return head + rest


def section_focus(args, windows):
    """The URL the change was aimed at, measured directly.

    This is the strongest evidence available: no control day is needed to
    claim that a specific URL now returns fewer bytes, because the before and
    after are the same URL under the same name.
    """
    before, after = windows['before'], windows['after']
    if not before.get('focus') and not after.get('focus'):
        return []

    lines = [heading(f'FOCUS URL  {args.focus_url}')]

    matched = {m['url'] for w in (before, after)
               for m in ((w.get('focus') or {}).get('matched_urls') or [])}
    if not matched:
        lines.append('  No request matched this pattern in either window.')
        return lines
    for url in sorted(matched):
        lines.append(f'  matched: {url}')

    lines.append('')
    lines.append(f'  {"segment":<26}{"":<8}{"requests/h":>12}{"bytes/h":>12}'
                 f'{"avg/req":>11}  status')
    segments = sorted(
        set((before.get('focus') or {}).get('by_segment', {}))
        | set((after.get('focus') or {}).get('by_segment', {})))
    for name in segments:
        for phase, window in (('before', before), ('after', after)):
            row = ((window.get('focus') or {}).get('by_segment', {}) or {}).get(name)
            row = row or {'requests_per_hour': 0.0, 'bytes_per_hour': 0.0,
                          'avg_bytes': None, 'status': {}}
            label = name if phase == 'before' else ''
            lines.append(
                f'  {label[:25]:<26}{phase:<8}'
                f'{fmt_int(row["requests_per_hour"]):>12}'
                f'{fmt_bytes(row["bytes_per_hour"]):>12}'
                f'{fmt_bytes(row["avg_bytes"]):>11}  '
                f'{status_mix(row["status"])}')
        lines.append('')

    b_total = (before.get('focus') or {}).get('bytes', 0)
    a_total = (after.get('focus') or {}).get('bytes', 0)
    b_rate = b_total / before['hours'] if before['hours'] else 0
    a_rate = a_total / after['hours'] if after['hours'] else 0
    lines.append(f'  Direct change on this URL: {fmt_bytes(b_rate)}/h → '
                 f'{fmt_bytes(a_rate)}/h  '
                 f'({fmt_bytes(a_rate - b_rate)}/h, '
                 f'{fmt_pct((a_rate - b_rate) / b_rate, signed=True) if b_rate else "—"})')
    return lines


def section_timeline(args, data):
    """The change's edge, bucket by bucket.

    A step that lands in the bucket containing the change is evidence no
    control day can supply; a drift spread across the whole span is evidence
    against the change having caused it.
    """
    minutes = data['bucket'] // 60
    focus = ' — focus URL' if data['focus_url'] else ''
    lines = [heading(f'TIMELINE ({minutes}-minute buckets{focus})')]
    groups = data['highlight'] + ['rest']
    header = f'  {"bucket (UTC)":<14}'
    for group in groups:
        header += f'{group[:13] + " req":>18}{"bytes":>11}'
    lines.append(header)

    change_bucket = plan_bucket(args, data['bucket'])
    for entry in data['bins']:
        row = f'  {fmt_time(entry["start"]):<14}'
        for group in groups:
            stats = entry['groups'].get(group) or {}
            key = 'focus_requests' if data['focus_url'] else 'requests'
            byte_key = 'focus_bytes' if data['focus_url'] else 'bytes'
            row += (f'{fmt_int(stats.get(key, 0)):>18}'
                    f'{fmt_bytes(stats.get(byte_key, 0)):>11}')
        if entry['start'] == change_bucket:
            row += '   <== change'
        lines.append(row)
    return lines


def plan_bucket(args, bucket):
    return parse_instant(args.change_at) // bucket * bucket


def section_verification(windows):
    """Whether the crawlers that moved are who they say they are.

    A bandwidth claim about "Googlebot" is worth nothing if the traffic was a
    scraper wearing the name, so when verification ran its result is reported
    next to the figures rather than buried in the JSON.
    """
    rows = []
    for label in ('before', 'after'):
        for name, seg in (windows[label].get('segments') or {}).items():
            counts = seg.get('verified') or {}
            if counts.get('yes') or counts.get('no'):
                rows.append((label, name, counts))
    if not rows:
        return []

    lines = [heading('CRAWLER VERIFICATION — declared UA vs published IP ranges'),
             f'  {"window":<10}{"segment":<26}{"from published range":>22}'
             f'{"not":>8}{"no list":>10}']
    for label, name, counts in rows:
        lines.append(f'  {label:<10}{name[:25]:<26}'
                     f'{fmt_int(counts.get("yes", 0)):>22}'
                     f'{fmt_int(counts.get("no", 0)):>8}'
                     f'{fmt_int(counts.get("unknown", 0)):>10}')
    lines.append('  A crawler with no published list is unverifiable, '
                 'not an impostor.')
    return lines


def section_segments(comparison, limit):
    lines = [heading('SEGMENT COMPARISON — bandwidth first'),
             f'  {"segment":<26}{"bytes/h before":>15}{"bytes/h after":>15}'
             f'{"change":>10}{"req/h chg":>11}']
    for row in comparison['segments'][:limit]:
        d = row['delta']
        lines.append(
            f'  {row["segment"][:25]:<26}'
            f'{fmt_bytes(d["bytes_per_hour"]["before"]):>15}'
            f'{fmt_bytes(d["bytes_per_hour"]["after"]):>15}'
            f'{fmt_pct(d["bytes_per_hour"]["pct"], signed=True):>10}'
            f'{fmt_pct(d["requests_per_hour"]["pct"], signed=True):>11}')
    totals = comparison['totals']
    lines.append('  ' + rule('.')[:WIDTH - 2])
    lines.append(
        f'  {"ALL TRAFFIC":<26}'
        f'{fmt_bytes(totals["bytes_per_hour"]["before"]):>15}'
        f'{fmt_bytes(totals["bytes_per_hour"]["after"]):>15}'
        f'{fmt_pct(totals["bytes_per_hour"]["pct"], signed=True):>10}'
        f'{fmt_pct(totals["requests_per_hour"]["pct"], signed=True):>11}')
    return lines


def render_attribution(title, metric_label, attribution, formatter):
    """One metric's observed change set against what the control days did."""
    obs = attribution['observed']
    lines = [f'  {title} — {metric_label}']
    lines.append(f'      observed        {formatter(obs["before"])} → '
                 f'{formatter(obs["after"])}   '
                 f'({fmt_pct(obs["pct"], signed=True)})')

    if not attribution['control_count']:
        lines.append('      control days    none collected — this change is '
                     'unverified against normal variation')
        return lines

    ratios = '  '.join(fmt_ratio(r) for r in attribution['control_ratios'])
    lines.append(f'      control ratios  {ratios}   '
                 f'(geo-mean {fmt_ratio(attribution["expected_ratio"])})')
    lines.append(f'      expected after  {formatter(attribution["expected_after"])}'
                 f'   if nothing had changed')
    lines.append(f'      attributable    '
                 f'{formatter(attribution["attributable_abs"])}   '
                 f'({fmt_pct(attribution["attributable_pct"], signed=True)} '
                 f'vs expected)')
    verdict = attribution['outside_control_range']
    lines.append(f'      outside the control days\' own range: '
                 f'{"YES" if verdict else "no" if verdict is False else "—"}')
    return lines


def section_attribution(args, windows):
    lines = [heading('ATTRIBUTION — observed change minus what the control '
                     'days did anyway')]
    for segment in args.segment:
        present = any(segment in w['segments'] for w in windows.values())
        if not present:
            lines.append(f'  {segment}: not seen in any window.')
            continue
        lines += render_attribution(
            segment, 'bytes/hour',
            attribute_segment(segment, 'bytes_per_hour', windows), fmt_bytes)
        lines.append('')
        lines += render_attribution(
            segment, 'requests/hour',
            attribute_segment(segment, 'requests_per_hour', windows), fmt_int)
        lines.append('')

    controls = [(windows[l]['bytes_per_hour'],
                 windows[l[:-len('-before')] + '-after']['bytes_per_hour'])
                for l in windows
                if l.startswith('control-') and l.endswith('-before')]
    lines += render_attribution(
        'ALL TRAFFIC', 'bytes/hour',
        attribute_change((windows['before']['bytes_per_hour'],
                          windows['after']['bytes_per_hour']), controls),
        fmt_bytes)
    return lines


def section_safety(args, windows):
    """Did the change hurt anything it was not aimed at?

    A URL that now 404s is only a win if nothing legitimate was asking for
    it. Undeclared clients — real browsers among them — are the population
    that would notice, so their traffic to the focus URL and their overall
    error mix are checked explicitly rather than left to the reader.
    """
    before, after = windows['before'], windows['after']
    lines = [heading('SAFETY CHECK — did anything else move?')]

    if args.focus_url:
        rows = []
        for phase, window in (('before', before), ('after', after)):
            seg = ((window.get('focus') or {}).get('by_segment', {}) or {})
            human = seg.get(SEGMENT_HUMAN)
            rows.append((phase, human))
        if any(r[1] for r in rows):
            lines.append(f'  Undeclared/browser clients requesting the focus URL:')
            for phase, human in rows:
                human = human or {'requests': 0, 'status': {}}
                lines.append(f'    {phase:<8}{fmt_int(human["requests"]):>10} '
                             f'requests   {status_mix(human["status"])}')
            lines.append('    ^ if this is non-zero and now 4xx, real clients '
                         'are being refused.')
        else:
            lines.append('  No undeclared/browser client requested the focus '
                         'URL in either window — the 404 is reaching crawlers '
                         'only.')

    lines.append('')
    for name, window in (('before', before), ('after', after)):
        total = window['rows'] or 1
        mix = {k: v / total for k, v in window['status'].items()}
        lines.append(f'  status mix {name:<7}'
                     + '  '.join(f'{k} {fmt_pct(v)}'
                                 for k, v in sorted(mix.items())))
    return lines


def section_notes(args, plan, windows, ranges_meta):
    lines = [heading('HOW TO READ THIS')]
    lines.append(
        '  * Figures are per-hour rates. The windows are equal length by '
        'construction,\n    but rates stay comparable if one is re-collected '
        'at a different size.')
    lines.append(
        '  * "bytes" is the access log\'s BytesSent summed over matching '
        'requests. It is\n    a per-request measure of what left the edge, '
        'not the account\'s metered\n    FUP figure, so treat it as the shape '
        'of the bandwidth rather than the bill.')
    if plan['controls']:
        lines.append(
            f'  * Control days are the same clock windows on the previous '
            f'{len(plan["controls"])} day(s),\n    when nothing was changed. '
            'They measure how much this comparison moves on\n    its own. A '
            'result inside their range is not a result.')
    else:
        lines.append(
            '  * No control days were collected, so nothing here separates '
            'the change\n    from ordinary day-to-day variation. Re-run with '
            '--control-days 3.')
    lines.append(
        '  * Crawler segments come from the declared User-Agent.'
        + ('' if args.verify else
           ' Addresses were NOT\n    verified against the operators\' '
           'published ranges; re-run with --verify to\n    check that '
           '"Googlebot" is actually Google.'))
    if args.verify and ranges_meta:
        missing = sorted(k for k, m in (ranges_meta or {}).items()
                         if not m.get('available'))
        if missing:
            lines.append(f'  * Published IP ranges unavailable for: '
                         f'{", ".join(missing)} — crawlers relying on those\n'
                         f'    are reported unverifiable, not as impostors.')
    caps = {k for w in windows.values() for k, v in (w.get('caps') or {}).items() if v}
    if caps:
        lines.append(f'  * Per-window URL tables hit their size cap '
                     f'({", ".join(sorted(caps))}); totals are exact, the\n'
                     f'    URL lists show the heaviest entries only.')
    return lines


# --- main ------------------------------------------------------------------


def build_report(args, plan, windows, markers, ranges_meta, timeline_data):
    comparison = compare_windows(windows['before'], windows['after'])
    changed = datetime.fromtimestamp(plan['change_at'], tz=timezone.utc)
    lines = [
        rule('='),
        f'Traffic before/after — {args.app}',
        f'Change at {changed.strftime("%Y-%m-%d %H:%M:%S")} UTC   '
        f'({plan["duration"] // 60}m windows, {plan["guard"] // 60}m guard, '
        f'{len(plan["controls"])} control day(s))',
        rule('='),
    ]
    lines += section_windows(windows, markers)
    lines += section_focus(args, windows) if args.focus_url else []
    lines += section_timeline(args, timeline_data) if timeline_data else []
    lines += section_segments(comparison, args.top_segments)
    lines += section_attribution(args, windows)
    lines += section_verification(windows) if args.verify else []
    lines += section_safety(args, windows)
    lines += section_notes(args, plan, windows, ranges_meta)
    return '\n'.join(lines) + '\n', comparison


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--account', help='WaasAccount.account_name')
    parser.add_argument('--user-id', type=int, default=None,
                        help='disambiguate accounts sharing a name')
    parser.add_argument('--app', help='application name / hostname')
    parser.add_argument('--change-at',
                        help='when the change went in, ISO-8601 (UTC if naive)')
    parser.add_argument('--duration', default='2h',
                        help='length of each window (default 2h)')
    parser.add_argument('--guard', default='3m',
                        help='settle time skipped after the change (default 3m)')
    parser.add_argument('--control-days', type=int, default=3,
                        help='prior days to collect as a control (default 3)')
    parser.add_argument('--lag', type=int, default=120,
                        help='seconds of log-ingestion margin (default 120)')
    parser.add_argument('--focus-url',
                        help='substring of the URL the change targeted')
    parser.add_argument('--segment', action='append', default=None,
                        help='segment to attribute (repeatable; default Googlebot)')
    parser.add_argument('--segment-by', default=None,
                        help='segment on a raw log field (Host, '
                             'ClientIP_country_code, …) instead of crawler UA')
    parser.add_argument('--top-segments', type=int, default=15)
    parser.add_argument('--timeline', default=None,
                        help='bucket the before+after windows at this interval '
                             '(e.g. 10m) to show where the change landed')
    parser.add_argument('--verify', action='store_true',
                        help='check crawler IPs against published ranges')
    parser.add_argument('--run-id', default=None,
                        help='reuse or name a run directory')
    parser.add_argument('--no-collect', action='store_true',
                        help='report over already-collected windows only')
    parser.add_argument('--force', action='store_true',
                        help='re-collect windows that are already complete')
    parser.add_argument('--json', dest='json_path', default=None,
                        help='also write the full result as JSON here')
    args = parser.parse_args()

    if not args.segment:
        args.segment = ['Googlebot']

    app = create_app()
    for name in ('app.waas_client', 'urllib3', 'app.logpull'):
        logging.getLogger(name).setLevel(logging.WARNING)

    with app.app_context():
        run_id = args.run_id

        for required in ('app', 'change_at'):
            if not getattr(args, required):
                parser.error(f'--{required.replace("_", "-")} is required')
        if not args.no_collect and not args.account:
            parser.error('--account is required unless --no-collect is given')

        plan = plan_comparison(
            parse_instant(args.change_at), parse_duration(args.duration),
            guard=parse_duration(args.guard) if args.guard else 0,
            control_days=args.control_days, lag=args.lag)

        if run_id is None:
            stamp = datetime.fromtimestamp(plan['change_at'], tz=timezone.utc)
            run_id = (f'{args.app.replace(".", "-")}-'
                      f'{stamp.strftime("%Y%m%dT%H%M")}')
        store = PullStore(app.instance_path, os.path.join('compare', run_id))
        store_root = store.ensure()

        markers = {}
        if args.no_collect:
            for label, _window in plan_labels(plan):
                markers[label] = store.read_day_marker(label) or {}
        else:
            query = WaasAccount.query.filter_by(account_name=args.account)
            if args.user_id is not None:
                query = query.filter_by(user_id=args.user_id)
            matches = query.all()
            if len(matches) != 1:
                parser.error(f'{len(matches)} accounts named {args.account!r}; '
                             f'use --user-id to disambiguate')
            client = WaasClient.from_account(matches[0])
            print(f'Collecting into {store_root}', file=sys.stderr)
            markers = collect(args, client, store, plan)

        verifier, ranges_meta = build_verifier(app.instance_path, args.verify)
        segment = (field_segment(args.segment_by) if args.segment_by
                   else crawler_segment)

        windows = {}
        for label, window in plan_labels(plan):
            windows[label] = aggregate_window(
                store, label, window, segment=segment,
                focus_url=args.focus_url, verifier=verifier)

        timeline_data = None
        if args.timeline:
            timeline_data = timeline(
                store, ('before', 'after'),
                bucket=parse_duration(args.timeline), segment=segment,
                focus_url=args.focus_url, highlight=args.segment)

        text, comparison = build_report(args, plan, windows, markers,
                                        ranges_meta, timeline_data)
        print(text)

        payload = {
            'app': args.app,
            'plan': {
                'change_at': plan['change_at'],
                'duration': plan['duration'],
                'guard': plan['guard'],
                'windows': {l: {'start': w.start, 'end': w.end}
                            for l, w in plan_labels(plan)},
            },
            'markers': markers,
            'windows': windows,
            'comparison': comparison,
            'timeline': timeline_data,
            'attribution': {
                seg: {m: attribute_segment(seg, m, windows)
                      for m in ('bytes_per_hour', 'requests_per_hour')}
                for seg in args.segment
            },
        }
        out_path = args.json_path or os.path.join(store_root, 'report.json')
        with open(out_path, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh, indent=1, default=str)
        print(f'JSON written to {out_path}', file=sys.stderr)


if __name__ == '__main__':
    main()
