"""Before/after comparison of two collected traffic windows.

The rest of `app.logpull` answers *"what is this traffic doing?"* over one
window. This module answers *"what changed, and was it my change that did
it?"* over two — which is a different question with a different failure mode.

Three rules shape everything here.

**Compare rates, not totals.** Two windows never carry the same amount of
traffic, so an absolute drop in bytes is not evidence of anything on its own.
Every figure is normalised to a per-hour rate and paired with the share of
the window it represents. `report.py` already states this for its own
figures; here it is structural rather than advisory.

**One before/after pair proves nothing by itself.** Web traffic has a
diurnal cycle, a weekly cycle, and crawlers that arrive in episodes. A single
pair cannot tell "my change worked" apart from "it is a quieter hour". So the
plan includes *control days* — the same two windows, same clock times, on
days when nothing was changed — and the observed change is reported against
the spread of what those days did by themselves. That spread is the noise
floor, and a result inside it is not a result.

**Ratios average geometrically.** The control days are combined as a
geometric mean of their after/before ratios, because a day that halved and a
day that doubled cancel to 1.0, not to 1.25.

What this module does *not* do is decide significance. With three control
days there is no honest p-value to compute, so it reports the observed ratio,
the control ratios, and whether the observed one falls outside their range —
and leaves the judgement where it belongs.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone

from app.logpull.crawlers import (
    classify_ua,
    crawler_product,
    looks_like_crawler,
)
from app.logpull.windows import Window, drain
from app.traffic_insights import _int, _rate, _text

#: Segment name for everything that does not declare itself a crawler. Not
#: "human" on its own: an undeclared scraper lands here too, and the label
#: should not claim more than the User-Agent said.
SEGMENT_HUMAN = 'Human / undeclared'

#: Per-segment URL tables are kept for the bandwidth story, so they are
#: trimmed by bytes rather than by hits. A URL fetched constantly but cheaply
#: is a request-count finding, not a bandwidth one, and the request totals
#: stay exact either way.
TOP_URLS = 25
MAX_TRACKED_URLS = 2000

#: Metrics compared for every segment, bandwidth first. The ordering is the
#: deliverable: this feature exists to answer a bytes question, and a reader
#: should meet the bytes before the hit counts.
METRICS = (
    'bytes_per_hour',
    'bytes',
    'byte_share',
    'avg_bytes',
    'requests_per_hour',
    'requests',
    'request_share',
)


# --- window planning -------------------------------------------------------


def parse_duration(text):
    """Seconds from `90s` / `30m` / `2h` / `1d`, or a bare number of seconds."""
    raw = str(text).strip().lower()
    if not raw:
        raise ValueError('empty duration')
    units = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
    if raw[-1] in units:
        value, unit = raw[:-1], units[raw[-1]]
    else:
        value, unit = raw, 1
    try:
        seconds = int(float(value) * unit)
    except ValueError:
        raise ValueError(f'cannot parse duration {text!r}') from None
    if seconds <= 0:
        raise ValueError(f'duration must be positive, got {text!r}')
    return seconds


def plan_comparison(change_at, duration, *, guard=0, control_days=0,
                    now=None, lag=120):
    """Windows for a before/after run around a change at `change_at`.

    `before` ends exactly at the change; `after` starts `guard` seconds later.
    The guard exists because the minutes either side of a config push are a
    transition — caches drain, a deploy finishes — and folding that into
    either side understates the change.

    Control days repeat *both* windows shifted back whole days, so each
    control pair spans the same clock times and the same before/after
    boundary. Shifting by whole days is what preserves the diurnal position;
    anything else reintroduces the bias the controls exist to remove.

    `lag` is a margin against log-ingestion delay: a window whose end is
    nearer than this to `now` may still be filling, and a half-filled "after"
    window is the most flattering possible artefact in a bandwidth
    comparison.
    """
    change_at = int(change_at)
    duration = int(duration)
    guard = int(guard)
    now = int(now if now is not None else datetime.now(timezone.utc).timestamp())

    if duration <= 0:
        raise ValueError('duration must be positive')
    if guard < 0:
        raise ValueError('guard cannot be negative')

    after = Window(change_at + guard, change_at + guard + duration)
    if after.end > now - lag:
        room = max(0, (now - lag) - (change_at + guard))
        raise ValueError(
            f'the "after" window ends at {_iso(after.end)}, which is not yet '
            f'{lag}s in the past. Only {room}s of settled traffic exists since '
            f'the change; use --duration {room // 60}m or less, or wait.'
        )

    before = Window(change_at - duration, change_at)

    controls = []
    for day in range(1, int(control_days) + 1):
        shift = day * 86400
        controls.append({
            'day': day,
            'label': f'control-{day}d',
            'before': Window(before.start - shift, before.end - shift),
            'after': Window(after.start - shift, after.end - shift),
        })

    return {
        'change_at': change_at,
        'duration': duration,
        'guard': guard,
        'before': before,
        'after': after,
        'controls': controls,
    }


def plan_labels(plan):
    """`(label, Window)` for every window in a plan, in collection order."""
    out = [('before', plan['before']), ('after', plan['after'])]
    for control in plan['controls']:
        out.append((f'{control["label"]}-before', control['before']))
        out.append((f'{control["label"]}-after', control['after']))
    return out


# --- collection ------------------------------------------------------------


def collect_window(source, store, label, window, *, force=False, on_page=None):
    """Drain one labelled window to disk, skipping it if already complete.

    `store` is a `PullStore`; its per-day files are keyed by an arbitrary
    string, so a comparison run uses the window's label where a pull would
    use a date. The done-marker then means the same thing it means for a
    pull — this window finished, and a re-run can skip it — which is what
    makes a run resumable after a timeout or a Ctrl-C.
    """
    if store.is_day_done(label) and not force:
        marker = store.read_day_marker(label) or {}
        marker['reused'] = True
        return marker

    writer = store.open_day(label)
    try:
        stats = drain(source, window, writer.write, on_page=on_page)
    finally:
        writer.close()

    marker = {
        'label': label,
        'start': window.start,
        'end': window.end,
        'seconds': window.width,
        'rows': writer.rows,
        'bytes_on_disk': writer.size_bytes(),
        'pages': stats.pages,
        'count_queries': stats.count_queries,
        'truncated': stats.truncated,
        'collected_at': _iso(None),
        'reused': False,
    }
    store.mark_day_done(label, marker)
    return marker


# --- segmentation ----------------------------------------------------------


def crawler_segment(row, verifier=None):
    """`(segment, category, verified)` keyed on the declared User-Agent.

    `verified` is tri-state and the third state carries weight: `None` means
    the operator publishes no address list to check against, which is not the
    same claim as "this IP is not theirs". Nothing here promotes an
    unverifiable crawler to an impostor.
    """
    ua = _text(row.get('UserAgent'))
    known = classify_ua(ua)
    if known is not None:
        _token, label, category, sources = known
        verified = (verifier.verify(sources, _text(row.get('ClientIP')))
                    if verifier is not None else None)
        return label, category, verified
    if looks_like_crawler(ua):
        return f'Other crawler: {crawler_product(ua)}', 'other', None
    return SEGMENT_HUMAN, 'human', None


def field_segment(field, default='(unset)'):
    """Segment on any raw log field — Host, ClientIP_country_code, Method.

    The comparison math does not care what the segments mean, so the same
    machinery that splits crawlers from visitors will split a change by
    hostname or by country with no further work.
    """
    def segment(row, verifier=None):
        return (_text(row.get(field)) or default, None, None)
    return segment


# --- aggregation -----------------------------------------------------------


def _new_segment(category):
    return {
        'category': category,
        'requests': 0,
        'bytes': 0,
        'status': {},
        'status_bytes': {},
        'verified': {'yes': 0, 'no': 0, 'unknown': 0},
        'urls': {},
    }


def _bump(mapping, key, amount=1):
    mapping[key] = mapping.get(key, 0) + amount


class WindowAggregator:
    """Streaming per-segment tally over one window's rows.

    Fed the same way every other aggregator in this package is fed — one row
    at a time, counters only, never the row set — so a window of any size
    costs the same memory.
    """

    def __init__(self, label, window, *, segment=None, focus_url=None,
                 verifier=None, top_urls=TOP_URLS,
                 max_tracked_urls=MAX_TRACKED_URLS):
        self.label = label
        self.window = window
        self.segment = segment or crawler_segment
        self.focus_url = focus_url or None
        self.verifier = verifier
        self.top_urls = top_urls
        self.max_tracked_urls = max_tracked_urls

        self.rows = 0
        self.bytes_total = 0
        self.status = {}
        self._segments = {}
        self._focus = {}
        self._focus_urls = {}
        self.caps = {}

    # --- ingest -----------------------------------------------------------

    def feed(self, row):
        self.rows += 1
        sent = _int(row.get('BytesSent')) or 0
        status = _int(row.get('HTTPStatus'))
        url = _text(row.get('URL'))
        klass = f'{status // 100}xx' if status is not None else 'unknown'

        self.bytes_total += sent
        _bump(self.status, klass)

        name, category, verified = self.segment(row, self.verifier)
        stats = self._segments.get(name)
        if stats is None:
            stats = self._segments[name] = _new_segment(category)

        stats['requests'] += 1
        stats['bytes'] += sent
        _bump(stats['status'], klass)
        _bump(stats['status_bytes'], klass, sent)
        stats['verified'][
            'unknown' if verified is None else ('yes' if verified else 'no')
        ] += 1

        if url:
            self._track_url(stats, url, sent)
            if self.focus_url and self.focus_url in url:
                self._track_focus(name, url, klass, sent)

    def _track_url(self, stats, url, sent):
        urls = stats['urls']
        entry = urls.get(url)
        if entry is None:
            if len(urls) >= self.max_tracked_urls:
                self.caps['segment_urls'] = True
                return
            entry = urls[url] = [0, 0]
        entry[0] += 1
        entry[1] += sent

    def _track_focus(self, name, url, klass, sent):
        entry = self._focus.get(name)
        if entry is None:
            entry = self._focus[name] = {
                'requests': 0, 'bytes': 0, 'status': {}, 'status_bytes': {},
            }
        entry['requests'] += 1
        entry['bytes'] += sent
        _bump(entry['status'], klass)
        _bump(entry['status_bytes'], klass, sent)

        seen = self._focus_urls.get(url)
        if seen is None:
            if len(self._focus_urls) < self.max_tracked_urls:
                self._focus_urls[url] = [0, 0]
                seen = self._focus_urls[url]
            else:
                self.caps['focus_urls'] = True
                return
        seen[0] += 1
        seen[1] += sent

    # --- output -----------------------------------------------------------

    @property
    def hours(self):
        return (self.window.width / 3600.0) if self.window else None

    def _segment_row(self, name, stats):
        top = sorted(stats['urls'].items(), key=lambda kv: kv[1][1],
                     reverse=True)[:self.top_urls]
        return {
            'segment': name,
            'category': stats['category'],
            'requests': stats['requests'],
            'bytes': stats['bytes'],
            'requests_per_hour': _per_hour(stats['requests'], self.hours),
            'bytes_per_hour': _per_hour(stats['bytes'], self.hours),
            'avg_bytes': _rate(stats['bytes'], stats['requests']),
            'request_share': _rate(stats['requests'], self.rows),
            'byte_share': _rate(stats['bytes'], self.bytes_total),
            'status': dict(sorted(stats['status'].items())),
            'status_bytes': dict(sorted(stats['status_bytes'].items())),
            'verified': dict(stats['verified']),
            'top_urls': [{'url': url, 'requests': v[0], 'bytes': v[1]}
                         for url, v in top],
        }

    def result(self):
        segments = {name: self._segment_row(name, stats)
                    for name, stats in self._segments.items()}

        focus = None
        if self.focus_url:
            matched = sorted(self._focus_urls.items(),
                             key=lambda kv: kv[1][1], reverse=True)
            by_segment = {}
            for name, entry in self._focus.items():
                by_segment[name] = {
                    'segment': name,
                    'requests': entry['requests'],
                    'bytes': entry['bytes'],
                    'requests_per_hour': _per_hour(entry['requests'], self.hours),
                    'bytes_per_hour': _per_hour(entry['bytes'], self.hours),
                    'avg_bytes': _rate(entry['bytes'], entry['requests']),
                    'status': dict(sorted(entry['status'].items())),
                    'status_bytes': dict(sorted(entry['status_bytes'].items())),
                }
            focus = {
                'pattern': self.focus_url,
                'requests': sum(e['requests'] for e in self._focus.values()),
                'bytes': sum(e['bytes'] for e in self._focus.values()),
                'matched_urls': [{'url': u, 'requests': v[0], 'bytes': v[1]}
                                 for u, v in matched[:self.top_urls]],
                'by_segment': by_segment,
            }

        return {
            'label': self.label,
            'start': self.window.start if self.window else None,
            'end': self.window.end if self.window else None,
            'seconds': self.window.width if self.window else None,
            'hours': self.hours,
            'rows': self.rows,
            'bytes': self.bytes_total,
            'requests_per_hour': _per_hour(self.rows, self.hours),
            'bytes_per_hour': _per_hour(self.bytes_total, self.hours),
            'avg_bytes': _rate(self.bytes_total, self.rows),
            'status': dict(sorted(self.status.items())),
            'segments': segments,
            'focus': focus,
            'caps': dict(self.caps),
        }


def aggregate_window(store, label, window, **kwargs):
    """Stream one collected window off disk and aggregate it."""
    aggregator = WindowAggregator(label, window, **kwargs)
    for row in store.iter_rows(dates={label}):
        aggregator.feed(row)
    return aggregator.result()


# --- timeline --------------------------------------------------------------


def timeline(store, labels, *, bucket=600, segment=None, focus_url=None,
             highlight=()):
    """Per-bucket counts across one or more collected windows.

    Two aggregated windows can tell you that a number moved. Only a timeline
    tells you that it moved *when the change was made*, which is the
    difference between a correlation and a cause. On a change with a sharp
    edge this is the strongest evidence the log data can produce, and it
    needs no control day at all.

    `highlight` names the segments to track separately in each bucket;
    everything else is folded into `rest`. Buckets with no rows are omitted
    rather than zero-filled — a gap in collection and a genuinely quiet
    bucket are different facts, and inventing zeroes would merge them.
    """
    from app.logpull.analysis import _epoch_ms

    segment = segment or crawler_segment
    highlight = set(highlight)
    bins = {}

    for label in labels:
        for row in store.iter_rows(dates={label}):
            ms = _epoch_ms(row.get('EpochTime'))
            if ms is None:
                continue
            start = (ms // 1000) // bucket * bucket
            entry = bins.get(start)
            if entry is None:
                entry = bins[start] = {
                    'start': start, 'requests': 0, 'bytes': 0,
                    'focus_requests': 0, 'focus_bytes': 0,
                    'groups': {}, 'focus_status': {},
                }

            sent = _int(row.get('BytesSent')) or 0
            entry['requests'] += 1
            entry['bytes'] += sent

            name, _category, _verified = segment(row, None)
            group = name if name in highlight else 'rest'
            stats = entry['groups'].setdefault(
                group, {'requests': 0, 'bytes': 0,
                        'focus_requests': 0, 'focus_bytes': 0})
            stats['requests'] += 1
            stats['bytes'] += sent

            if focus_url and focus_url in _text(row.get('URL')):
                status = _int(row.get('HTTPStatus'))
                entry['focus_requests'] += 1
                entry['focus_bytes'] += sent
                _bump(entry['focus_status'],
                      f'{status // 100}xx' if status is not None else 'unknown')
                stats['focus_requests'] += 1
                stats['focus_bytes'] += sent

    return {
        'bucket': bucket,
        'focus_url': focus_url,
        'highlight': sorted(highlight),
        'bins': [bins[k] for k in sorted(bins)],
    }


# --- comparison math -------------------------------------------------------


def delta(before, after):
    """One metric's before/after with its absolute and relative change.

    `pct` and `ratio` are `None` when the baseline is zero rather than
    infinity or a fabricated 100%: "it went from nothing to something" is a
    real result, and it is not a percentage.
    """
    out = {'before': before, 'after': after, 'abs': None, 'pct': None,
           'ratio': None}
    if before is None or after is None:
        return out
    out['abs'] = after - before
    if before:
        out['ratio'] = after / before
        out['pct'] = (after - before) / before
    return out


def _zero_segment(name, category=None):
    return {
        'segment': name, 'category': category, 'requests': 0, 'bytes': 0,
        'requests_per_hour': 0.0, 'bytes_per_hour': 0.0, 'avg_bytes': None,
        'request_share': 0.0, 'byte_share': 0.0, 'status': {},
        'status_bytes': {}, 'verified': {}, 'top_urls': [],
    }


def compare_windows(before, after, *, metrics=METRICS):
    """Per-segment deltas between two aggregated windows.

    A segment missing from one side is compared against an explicit zero
    rather than dropped — a crawler that stopped entirely is exactly the
    result this is looking for, and silently omitting it would hide it.
    """
    names = set(before['segments']) | set(after['segments'])
    rows = []
    for name in names:
        b = before['segments'].get(name) or _zero_segment(
            name, (after['segments'].get(name) or {}).get('category'))
        a = after['segments'].get(name) or _zero_segment(name, b.get('category'))
        rows.append({
            'segment': name,
            'category': b.get('category') or a.get('category'),
            'before': b,
            'after': a,
            'delta': {m: delta(b.get(m), a.get(m)) for m in metrics},
        })
    rows.sort(key=lambda r: max(r['before']['bytes'], r['after']['bytes']),
              reverse=True)

    totals = {m: delta(before.get(m), after.get(m))
              for m in ('bytes_per_hour', 'bytes', 'requests_per_hour', 'rows',
                        'avg_bytes')}

    return {
        'before': {k: before[k] for k in
                   ('label', 'start', 'end', 'seconds', 'hours', 'rows', 'bytes')},
        'after': {k: after[k] for k in
                  ('label', 'start', 'end', 'seconds', 'hours', 'rows', 'bytes')},
        'totals': totals,
        'segments': rows,
    }


def geometric_mean(values):
    """Geometric mean of positive ratios, or None if there are none.

    Ratios must not be averaged arithmetically: a control day that halved
    (0.5) and one that doubled (2.0) describe equal and opposite movement,
    and should combine to 1.0, not to 1.25. Non-positive values are dropped
    rather than crashing the log — a control day with a zero baseline has no
    ratio to contribute.
    """
    usable = [v for v in values if v is not None and v > 0]
    if not usable:
        return None
    return math.exp(sum(math.log(v) for v in usable) / len(usable))


def attribute_change(treatment, controls):
    """Separate the observed change from what the control days did anyway.

    `treatment` is `(before, after)` for the window pair that straddles the
    change; `controls` is the same pair measured on days when nothing was
    changed. The control days supply the expected after/before ratio, and
    what is left over is the part attributable to the change.

    `outside_control_range` is the honest summary for a handful of control
    days: no significance test is claimed, only whether the observed movement
    is larger than the movement those days produced on their own. With no
    controls, every control field is `None` and the observed change stands
    alone — which the caller should say out loud rather than imply.
    """
    t_before, t_after = treatment
    observed = delta(t_before, t_after)

    pairs = [(b, a) for b, a in controls if b is not None and a is not None]
    ratios = [a / b for b, a in pairs if b]
    expected_ratio = geometric_mean(ratios)

    out = {
        'observed': observed,
        'control_ratios': ratios,
        'control_count': len(pairs),
        'expected_ratio': expected_ratio,
        'control_min_ratio': min(ratios) if ratios else None,
        'control_max_ratio': max(ratios) if ratios else None,
        'expected_after': None,
        'attributable_abs': None,
        'attributable_pct': None,
        'adjusted_ratio': None,
        'outside_control_range': None,
    }

    if expected_ratio is None or t_before is None or t_after is None:
        return out

    out['expected_after'] = t_before * expected_ratio
    out['attributable_abs'] = t_after - out['expected_after']
    if out['expected_after']:
        out['attributable_pct'] = out['attributable_abs'] / out['expected_after']
    if observed['ratio'] is not None:
        out['adjusted_ratio'] = observed['ratio'] / expected_ratio
        out['outside_control_range'] = (
            observed['ratio'] < out['control_min_ratio']
            or observed['ratio'] > out['control_max_ratio']
        )
    return out


def attribute_segment(segment, metric, windows):
    """`attribute_change` for one segment's metric across a planned run.

    `windows` maps label -> aggregated window result, as produced by
    `aggregate_window` over the labels `plan_labels` generated.
    """
    def value(label):
        window = windows.get(label)
        if window is None:
            return None
        row = window['segments'].get(segment)
        if row is None:
            # The segment is absent from a window that was collected, which
            # means zero of it — not missing data.
            return 0.0
        return row.get(metric)

    controls = []
    for label in sorted(windows):
        if label.endswith('-before') and label.startswith('control-'):
            controls.append((value(label), value(label[:-len('-before')] + '-after')))

    return attribute_change((value('before'), value('after')), controls)


# --- small helpers ---------------------------------------------------------


def _per_hour(count, hours):
    if not hours:
        return None
    return count / hours


def _iso(epoch):
    moment = (datetime.now(timezone.utc) if epoch is None
              else datetime.fromtimestamp(epoch, tz=timezone.utc))
    return moment.isoformat()
