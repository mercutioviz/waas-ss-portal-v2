"""Service layer for before/after traffic comparisons.

`app/logpull/compare.py` holds the measurement — window planning, segment
aggregation, the control-day attribution maths — and knows nothing about the
ORM. This module is the half that does: it turns a user's "measure what this
change did" into `TrafficComparison` and `LogPull` rows, decides which windows
can be collected now and which have to wait, and assembles the stored result.

The shape it exists to support is **arm now, report later**. `before` and every
control window are already in the past and immutable the moment a change is
made; only `after` has to wait. So arming collects the immutable half
immediately and defers one window, rather than making the user come back in two
hours and start a job by hand.

Two things here are load-bearing and easy to get wrong:

- **The `after` child row is not created at arming.** `LogPull.STATUS_PENDING`
  counts as active, and the portal runs one pull at a time, so an early row
  would hold that slot for the whole wait and block every other user. The plan
  lives on the parent; `ensure_after_window` creates the child when due.
- **The `after` window's row count is projected, not measured.** A count query
  against a window that has not happened yet returns whatever has accumulated
  so far, which is near zero at arming and would make the progress bar read
  ~100% before the last window even starts. It is estimated from `before`
  instead — same duration, adjacent in time — and flagged as an estimate.
"""
import logging
import uuid
from datetime import datetime, timedelta, timezone

from app import db
from app.logpull.compare import (
    DEFAULT_INGEST_LAG,
    aggregate_window,
    attribute_change,
    attribute_segment,
    compare_windows,
    crawler_segment,
    plan_comparison,
    plan_labels,
    timeline,
)
from app.logpull.preflight import ROWS_PER_SECOND, disk_report, estimate
from app.logpull.store import PullStore
from app.logpull.windows import MODE_FULL
from app.models import LogPull, TrafficComparison

logger = logging.getLogger(__name__)

#: Comparison windows are short and collected in full. Sampling a two-hour
#: window would put extrapolation error on the one figure the whole exercise
#: is measuring, and the saving is minutes.
COMPARISON_MODE = MODE_FULL

#: Duration presets offered by the wizard, and the default.
DURATION_CHOICES = (3600, 7200, 21600, 86400)
DEFAULT_DURATION = 7200
DEFAULT_GUARD = 180
DEFAULT_CONTROL_DAYS = 1
MAX_CONTROL_DAYS = 3

#: Segments attributed when the user names none. Picked from the `before`
#: window by bytes, because the heavy segment is the one worth attributing and
#: it is rarely the one a user would think to type — the production run that
#: motivated this feature found `GoogleOther` carrying five times `Googlebot`.
AUTO_SEGMENT_LIMIT = 3

#: Timeline bucket. Ten minutes resolved the step cleanly on a two-hour window
#: without turning the chart into noise.
TIMELINE_BUCKET = 600


def _now():
    return int(datetime.now(timezone.utc).timestamp())


def plan_for(comparison, *, allow_future=True, now=None):
    """Rebuild the window plan from a stored comparison's fields."""
    return plan_comparison(
        comparison.change_at,
        comparison.duration_seconds,
        guard=comparison.guard_seconds,
        control_days=comparison.control_days,
        now=now,
        allow_future=allow_future,
    )


# --- pre-flight ------------------------------------------------------------


def preflight(source, plan, instance_path, *, now=None):
    """Exact counts per window, and what collecting all of them will cost.

    One count query per window (~0.3 s each). That is what makes the progress
    bar a true fraction later and, more usefully, what lets the user see the
    whole commitment before accepting it — including a control day that
    happens to carry four times the traffic of its neighbours, which is
    exactly the surprise this is here to prevent.
    """
    now = now if now is not None else _now()
    lag = plan.get('lag', DEFAULT_INGEST_LAG)

    windows = []
    before_rows = None
    for label, window in plan_labels(plan):
        settled = window.end <= now - lag
        if settled:
            rows = source.count(window)
            if label == 'before':
                before_rows = rows
        else:
            # Projected from `before`: same duration, adjacent in time. A
            # count against a window still in the future measures nothing.
            rows = before_rows if before_rows is not None else 0
        windows.append({
            'label': label,
            'start': window.start,
            'end': window.end,
            'rows': rows,
            'exact': settled,
            'settled': settled,
        })

    total = sum(w['rows'] for w in windows)
    option = estimate(total, COMPARISON_MODE)
    option['disk'] = disk_report(option['bytes'], instance_path)

    settled_rows = sum(w['rows'] for w in windows if w['settled'])
    return {
        'windows': windows,
        'total_rows': total,
        'windows_total': len(windows),
        'option': option,
        # Split because they happen at different times: the settled part runs
        # as soon as the comparison is armed, the rest after the wait.
        'now_seconds': int(round(settled_rows / ROWS_PER_SECOND)),
        'later_seconds': int(round((total - settled_rows) / ROWS_PER_SECOND)),
        'after_collectable_at': plan['after_collectable_at'],
        'change_at': plan['change_at'],
    }


# --- arming ----------------------------------------------------------------


def arm(user_id, account, *, app_id, app_name, change_at, duration,
        guard=DEFAULT_GUARD, control_days=DEFAULT_CONTROL_DAYS,
        focus_url=None, segments=None, change_note=None, pinned=False,
        counts=None, now=None):
    """Create the comparison and the child pulls for its settled windows.

    `counts` is the `windows` list from `preflight`, so arming does not repeat
    the count queries the wizard already paid for. Without it the children
    start with a zero denominator and the bar simply stays at 0 until the
    first window finishes — degraded, not wrong.
    """
    now = now if now is not None else _now()
    comparison = TrafficComparison(
        user_id=user_id,
        account_id=account.id,
        app_id=app_id,
        app_name=app_name,
        change_at=int(change_at),
        duration_seconds=int(duration),
        guard_seconds=int(guard),
        control_days=int(control_days),
        focus_url=(focus_url or None),
        change_note=(change_note or None),
        pinned=bool(pinned),
        session_id=str(uuid.uuid4()),
        status=TrafficComparison.STATUS_PENDING,
    )
    comparison.segments = segments or []

    plan = plan_for(comparison, now=now)
    labels = plan_labels(plan)
    comparison.windows_total = len(labels)

    by_label = {w['label']: w for w in (counts or [])}
    comparison.rows_expected = sum(w.get('rows') or 0 for w in (counts or []))

    lag = plan.get('lag', DEFAULT_INGEST_LAG)
    comparison.after_due_at = datetime.utcfromtimestamp(
        plan['after_collectable_at'])

    db.session.add(comparison)
    db.session.flush()           # need the id for the children

    for label, window in labels:
        if window.end > now - lag:
            # Not settled yet — `ensure_after_window` creates this one when
            # its time comes, so it does not hold the pull slot meanwhile.
            continue
        db.session.add(_child(comparison, label, window,
                              rows_expected=(by_label.get(label) or {}).get('rows') or 0))

    db.session.commit()
    return comparison


def _child(comparison, label, window, *, rows_expected=0):
    """One window of a comparison, as an ordinary `LogPull`."""
    from app.background_tasks import COMPARISON_RAW_RETENTION_DAYS

    span = window.end - window.start
    return LogPull(
        user_id=comparison.user_id,
        account_id=comparison.account_id,
        app_id=comparison.app_id,
        app_name=comparison.app_name,
        mode=COMPARISON_MODE,
        # Non-null on the row; the UI reads `range_label` off the range.
        window_days=max(1, round(span / 86400)),
        range_start=window.start,
        range_end=window.end,
        session_id=str(uuid.uuid4()),
        rows_expected=rows_expected,
        status=LogPull.STATUS_PENDING,
        phase=LogPull.PHASE_QUEUED,
        comparison_id=comparison.id,
        window_label=label,
        pinned=comparison.pinned,
        raw_expires_at=(None if comparison.pinned else
                        datetime.utcnow() + timedelta(
                            days=COMPARISON_RAW_RETENTION_DAYS)),
    )


def ensure_after_window(comparison, *, now=None):
    """Create the `after` child once its window has settled.

    Returns the child, or None if it is not due yet. Deliberately idempotent:
    the scheduler may see the same comparison on consecutive ticks if a tick
    overlaps a long-running pull.
    """
    now = now if now is not None else _now()
    existing = comparison.window('after')
    if existing is not None:
        return existing

    plan = plan_for(comparison, now=now)
    lag = plan.get('lag', DEFAULT_INGEST_LAG)
    window = plan['after']
    if window.end > now - lag:
        return None

    before = comparison.window('before')
    child = _child(comparison, 'after', window,
                   rows_expected=(before.rows_fetched if before else 0))
    db.session.add(child)
    db.session.commit()
    return child


def pending_windows(comparison):
    """Child pulls still needing collection, in plan order."""
    return [pull for pull in comparison.windows
            if pull.status not in (LogPull.STATUS_COMPLETE,
                                   LogPull.STATUS_CANCELLED)]


# --- analysis --------------------------------------------------------------


def auto_segments(window_result, limit=AUTO_SEGMENT_LIMIT):
    """The heaviest segments by bytes, for attribution.

    Bytes rather than requests: this feature's primary question is bandwidth,
    and the two orderings genuinely differ — a crawler making few very large
    requests outranks one making many small ones, and it is the former that
    moves the bill.
    """
    rows = sorted((window_result.get('segments') or {}).values(),
                  key=lambda s: s.get('bytes') or 0, reverse=True)
    return [row['segment'] for row in rows[:limit]]


def analyze(comparison, instance_path, *, verifier=None, now=None):
    """Aggregate every collected window and assemble the stored result.

    Returns the dict written to `TrafficComparison.result`. It holds measured
    figures only — the rendering decisions live in the template, the same
    split `app/logpull/report.py` keeps.
    """
    plan = plan_for(comparison, now=now)
    segment = crawler_segment

    windows = {}
    for label, window in plan_labels(plan):
        pull = comparison.window(label)
        if pull is None or pull.status != LogPull.STATUS_COMPLETE:
            continue
        store = PullStore(instance_path, pull.id)
        windows[label] = aggregate_window(
            store, label, window,
            # A window collected by `PullRunner` is keyed by calendar date in
            # a store of its own, not by the comparison's label.
            dates=None,
            segment=segment,
            focus_url=comparison.focus_url,
            verifier=verifier,
        )

    if 'before' not in windows or 'after' not in windows:
        raise ValueError('both the before and after windows must be collected')

    segments = comparison.segments or auto_segments(windows['before'])
    comparison.segments = segments

    attribution = {
        name: {metric: attribute_segment(name, metric, windows)
               for metric in ('bytes_per_hour', 'requests_per_hour')}
        for name in segments
    }

    controls = [
        (windows[label]['bytes_per_hour'],
         windows[label[:-len('-before')] + '-after']['bytes_per_hour'])
        for label in windows
        if label.startswith('control-') and label.endswith('-before')
        and (label[:-len('-before')] + '-after') in windows
    ]
    overall = attribute_change(
        (windows['before']['bytes_per_hour'], windows['after']['bytes_per_hour']),
        controls)

    return {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'change_at': comparison.change_at,
        'duration_seconds': comparison.duration_seconds,
        'guard_seconds': comparison.guard_seconds,
        'focus_url': comparison.focus_url,
        'segments': segments,
        'windows': windows,
        'comparison': compare_windows(windows['before'], windows['after']),
        'attribution': attribution,
        'overall': overall,
        'timeline': _timeline(comparison, instance_path, plan, segments, segment),
        'truncated_windows': sum(
            pull.truncated_windows or 0 for pull in comparison.windows),
    }


def verdict(result):
    """The one sentence a reader should leave with, plus how much to trust it.

    Built here rather than in the template because it is a judgement about
    measurements — which segment leads, whether the movement cleared the
    control days — and judgements belong next to the numbers that support
    them. The template renders it; it does not decide it.
    """
    segments = result.get('segments') or []
    attribution = result.get('attribution') or {}
    if not segments or not attribution:
        return None

    primary = segments[0]
    bytes_ = (attribution.get(primary) or {}).get('bytes_per_hour') or {}
    observed = bytes_.get('observed') or {}
    pct = observed.get('pct')
    if pct is None:
        return None

    fell = pct < 0
    controls = bytes_.get('control_count') or 0
    outside = bytes_.get('outside_control_range')

    if not controls:
        confidence = ('No control days were collected, so nothing here '
                      'separates this from ordinary day-to-day variation.')
        tone = 'warning'
    elif outside:
        confidence = (f'That is outside the range of all {controls} control '
                      f'day(s), so it is not the sort of movement this '
                      f'comparison produces on its own.')
        tone = 'good' if fell else 'warning'
    else:
        confidence = (f'That is within the range the {controls} control '
                      f'day(s) moved by themselves, so it is not '
                      f'distinguishable from normal variation.')
        tone = 'neutral'

    return {
        'segment': primary,
        'pct': pct,
        'fell': fell,
        'attributable_abs': bytes_.get('attributable_abs'),
        'attributable_pct': bytes_.get('attributable_pct'),
        'before': observed.get('before'),
        'after': observed.get('after'),
        'control_count': controls,
        'outside_control_range': outside,
        'confidence': confidence,
        'tone': tone,
    }


def limits(comparison, result):
    """Known limits, built from what this run actually hit.

    The same discipline `app/logpull/report.py` uses: a fixed disclaimer
    degrades into something nobody reads, while a list naming this run's
    specific gaps is what makes the rest of the numbers credible.
    """
    out = []
    windows = result.get('windows') or {}
    hours = (windows.get('before') or {}).get('hours') or 0

    out.append(
        f'Figures are per-hour rates measured over {hours:g}-hour windows, '
        f'collected in full — no sampling and no extrapolation.')

    controls = sum(1 for label in windows
                   if label.startswith('control-') and label.endswith('-before'))
    if controls:
        out.append(
            f'Control days are the same two windows, at the same clock times, '
            f'on the previous {controls} day(s). They measure how much this '
            f'comparison moves on its own; a result inside their range is not '
            f'a result.')
    else:
        out.append(
            'No control days were collected. Nothing here separates the change '
            'from the ordinary difference between one part of the day and the '
            'next.')

    if result.get('truncated_windows'):
        out.append(
            f'{result["truncated_windows"]} collection window(s) hit the API\'s '
            f'10,000-row pagination cap. Traffic there is under-represented '
            f'rather than missing, so busy periods are flattened slightly.')

    out.append(
        'Bandwidth is the access log\'s BytesSent summed over matching '
        'requests — what left the edge per request, not the account\'s metered '
        'FUP figure.')

    out.append(
        'Crawler segments come from the declared User-Agent. Where an operator '
        'publishes an address list the claim is checked against it; where none '
        'exists the crawler is reported as unverifiable, never as an impostor.')

    caps = {name for window in windows.values()
            for name, hit in (window.get('caps') or {}).items() if hit}
    if caps:
        out.append(
            f'Per-window URL tables reached their size cap ({", ".join(sorted(caps))}); '
            f'totals stay exact, the URL lists show the heaviest entries only.')

    if comparison.focus_url:
        out.append(
            'The focus URL is matched as a substring, and its before/after is a '
            'direct measurement of the same URL — it needs no control day, '
            'which makes it the strongest claim on this page.')

    return out


def _timeline(comparison, instance_path, plan, segments, segment):
    """Buckets spanning `before` and `after`, read from both stores.

    This is the section that turns "the number moved" into "the number moved
    when the change was made", so it reads the two windows that straddle the
    change and nothing else.
    """
    bins = []
    bucket = TIMELINE_BUCKET
    highlight = list(segments)
    # The two windows are a guard apart and neither starts on a bucket
    # boundary, so every bucket needs the seconds it genuinely covers.
    bounds = [(w.start, w.end) for label, w in plan_labels(plan)
              if label in ('before', 'after')]
    for label in ('before', 'after'):
        pull = comparison.window(label)
        if pull is None or pull.status != LogPull.STATUS_COMPLETE:
            continue
        store = PullStore(instance_path, pull.id)
        part = timeline(store, (label,), bucket=bucket, segment=segment,
                        focus_url=comparison.focus_url, highlight=highlight,
                        dates=None, bounds=bounds)
        bins.extend(part['bins'])
    bins.sort(key=lambda b: b['start'])
    return {
        'bucket': bucket,
        'focus_url': comparison.focus_url,
        'highlight': sorted(highlight),
        'change_at': comparison.change_at,
        'bins': bins,
    }
