"""Time-window planning and the bisect drain that works around the
logs API's pagination cap.

The API refuses pagination past offset 10,000, so any time window holding
more rows than that cannot be drained by paging alone — it has to be split
in time until each piece fits. That is the whole job of this module.

**The range is half-open: `[from, to)`.** Measured against a 1-hour window of
84,978 rows on a live app:

    [A, B)            = 84,978
    [A, M) + [M, B)   = 84,978   delta  +0   <- shared mid is exact
    [A, M) + [M+1, B) = 84,951   delta -27   <- loses the rows in second M
    [M, M)            = 0                    <- empty, confirming half-open

So bisect splits at a **shared** mid. The intuitive "skip the boundary second
to avoid double-counting" move is backwards: it opens a gap, and the loss is
invisible because both halves still return plausible counts.

Nothing here touches the ORM, the network directly, or gevent. The caller
supplies a `source` and callbacks, which keeps the engine unit-testable
against a fake and lets the greenlet decide when to yield.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Callable, NamedTuple

logger = logging.getLogger(__name__)

# The API caps itemsPerPage at 1000 and refuses offsets past 10,000.
PAGE_SIZE = 1000
OFFSET_CAP = 10000

# Split any window whose count exceeds this. Deliberately below OFFSET_CAP:
# live traffic keeps arriving while the pull runs, so a window that counted
# 9,998 can overflow before it is drained.
SAFE_ROWS = 9000

# `[t, t+1)` is the narrowest non-empty window the half-open range allows.
MIN_WINDOW_SECONDS = 1

# Guard against a pathological bisect; at 1s leaves a 30-day range needs ~22.
MAX_DEPTH = 40

# Access-log rows only. WAF rows (LogType=WF) are a different analysis.
ACCESS_ONLY = {'LogType': [{'condition': 'is', 'value': 'TR'}]}

MODE_SAMPLE = 'sample'
MODE_FULL = 'full'

# Sampling defaults: a 300s slice every 7200s. Nominally 4.17%, but the
# realized rate is always measured per day rather than assumed — see
# `scale_factor`.
DEFAULT_SAMPLE_WINDOW = 300
DEFAULT_SAMPLE_SLOT = 7200


class Window(NamedTuple):
    """A half-open epoch-second range `[start, end)`."""
    start: int
    end: int

    @property
    def width(self) -> int:
        return self.end - self.start

    def split(self) -> tuple['Window', 'Window']:
        """Bisect at a shared midpoint.

        Half-open ranges make this exact: `[s, m)` and `[m, e)` partition
        `[s, e)` with no gap and no overlap.
        """
        mid = (self.start + self.end) // 2
        return Window(self.start, mid), Window(mid, self.end)


class DayPlan(NamedTuple):
    """One UTC day's worth of windows — the checkpoint unit."""
    date: str               # YYYY-MM-DD
    windows: list[Window]
    day_start: int
    day_end: int


class Cancelled(Exception):
    """Raised out of `drain` when the caller's `should_cancel` returns True."""


class DrainStats:
    """Mutable tally accumulated across a drain."""

    def __init__(self) -> None:
        self.rows = 0
        self.pages = 0
        self.count_queries = 0
        self.leaf_windows = 0
        self.truncated: list[dict] = []

    def as_dict(self) -> dict:
        return {
            'rows': self.rows,
            'pages': self.pages,
            'count_queries': self.count_queries,
            'leaf_windows': self.leaf_windows,
            'truncated': self.truncated,
            'truncated_count': len(self.truncated),
        }

    def merge(self, other: 'DrainStats') -> None:
        self.rows += other.rows
        self.pages += other.pages
        self.count_queries += other.count_queries
        self.leaf_windows += other.leaf_windows
        self.truncated.extend(other.truncated)


def day_bounds(epoch: int) -> tuple[int, int]:
    """UTC day containing `epoch`, as a half-open `[start, end)` pair."""
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    start = datetime(dt.year, dt.month, dt.day, tzinfo=timezone.utc)
    return int(start.timestamp()), int((start + timedelta(days=1)).timestamp())


def plan_days(
    start: int,
    end: int,
    mode: str = MODE_SAMPLE,
    sample_window: int = DEFAULT_SAMPLE_WINDOW,
    sample_slot: int = DEFAULT_SAMPLE_SLOT,
) -> list[DayPlan]:
    """Break `[start, end)` into per-UTC-day plans.

    The day is the checkpoint unit for both modes, so an interrupted pull
    resumes at a day boundary rather than restarting.

    FULL mode emits one window per day and lets `drain` bisect it. SAMPLE
    mode emits a `sample_window`-second slice every `sample_slot` seconds.

    Partial days at either end of the range are clipped, which is why the
    realized sample rate has to be measured rather than assumed.
    """
    if end <= start:
        return []

    plans: list[DayPlan] = []
    cursor, _ = day_bounds(start)

    while cursor < end:
        _, next_day = day_bounds(cursor)
        lo, hi = max(cursor, start), min(next_day, end)
        date = datetime.fromtimestamp(lo, tz=timezone.utc).strftime('%Y-%m-%d')

        if mode == MODE_FULL:
            windows = [Window(lo, hi)]
        else:
            windows = []
            # Anchor slots to the UTC day, not to `lo`, so every day in the
            # range samples the same wall-clock offsets and the per-day
            # figures stay comparable.
            slot = cursor
            while slot < hi:
                w_lo, w_hi = max(slot, lo), min(slot + sample_window, hi)
                if w_hi > w_lo:
                    windows.append(Window(w_lo, w_hi))
                slot += sample_slot

        if windows:
            plans.append(DayPlan(date=date, windows=windows, day_start=lo, day_end=hi))
        cursor = next_day

    return plans


def drain(
    source,
    window: Window,
    emit_rows: Callable[[list[dict]], None],
    *,
    on_page: Callable[[int, Window], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
    safe_rows: int = SAFE_ROWS,
    min_width: int = MIN_WINDOW_SECONDS,
) -> DrainStats:
    """Drain every row in `window`, splitting it as needed to stay under the
    pagination cap.

    `source` must provide `count(window) -> int` and
    `page(window, page) -> list[dict]`.

    `emit_rows` receives each fetched page. `on_page` is called after every
    page with `(row_count, window)` — the greenlet uses it to yield to the
    hub and to update progress, which is why this module needs no gevent
    import of its own.

    Windows that still exceed the cap at `min_width` cannot be split further.
    Those are drained as far as the cap allows and recorded in
    `stats.truncated`. Silent truncation is what turns an incomplete report
    into a wrong one, so the flag propagates all the way to the UI.
    """
    stats = DrainStats()
    # (window, depth). LIFO with the right half pushed first, so the left
    # half pops first and rows land in chronological order.
    stack: list[tuple[Window, int]] = [(window, 0)]

    while stack:
        if should_cancel is not None and should_cancel():
            raise Cancelled()

        current, depth = stack.pop()
        if current.width <= 0:
            continue

        total = source.count(current)
        stats.count_queries += 1
        if total <= 0:
            continue

        splittable = current.width > min_width and depth < MAX_DEPTH
        if total > safe_rows and splittable:
            left, right = current.split()
            # A midpoint that doesn't move can't make progress; drain instead
            # of looping forever.
            if left.width > 0 and right.width > 0:
                stack.append((right, depth + 1))
                stack.append((left, depth + 1))
                continue

        stats.leaf_windows += 1

        if total > OFFSET_CAP:
            # Unsplittable and over the cap: a burst of >10k rows inside
            # `min_width` seconds. Take what the cap allows and say so.
            logger.warning(
                'logpull: window [%s, %s) holds %s rows at minimum width; '
                'truncating to %s', current.start, current.end, total, OFFSET_CAP,
            )
            stats.truncated.append({
                'start': current.start,
                'end': current.end,
                'counted': total,
                'fetched_cap': OFFSET_CAP,
            })

        reachable = min(total, OFFSET_CAP)
        page = 1
        fetched = 0
        while fetched < reachable:
            if should_cancel is not None and should_cancel():
                raise Cancelled()

            rows = source.page(current, page)
            stats.pages += 1
            if not rows:
                break

            emit_rows(rows)
            fetched += len(rows)
            stats.rows += len(rows)
            if on_page is not None:
                on_page(len(rows), current)

            # A short page means the result set is exhausted, whatever the
            # count said — counts drift while the pull runs.
            if len(rows) < PAGE_SIZE:
                break
            page += 1

    return stats


def scale_factor(day_total: int, sampled_rows: int) -> float:
    """Extrapolation factor for a sampled day: `day_total / sampled_rows`.

    Always measured, never assumed. A 300s-every-7200s plan is nominally
    4.17% (24x), but sampling on even UTC-hour boundaries biases the draw —
    the realized factor on a 30-day production pull was 24.87x, and using the
    nominal 24 would have understated every extrapolated figure by 3.5%.

    Returns 0.0 when nothing was sampled, so callers can detect "no basis to
    extrapolate" rather than silently scaling by a made-up number.
    """
    if sampled_rows <= 0:
        return 0.0
    return day_total / sampled_rows
