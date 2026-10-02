"""Pre-flight estimate shown to the user before a pull is committed.

The point of this module is that the sample-vs-full choice should never be
blind. One count query is exact and costs ~0.3s, so the user can be told
what they are signing up for in advance:

    61,394,605 rows — full: ~37 hours, 3.8 GB.  sample: ~1.5 hours, 150 MB.

On a small app a full pull is minutes and should be the default; on a large
one it is a day and a half and needs a deliberate confirmation. Disk is
almost never the binding constraint — wall-clock is.
"""
from __future__ import annotations

import shutil

from app.logpull.windows import (
    DEFAULT_SAMPLE_SLOT,
    DEFAULT_SAMPLE_WINDOW,
    MODE_FULL,
    MODE_SAMPLE,
    Window,
)

# Both measured end-to-end on a 30-day production pull (2,468,301 rows in
# ~90 minutes, 144 MB gzipped), so they already include bisect overhead,
# count queries and retries rather than modelling a best case.
ROWS_PER_SECOND = 457.0
BYTES_PER_ROW = 61

# Above this, a full pull is a multi-hour commitment and the UI must make
# the user confirm explicitly rather than accept a click.
FULL_CONFIRM_ROW_THRESHOLD = 2_000_000

# Keep this much free after the pull, whatever else happens on the box.
DISK_RESERVE_BYTES = 10 * 1024 ** 3
# Refuse outright below this much headroom beyond the estimate.
DISK_HEADROOM_FACTOR = 1.5
# Abort a running pull if free space falls under this.
DISK_ABORT_FLOOR_BYTES = 5 * 1024 ** 3

# Corpus-wide ceiling across all retained pulls.
MAX_TOTAL_BYTES = 40 * 1024 ** 3


def nominal_sample_rate(sample_window=DEFAULT_SAMPLE_WINDOW, sample_slot=DEFAULT_SAMPLE_SLOT):
    """Fraction of wall-clock the sample plan covers.

    Nominal only. The realized rate differs — sampling on even UTC-hour
    boundaries biases the draw — so reports extrapolate with the measured
    per-day factor from `windows.scale_factor`, never with this.
    """
    if sample_slot <= 0:
        return 1.0
    return min(1.0, sample_window / sample_slot)


def estimate(total_rows, mode, sample_window=DEFAULT_SAMPLE_WINDOW,
             sample_slot=DEFAULT_SAMPLE_SLOT):
    """Project rows, seconds and bytes for one mode."""
    rate = 1.0 if mode == MODE_FULL else nominal_sample_rate(sample_window, sample_slot)
    rows = int(round(total_rows * rate))
    return {
        'mode': mode,
        'rows': rows,
        'seconds': int(round(rows / ROWS_PER_SECOND)) if rows else 0,
        'bytes': rows * BYTES_PER_ROW,
        'sample_rate': rate,
    }


def disk_report(estimated_bytes, path):
    """Free space versus what the pull is projected to need.

    `ok` is advisory-with-warning; `blocked` means refuse to start. The two
    are separate because a tight-but-survivable pull is the user's call,
    while one that would fill the filesystem is not.
    """
    usage = shutil.disk_usage(path)
    required = int(estimated_bytes * DISK_HEADROOM_FACTOR)
    remaining_after = usage.free - estimated_bytes
    blocked = remaining_after < DISK_RESERVE_BYTES or usage.free < required
    return {
        'free_bytes': usage.free,
        'total_bytes': usage.total,
        'estimated_bytes': int(estimated_bytes),
        'required_bytes': required,
        'remaining_after_bytes': int(remaining_after),
        'reserve_bytes': DISK_RESERVE_BYTES,
        'blocked': bool(blocked),
        'ok': not blocked,
    }


def preflight(source, start, end, path, sample_window=DEFAULT_SAMPLE_WINDOW,
              sample_slot=DEFAULT_SAMPLE_SLOT, corpus_bytes=0):
    """Exact row count for the range plus a projection for each mode.

    The returned `total_rows` is also what makes an honest progress bar
    possible later: it is the real denominator, so the watch page reports a
    true fraction instead of a guess. That alone is worth the 0.3s.
    """
    total_rows = source.count(Window(int(start), int(end)))

    options = {}
    for mode in (MODE_SAMPLE, MODE_FULL):
        est = estimate(total_rows, mode, sample_window, sample_slot)
        est['disk'] = disk_report(est['bytes'], path)
        options[mode] = est

    full_rows = options[MODE_FULL]['rows']
    corpus_full = corpus_bytes >= MAX_TOTAL_BYTES

    return {
        'total_rows': total_rows,
        'range_start': int(start),
        'range_end': int(end),
        'options': options,
        # Small apps: pull everything, it's quick. Large ones: sample, and
        # make the user say out loud that they want the long version.
        'recommended_mode': MODE_FULL if full_rows <= FULL_CONFIRM_ROW_THRESHOLD else MODE_SAMPLE,
        'full_requires_confirmation': full_rows > FULL_CONFIRM_ROW_THRESHOLD,
        'corpus_bytes': corpus_bytes,
        'corpus_max_bytes': MAX_TOTAL_BYTES,
        'corpus_full': corpus_full,
    }


def format_duration(seconds):
    """Compact human duration: `45s`, `12m`, `3h 20m`, `1d 13h`."""
    seconds = int(seconds or 0)
    if seconds < 60:
        return f'{seconds}s'
    if seconds < 3600:
        return f'{seconds // 60}m'
    if seconds < 86400:
        hours, rem = divmod(seconds, 3600)
        minutes = rem // 60
        return f'{hours}h {minutes}m' if minutes else f'{hours}h'
    days, rem = divmod(seconds, 86400)
    hours = rem // 3600
    return f'{days}d {hours}h' if hours else f'{days}d'
