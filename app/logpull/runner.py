"""Greenlet body for a log pull: plan, drain, checkpoint, report progress.

Three properties this has to hold that a short-lived job would not need:

1. **Resumable.** A multi-hour pull will meet `systemctl restart`. Each UTC
   day is checkpointed, so a restarted pull skips the days already on disk
   instead of starting over. The same mechanism serves cancel.
2. **Non-blocking.** The portal runs a single gevent worker, so this greenlet
   shares an event loop with every HTTP request. It yields explicitly after
   each page; without that, a long pull makes the portal unresponsive for
   everyone.
3. **Honest when it falls short.** Truncated windows, disk aborts and
   cancellation all leave partial data flagged as partial rather than
   presented as complete.
"""
from __future__ import annotations

import logging
import shutil
import time
from datetime import datetime, timedelta

from app.logpull.preflight import DISK_ABORT_FLOOR_BYTES
from app.logpull.source import LogSource
from app.logpull.store import PullStore
from app.logpull.windows import (
    MODE_FULL,
    Cancelled,
    DrainStats,
    Window,
    drain,
    plan_days,
    scale_factor,
)

logger = logging.getLogger(__name__)

# Persist progress at most this often. Writing per page would mean tens of
# thousands of commits over one pull, for a bar that moves imperceptibly.
PROGRESS_INTERVAL_SECONDS = 2.0

# Re-check free space every N pages; the pre-flight estimate can be wrong.
DISK_CHECK_EVERY_PAGES = 200

# Re-read the row to see whether a cancel arrived, at the same cadence.
CANCEL_POLL_SECONDS = 2.0


class DiskAborted(Exception):
    """Free space fell below the floor mid-pull."""


def _yield_to_hub():
    """Give the gevent hub a turn.

    The fetch loop is mostly network I/O, which yields on its own, but
    re-serializing a thousand rows to JSONL between requests is CPU work.
    Without an explicit yield the worker can starve request handling.
    """
    try:
        import gevent
        gevent.sleep(0)
    except ImportError:  # pragma: no cover — gevent absent under plain pytest
        pass


class PullRunner:
    """Drives one `LogPull` row to a terminal state."""

    def __init__(self, db, pull, client, instance_path, emit=None, clock=time.monotonic):
        self.db = db
        self.pull = pull
        self.store = PullStore(instance_path, pull.id)
        self.instance_path = instance_path
        self.emit = emit or (lambda payload: None)
        self.clock = clock

        self.source = LogSource(client, pull.app_id)
        self.started = self.clock()
        self._last_progress = 0.0
        self._last_cancel_poll = 0.0
        self._cancelled = False
        self.stats = DrainStats()

    # --- progress ---------------------------------------------------------

    def _eta(self):
        """Seconds remaining, from observed throughput against the exact
        pre-flight denominator. None until there is enough to extrapolate."""
        done = self.pull.rows_fetched
        expected = self.pull.rows_expected
        if done <= 0 or expected <= 0 or done >= expected:
            return None
        elapsed = self.clock() - self.started
        if elapsed <= 0:
            return None
        return int((expected - done) / (done / elapsed))

    def _persist(self, force=False):
        now = self.clock()
        if not force and (now - self._last_progress) < PROGRESS_INTERVAL_SECONDS:
            return
        self._last_progress = now

        self.pull.bytes_on_disk = self.store.size_bytes()
        self.pull.eta_seconds = self._eta()
        self.pull.truncated_windows = len(self.stats.truncated)
        self.db.session.commit()
        self.emit(self.pull.to_dict())

    # --- cancellation -----------------------------------------------------

    def _should_cancel(self):
        """True once a cancel has been requested.

        Polled from the DB rather than held in memory, because the cancel
        arrives on a different greenlet handling the HTTP request. Rate-
        limited so the drain is not issuing a query per page.
        """
        if self._cancelled:
            return True
        now = self.clock()
        if (now - self._last_cancel_poll) < CANCEL_POLL_SECONDS:
            return False
        self._last_cancel_poll = now
        self.db.session.refresh(self.pull)
        if self.pull.cancel_requested:
            self._cancelled = True
        return self._cancelled

    # --- disk -------------------------------------------------------------

    def _check_disk(self):
        free = shutil.disk_usage(self.instance_path).free
        if free < DISK_ABORT_FLOOR_BYTES:
            raise DiskAborted(
                f'Free disk space fell to {free // 1024 ** 3} GB, below the '
                f'{DISK_ABORT_FLOOR_BYTES // 1024 ** 3} GB floor. '
                'Partial data has been kept.'
            )

    # --- the pull ---------------------------------------------------------

    def run(self):
        pull = self.pull
        self.store.ensure()

        plans = plan_days(
            pull.range_start, pull.range_end, pull.mode,
            pull.sample_window_seconds, pull.sample_slot_seconds,
        )

        resume = self.store.resume_state()
        done_days = set(resume['days'])

        pull.days_total = len(plans)
        pull.days_done = len(done_days)
        pull.rows_fetched = resume['rows']
        pull.phase = pull.PHASE_FETCHING
        self._persist(force=True)

        if done_days:
            logger.info(
                'logpull %s: resuming, %s of %s days already on disk (%s rows)',
                pull.id, len(done_days), len(plans), resume['rows'],
            )

        self.store.write_meta({
            'pull_id': pull.id,
            'app_id': pull.app_id,
            'app_name': pull.app_name,
            'mode': pull.mode,
            'range_start': pull.range_start,
            'range_end': pull.range_end,
            'sample_window_seconds': pull.sample_window_seconds,
            'sample_slot_seconds': pull.sample_slot_seconds,
            'rows_expected': pull.rows_expected,
        })

        for plan in plans:
            if plan.date in done_days:
                continue
            if self._should_cancel():
                raise Cancelled()
            self._drain_day(plan)

        pull.phase = pull.PHASE_ANALYZING
        self._persist(force=True)
        return self.summarize(plans)

    def _drain_day(self, plan):
        """Drain one day's windows into one gzip file, then checkpoint.

        The `.done.json` marker is written only after the data file is
        closed, so its presence implies the day is genuinely complete — a
        half-written day is re-pulled rather than trusted.
        """
        pull = self.pull
        day_stats = DrainStats()
        pages_at_last_disk_check = pull.pages_fetched

        with self.store.open_day(plan.date) as writer:
            def emit_rows(rows):
                writer.write(rows)

            def on_page(count, window):
                nonlocal pages_at_last_disk_check
                pull.rows_fetched += count
                pull.pages_fetched += 1
                pull.current_window_start = window.start
                # Yield before anything that might block, so request
                # handling interleaves with the pull.
                _yield_to_hub()
                if pull.pages_fetched - pages_at_last_disk_check >= DISK_CHECK_EVERY_PAGES:
                    pages_at_last_disk_check = pull.pages_fetched
                    self._check_disk()
                self._persist()

            for window in plan.windows:
                stats = drain(
                    self.source, window, emit_rows,
                    on_page=on_page, should_cancel=self._should_cancel,
                )
                day_stats.merge(stats)

            writer.flush()

        self.stats.merge(day_stats)

        # One extra count query per day, so sampled days can be extrapolated
        # with a measured factor instead of the nominal one.
        day_total = self.source.count(Window(plan.day_start, plan.day_end))

        self.store.mark_day_done(plan.date, {
            'date': plan.date,
            'day_start': plan.day_start,
            'day_end': plan.day_end,
            'day_total': day_total,
            'sampled_rows': day_stats.rows,
            'scale': scale_factor(day_total, day_stats.rows),
            'windows': len(plan.windows),
            'truncated': day_stats.truncated,
            'completed_at': datetime.utcnow().isoformat(),
        })

        pull.days_done += 1
        self._persist(force=True)

    def summarize(self, plans):
        """Collection-level summary stored on the row.

        `scale` is the ratio of the real totals to what was actually pulled,
        measured across the days collected. In full mode it is ~1.0; in
        sample mode it is the number every extrapolated figure in the report
        is multiplied by, which is why it is derived rather than assumed.
        """
        day_totals = 0
        sampled = 0
        per_day = []
        for plan in plans:
            marker = self.store.read_day_marker(plan.date)
            if not marker:
                continue
            day_totals += marker.get('day_total') or 0
            sampled += marker.get('sampled_rows') or 0
            per_day.append(marker)

        return {
            'mode': self.pull.mode,
            'range_start': self.pull.range_start,
            'range_end': self.pull.range_end,
            'days_collected': len(per_day),
            'days_planned': len(plans),
            'rows_sampled': sampled,
            'rows_total_exact': day_totals,
            'scale': scale_factor(day_totals, sampled),
            'nominal_full': self.pull.mode == MODE_FULL,
            'pages_fetched': self.pull.pages_fetched,
            'api_requests': self.source.requests,
            'truncated_windows': len(self.stats.truncated),
            'truncated': self.stats.truncated[:50],
            'bytes_on_disk': self.store.size_bytes(),
            'per_day': per_day,
        }


def retention_cutoff(days):
    return datetime.utcnow() - timedelta(days=days)
