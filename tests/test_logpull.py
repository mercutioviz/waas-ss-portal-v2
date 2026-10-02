"""Tests for the log-pull subsystem (app/logpull/, the LogPull row, the
traffic blueprint and the retention sweep).

The things worth testing here are the ones that fail *silently* if they are
wrong: a bisect that loses rows at a window boundary, a checkpoint written
before its data file is closed, a truncated window reported as a total, and
a second pull starting while one is already running. A fake source stands in
for the WaaS API so the drain engine can be exercised exactly.
"""
import calendar
import gzip
import importlib
import json
import os
from datetime import datetime, timedelta

import pytest

from app.background_tasks import (
    LOG_PULL_RAW_RETENTION_DAYS,
    LOG_PULL_RESULT_RETENTION_DAYS,
    reconcile_interrupted_pulls,
    run_log_pull_cleanup,
)
from app.logpull.preflight import (
    FULL_CONFIRM_ROW_THRESHOLD,
    MAX_TOTAL_BYTES,
    disk_report,
    estimate,
    format_duration,
    nominal_sample_rate,
    preflight,
)
from app.logpull.runner import PullRunner
from app.logpull.store import PullStore, corpus_bytes
from app.logpull.windows import (
    MODE_FULL,
    MODE_SAMPLE,
    OFFSET_CAP,
    PAGE_SIZE,
    SAFE_ROWS,
    Cancelled,
    Window,
    day_bounds,
    drain,
    plan_days,
    scale_factor,
)
from app.models import LogPull, User, WaasAccount

# `app.logpull` re-exports the `preflight` *function*, so the module itself
# has to come from sys.modules rather than attribute lookup on the package.
preflight_mod = importlib.import_module('app.logpull.preflight')


def epoch(y, m, d, hh=0, mm=0, ss=0):
    return calendar.timegm((y, m, d, hh, mm, ss, 0, 0, 0))


DAY0 = epoch(2026, 1, 1)
DAY1 = epoch(2026, 1, 2)
DAY2 = epoch(2026, 1, 3)


class FakeSource:
    """Stands in for `LogSource`, with the same half-open `[start, end)`
    semantics the real API was measured to have."""

    def __init__(self, timestamps):
        self.rows = [{'ts': t, 'i': i} for i, t in enumerate(sorted(timestamps))]
        self.counts = 0
        self.page_calls = 0
        self.requests = 0

    def _in(self, window):
        return [r for r in self.rows if window.start <= r['ts'] < window.end]

    def count(self, window):
        self.counts += 1
        self.requests += 1
        return len(self._in(window))

    def page(self, window, page):
        self.page_calls += 1
        self.requests += 1
        rows = self._in(window)
        offset = (page - 1) * PAGE_SIZE
        return rows[offset:offset + PAGE_SIZE]


class TestWindow:
    def test_split_shares_the_midpoint(self):
        """The half-open range makes a shared mid exact. Splitting at
        `mid + 1` instead opens a one-second gap that both halves hide."""
        left, right = Window(100, 200).split()
        assert left == Window(100, 150)
        assert right == Window(150, 200)
        assert left.width + right.width == Window(100, 200).width

    def test_width_is_half_open(self):
        assert Window(10, 11).width == 1
        assert Window(10, 10).width == 0

    def test_day_bounds_is_a_half_open_utc_day(self):
        start, end = day_bounds(DAY0 + 12 * 3600)
        assert (start, end) == (DAY0, DAY1)


class TestDrain:
    def test_fetches_every_row_exactly_once(self):
        """The whole point of the bisect: an over-cap window must yield the
        same row set as an impossible single page would."""
        source = FakeSource(DAY0 + (i * 3600 // 25000) for i in range(25000))
        got = []
        stats = drain(source, Window(DAY0, DAY0 + 3600), got.extend)

        assert stats.rows == 25000
        assert len(got) == 25000
        assert len({r['i'] for r in got}) == 25000
        assert not stats.truncated

    def test_emits_in_chronological_order(self):
        """Left half pops first, so the analysis layer sees time order."""
        source = FakeSource(DAY0 + (i * 3600 // 25000) for i in range(25000))
        got = []
        drain(source, Window(DAY0, DAY0 + 3600), got.extend)
        timestamps = [r['ts'] for r in got]
        assert timestamps == sorted(timestamps)

    def test_does_not_split_a_window_that_fits(self):
        source = FakeSource(DAY0 + i for i in range(500))
        stats = drain(source, Window(DAY0, DAY0 + 3600), lambda rows: None)
        assert stats.leaf_windows == 1
        assert stats.count_queries == 1

    def test_splits_once_above_the_safe_threshold(self):
        source = FakeSource([DAY0] * (SAFE_ROWS + 1) + [DAY0 + 1] * 10)
        got = []
        stats = drain(source, Window(DAY0, DAY0 + 2), got.extend)
        assert stats.leaf_windows == 2
        assert stats.rows == SAFE_ROWS + 11
        assert not stats.truncated

    def test_empty_window_costs_one_count_and_no_pages(self):
        source = FakeSource([])
        stats = drain(source, Window(DAY0, DAY1), lambda rows: None)
        assert stats.rows == 0
        assert source.page_calls == 0
        assert stats.count_queries == 1

    def test_flags_truncation_at_minimum_width(self):
        """A burst of >10k rows inside one second cannot be split further.
        It is drained to the cap and flagged — an incomplete report that
        says so is recoverable; a silent one is not."""
        source = FakeSource([DAY0] * 15000)
        got = []
        stats = drain(source, Window(DAY0, DAY0 + 1), got.extend)

        assert stats.rows == OFFSET_CAP
        assert len(got) == OFFSET_CAP
        assert len(stats.truncated) == 1
        assert stats.truncated[0] == {
            'start': DAY0, 'end': DAY0 + 1,
            'counted': 15000, 'fetched_cap': OFFSET_CAP,
        }

    def test_stops_on_a_short_page_even_if_the_count_disagreed(self):
        """Counts drift while a pull runs; a short page is the real signal."""
        source = FakeSource([DAY0 + i for i in range(1500)])
        original_count = source.count

        def inflated(window):
            original_count(window)
            return 8000

        source.count = inflated
        stats = drain(source, Window(DAY0, DAY0 + 3600), lambda rows: None)
        assert stats.rows == 1500
        assert stats.pages == 2

    def test_cancel_raises_out_of_the_drain(self):
        source = FakeSource(DAY0 + (i * 3600 // 25000) for i in range(25000))
        with pytest.raises(Cancelled):
            drain(source, Window(DAY0, DAY0 + 3600), lambda rows: None,
                  should_cancel=lambda: True)

    def test_on_page_sees_each_page_and_its_window(self):
        source = FakeSource([DAY0 + i for i in range(2500)])
        seen = []
        drain(source, Window(DAY0, DAY0 + 3600), lambda rows: None,
              on_page=lambda n, w: seen.append((n, w)))
        assert [n for n, _w in seen] == [1000, 1000, 500]
        assert all(isinstance(w, Window) for _n, w in seen)


class TestPlanDays:
    def test_full_mode_is_one_window_per_utc_day(self):
        plans = plan_days(DAY0, DAY2, MODE_FULL)
        assert [p.date for p in plans] == ['2026-01-01', '2026-01-02']
        assert plans[0].windows == [Window(DAY0, DAY1)]
        assert plans[1].windows == [Window(DAY1, DAY2)]

    def test_partial_days_are_clipped_at_both_ends(self):
        plans = plan_days(DAY0 + 3600, DAY1 + 7200, MODE_FULL)
        assert plans[0].windows == [Window(DAY0 + 3600, DAY1)]
        assert plans[1].windows == [Window(DAY1, DAY1 + 7200)]

    def test_sample_mode_slices_each_day(self):
        plans = plan_days(DAY0, DAY1, MODE_SAMPLE, sample_window=300, sample_slot=7200)
        assert len(plans) == 1
        windows = plans[0].windows
        assert len(windows) == 12
        assert windows[0] == Window(DAY0, DAY0 + 300)
        assert windows[1] == Window(DAY0 + 7200, DAY0 + 7500)
        assert all(w.width == 300 for w in windows)

    def test_sample_slots_anchor_to_the_day_not_the_range(self):
        """Every day must sample the same wall-clock offsets, or the per-day
        figures stop being comparable — which is also why the scale factor
        is measured rather than taken from the nominal rate."""
        plans = plan_days(DAY0 + 3 * 3600, DAY1, MODE_SAMPLE,
                          sample_window=300, sample_slot=7200)
        starts = [w.start - DAY0 for w in plans[0].windows]
        assert starts[0] == 4 * 3600
        assert all(s % 7200 == 0 for s in starts)

    def test_empty_range_plans_nothing(self):
        assert plan_days(DAY1, DAY0, MODE_FULL) == []
        assert plan_days(DAY0, DAY0, MODE_FULL) == []


class TestScaleFactor:
    def test_measured_ratio(self):
        assert scale_factor(2400, 100) == 24.0

    def test_zero_sample_gives_no_basis_to_extrapolate(self):
        """0.0 rather than a division error or a made-up 24x: callers need
        to be able to tell 'nothing sampled' from 'sampled and scaled'."""
        assert scale_factor(5000, 0) == 0.0
        assert scale_factor(0, 0) == 0.0


class TestPullStore:
    def test_round_trips_rows_through_gzip_jsonl(self, tmp_path):
        store = PullStore(str(tmp_path), 7)
        with store.open_day('2026-01-01') as writer:
            writer.write([{'a': 1}, {'a': 2}])
            writer.write([{'a': 3}])
        assert list(store.iter_rows()) == [{'a': 1}, {'a': 2}, {'a': 3}]

    def test_marker_is_absent_until_the_day_is_marked(self, tmp_path):
        """`mark_day_done` is called only after the writer is closed, so a
        marker's presence genuinely implies a complete day."""
        store = PullStore(str(tmp_path), 7)
        with store.open_day('2026-01-01') as writer:
            writer.write([{'a': 1}])
            assert store.is_day_done('2026-01-01') is False
        assert store.is_day_done('2026-01-01') is False

        store.mark_day_done('2026-01-01', {'sampled_rows': 1})
        assert store.is_day_done('2026-01-01') is True

    def test_resume_state_sums_completed_days_only(self, tmp_path):
        store = PullStore(str(tmp_path), 7)
        store.ensure()
        store.mark_day_done('2026-01-01', {'sampled_rows': 40})
        store.mark_day_done('2026-01-02', {'sampled_rows': 60})
        with store.open_day('2026-01-03') as writer:      # in flight, unmarked
            writer.write([{'a': 1}] * 5)

        state = store.resume_state()
        assert state['days'] == ['2026-01-01', '2026-01-02']
        assert state['rows'] == 100

    def test_open_day_truncates_a_partial_file(self, tmp_path):
        """No marker means whatever is on disk is incomplete, so the day is
        re-pulled rather than appended to."""
        store = PullStore(str(tmp_path), 7)
        with store.open_day('2026-01-01') as writer:
            writer.write([{'a': 1}] * 3)
        with store.open_day('2026-01-01') as writer:
            writer.write([{'b': 1}])
        assert list(store.iter_rows()) == [{'b': 1}]

    def test_iter_rows_skips_one_torn_final_line(self, tmp_path):
        """A pull killed mid-write leaves a half-written last line. Dropping
        it beats failing the whole analysis."""
        store = PullStore(str(tmp_path), 7)
        store.ensure()
        with gzip.open(store.day_path('2026-01-01'), 'wt', encoding='utf-8') as fh:
            fh.write('{"a": 1}\n{"a": 2}\n{"a": ')
        assert list(store.iter_rows()) == [{'a': 1}, {'a': 2}]

    def test_iter_rows_can_be_restricted_to_dates(self, tmp_path):
        store = PullStore(str(tmp_path), 7)
        with store.open_day('2026-01-01') as writer:
            writer.write([{'d': 1}])
        with store.open_day('2026-01-02') as writer:
            writer.write([{'d': 2}])
        assert list(store.iter_rows(dates={'2026-01-02'})) == [{'d': 2}]

    def test_delete_raw_keeps_the_conclusions(self, tmp_path):
        """The retention split only works if reaping the bulk leaves the
        markers and meta behind."""
        store = PullStore(str(tmp_path), 7)
        with store.open_day('2026-01-01') as writer:
            writer.write([{'a': i} for i in range(100)])
        store.mark_day_done('2026-01-01', {'sampled_rows': 100})
        store.write_meta({'pull_id': 7})

        freed = store.delete_raw()
        assert freed > 0
        assert not os.path.exists(store.day_path('2026-01-01'))
        assert store.is_day_done('2026-01-01') is True
        assert store.read_meta() == {'pull_id': 7}
        assert list(store.iter_rows()) == []

    def test_delete_all_removes_the_directory(self, tmp_path):
        store = PullStore(str(tmp_path), 7)
        with store.open_day('2026-01-01') as writer:
            writer.write([{'a': 1}])
        assert store.delete_all() > 0
        assert not os.path.isdir(store.root)
        assert store.size_bytes() == 0
        assert store.delete_all() == 0

    def test_corpus_bytes_spans_every_pull(self, tmp_path):
        assert corpus_bytes(str(tmp_path)) == 0
        for pull_id in (1, 2):
            with PullStore(str(tmp_path), pull_id).open_day('2026-01-01') as writer:
                writer.write([{'a': 1}])
        total = corpus_bytes(str(tmp_path))
        assert total == sum(PullStore(str(tmp_path), i).size_bytes() for i in (1, 2))


class FakeUsage:
    def __init__(self, free, total=500 * 1024 ** 3):
        self.free = free
        self.total = total
        self.used = total - free


@pytest.fixture
def fake_disk(monkeypatch):
    """Pin free space so the disk assertions don't depend on the box."""
    def _set(free_gb):
        monkeypatch.setattr(preflight_mod.shutil, 'disk_usage',
                            lambda path: FakeUsage(int(free_gb * 1024 ** 3)))
    return _set


class TestPreflight:
    def test_nominal_sample_rate(self):
        assert nominal_sample_rate(300, 7200) == pytest.approx(1 / 24)
        assert nominal_sample_rate(300, 0) == 1.0
        assert nominal_sample_rate(7200, 300) == 1.0

    def test_estimate_scales_rows_by_mode(self):
        full = estimate(240_000, MODE_FULL)
        sample = estimate(240_000, MODE_SAMPLE, 300, 7200)
        assert full['rows'] == 240_000
        assert sample['rows'] == 10_000
        assert full['seconds'] > sample['seconds']

    def test_estimate_of_nothing_is_zero_seconds(self):
        assert estimate(0, MODE_FULL)['seconds'] == 0

    def test_small_app_recommends_full(self, tmp_path, fake_disk):
        fake_disk(200)
        report = preflight(FakeSource([DAY0] * 1000), DAY0, DAY1, str(tmp_path))
        assert report['total_rows'] == 1000
        assert report['recommended_mode'] == MODE_FULL
        assert report['full_requires_confirmation'] is False

    def test_large_app_recommends_sample_and_demands_confirmation(self, tmp_path, fake_disk):
        """Above the threshold a full pull is a multi-hour commitment, so
        the UI has to make the user say so rather than accept a click."""
        fake_disk(200)

        class BigSource:
            def count(self, window):
                return FULL_CONFIRM_ROW_THRESHOLD + 1

        report = preflight(BigSource(), DAY0, DAY1, str(tmp_path))
        assert report['recommended_mode'] == MODE_SAMPLE
        assert report['full_requires_confirmation'] is True
        assert report['options'][MODE_SAMPLE]['rows'] < report['options'][MODE_FULL]['rows']

    def test_disk_report_blocks_when_the_reserve_would_be_eaten(self, fake_disk):
        fake_disk(6)
        assert disk_report(4 * 1024 ** 3, '/tmp')['blocked'] is True

    def test_disk_report_allows_a_pull_that_leaves_the_reserve(self, fake_disk):
        fake_disk(200)
        report = disk_report(1 * 1024 ** 3, '/tmp')
        assert report['blocked'] is False
        assert report['ok'] is True

    def test_corpus_cap_is_reported(self, tmp_path, fake_disk):
        fake_disk(200)
        report = preflight(FakeSource([DAY0]), DAY0, DAY1, str(tmp_path),
                           corpus_bytes=MAX_TOTAL_BYTES)
        assert report['corpus_full'] is True

    @pytest.mark.parametrize('seconds,label', [
        (0, '0s'), (45, '45s'), (60, '1m'), (720, '12m'),
        (3600, '1h'), (12000, '3h 20m'), (86400, '1d'), (134400, '1d 13h'),
    ])
    def test_format_duration(self, seconds, label):
        assert format_duration(seconds) == label

    def test_format_duration_tolerates_none(self):
        assert format_duration(None) == '0s'


# --- model --------------------------------------------------------------


@pytest.fixture
def user(app, db):
    u = User(username='lp-tester', email='lp@example.com', role='user', is_active=True)
    u.set_password('x')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def account(app, db, user):
    acc = WaasAccount(user_id=user.id, account_name='Acme WaaS', is_active=True)
    acc.api_key = 'v4-key'
    db.session.add(acc)
    db.session.commit()
    return acc


def make_pull(db, user, account, **kwargs):
    import uuid

    defaults = dict(
        user_id=user.id, account_id=account.id,
        app_id='app-1.example.com', app_name='app-1.example.com',
        mode=MODE_SAMPLE, window_days=7,
        range_start=DAY0, range_end=DAY2,
        sample_window_seconds=300, sample_slot_seconds=7200,
        session_id=str(uuid.uuid4()),
        status=LogPull.STATUS_PENDING, phase=LogPull.PHASE_QUEUED,
    )
    defaults.update(kwargs)
    pull = LogPull(**defaults)
    db.session.add(pull)
    db.session.commit()
    return pull


class TestLogPullModel:
    def test_percent_is_capped_below_100_while_running(self, db, user, account):
        """Live traffic can push the real total past the pre-flight count; a
        bar that reads 100% mid-pull is worse than one that waits."""
        pull = make_pull(db, user, account, status=LogPull.STATUS_RUNNING,
                         rows_expected=1000, rows_fetched=1200)
        assert pull.percent == 99

    def test_percent_is_100_only_when_complete(self, db, user, account):
        pull = make_pull(db, user, account, status=LogPull.STATUS_COMPLETE,
                         rows_expected=0, rows_fetched=0)
        assert pull.percent == 100

    def test_percent_without_a_denominator_is_zero(self, db, user, account):
        pull = make_pull(db, user, account, rows_expected=0, rows_fetched=500)
        assert pull.percent == 0

    def test_is_active_tracks_the_slot(self, db, user, account):
        pull = make_pull(db, user, account, status=LogPull.STATUS_RUNNING)
        assert pull.is_active is True
        pull.status = LogPull.STATUS_INTERRUPTED
        assert pull.is_active is False

    def test_result_round_trips_as_json(self, db, user, account):
        pull = make_pull(db, user, account)
        pull.result = {'scale': 24.87}
        db.session.commit()
        assert pull.result == {'scale': 24.87}

    def test_to_dict_is_json_serializable(self, db, user, account):
        pull = make_pull(db, user, account, status=LogPull.STATUS_RUNNING,
                         rows_expected=100, rows_fetched=50)
        payload = json.loads(json.dumps(pull.to_dict()))
        assert payload['percent'] == 50
        assert payload['status'] == LogPull.STATUS_RUNNING


# --- runner -------------------------------------------------------------


def minute_rows(day_start, days=1):
    return [day_start + d * 86400 + m * 60 for d in range(days) for m in range(1440)]


class TestPullRunner:
    def _runner(self, db, pull, tmp_path, source):
        runner = PullRunner(db, pull, client=None, instance_path=str(tmp_path))
        runner.source = source
        return runner

    def test_sampled_run_checkpoints_each_day_with_a_measured_scale(
            self, db, user, account, tmp_path):
        pull = make_pull(db, user, account, status=LogPull.STATUS_RUNNING,
                         rows_expected=2880)
        source = FakeSource(minute_rows(DAY0, days=2))
        summary = self._runner(db, pull, tmp_path, source).run()

        # 12 slots/day x 5 rows per 300s slot.
        assert summary['rows_sampled'] == 120
        assert summary['rows_total_exact'] == 2880
        assert summary['scale'] == pytest.approx(24.0)
        assert summary['days_collected'] == 2
        assert pull.days_done == 2
        assert [d['date'] for d in summary['per_day']] == ['2026-01-01', '2026-01-02']
        assert all(d['scale'] == pytest.approx(24.0) for d in summary['per_day'])

    def test_full_run_collects_everything(self, db, user, account, tmp_path):
        pull = make_pull(db, user, account, mode=MODE_FULL,
                         status=LogPull.STATUS_RUNNING)
        source = FakeSource(minute_rows(DAY0, days=2))
        summary = self._runner(db, pull, tmp_path, source).run()

        assert summary['rows_sampled'] == 2880
        assert summary['scale'] == pytest.approx(1.0)
        store = PullStore(str(tmp_path), pull.id)
        assert sum(1 for _ in store.iter_rows()) == 2880

    def test_rows_land_on_disk_in_day_files(self, db, user, account, tmp_path):
        pull = make_pull(db, user, account, mode=MODE_FULL,
                         status=LogPull.STATUS_RUNNING)
        self._runner(db, pull, tmp_path, FakeSource(minute_rows(DAY0, days=2))).run()

        store = PullStore(str(tmp_path), pull.id)
        assert store.completed_days() == ['2026-01-01', '2026-01-02']
        assert os.path.exists(store.day_path('2026-01-01'))
        assert store.read_meta()['app_id'] == pull.app_id

    def test_resume_skips_days_already_on_disk(self, db, user, account, tmp_path):
        """A greenlet does not survive `systemctl restart`. Day checkpoints
        are what turn that from 'start over' into 'carry on'."""
        pull = make_pull(db, user, account, mode=MODE_FULL,
                         status=LogPull.STATUS_RUNNING)
        rows = minute_rows(DAY0, days=2)
        self._runner(db, pull, tmp_path, FakeSource(rows)).run()

        second = FakeSource(rows)
        summary = self._runner(db, pull, tmp_path, second).run()
        assert second.page_calls == 0
        assert pull.rows_fetched == 2880
        assert summary['rows_sampled'] == 2880

    def test_resume_refetches_only_the_missing_day(self, db, user, account, tmp_path):
        pull = make_pull(db, user, account, mode=MODE_FULL,
                         status=LogPull.STATUS_RUNNING)
        rows = minute_rows(DAY0, days=2)
        self._runner(db, pull, tmp_path, FakeSource(rows)).run()

        store = PullStore(str(tmp_path), pull.id)
        os.remove(store.done_path('2026-01-02'))
        os.remove(store.day_path('2026-01-02'))

        second = FakeSource(rows)
        self._runner(db, pull, tmp_path, second).run()
        assert sum(1 for _ in store.iter_rows()) == 2880
        assert second.page_calls == 2        # one day, two pages

    def test_cancel_leaves_completed_days_intact(self, db, user, account, tmp_path):
        pull = make_pull(db, user, account, mode=MODE_FULL,
                         status=LogPull.STATUS_RUNNING)
        runner = self._runner(db, pull, tmp_path, FakeSource(minute_rows(DAY0, days=2)))
        runner._cancelled = True

        with pytest.raises(Cancelled):
            runner.run()
        assert PullStore(str(tmp_path), pull.id).completed_days() == []

    def test_truncated_windows_propagate_to_the_summary(self, db, user, account, tmp_path):
        """A >10k burst inside one second is unsplittable. The count for that
        period is a lower bound, and the report has to say so."""
        pull = make_pull(db, user, account, mode=MODE_FULL,
                         status=LogPull.STATUS_RUNNING,
                         range_start=DAY0, range_end=DAY1)
        source = FakeSource([DAY0 + 100] * 15000)
        summary = self._runner(db, pull, tmp_path, source).run()

        assert summary['truncated_windows'] == 1
        assert summary['truncated'][0]['counted'] == 15000
        assert pull.truncated_windows == 1

    def test_emits_progress_payloads(self, db, user, account, tmp_path):
        pull = make_pull(db, user, account, mode=MODE_FULL,
                         status=LogPull.STATUS_RUNNING, rows_expected=2880)
        seen = []
        runner = PullRunner(db, pull, client=None, instance_path=str(tmp_path),
                            emit=seen.append)
        runner.source = FakeSource(minute_rows(DAY0, days=2))
        runner.run()
        assert seen
        assert seen[-1]['days_done'] == 2


# --- retention ----------------------------------------------------------


def reread(db, pull_id):
    """Re-read a pull straight from the database, or None if it is gone.

    The sweep and the admin routes each run in their own app context, which
    under Flask-SQLAlchemy means their own session. Without expiring first,
    assertions would read the test session's cached copies rather than what
    was actually committed.
    """
    db.session.expire_all()
    return db.session.query(LogPull).filter_by(id=pull_id).first()


@pytest.fixture
def isolated_instance(app, tmp_path, monkeypatch):
    """Point the app at a scratch instance dir so the sweep can't touch the
    real one."""
    monkeypatch.setattr(app, 'instance_path', str(tmp_path / 'instance'))
    os.makedirs(app.instance_path, exist_ok=True)
    return app.instance_path


class TestRetentionSweep:
    def test_reaps_raw_rows_but_keeps_the_pull(self, app, db, user, account,
                                               isolated_instance):
        """Raw rows are gigabytes with a short useful life; the aggregates
        are kilobytes and should outlive them. That split is what makes a
        3-day raw window safe."""
        pull = make_pull(db, user, account, status=LogPull.STATUS_COMPLETE,
                         raw_expires_at=datetime.utcnow() - timedelta(hours=1))
        store = PullStore(isolated_instance, pull.id)
        with store.open_day('2026-01-01') as writer:
            writer.write([{'a': i} for i in range(500)])
        store.mark_day_done('2026-01-01', {'sampled_rows': 500})

        assert run_log_pull_cleanup(app) == 1

        refreshed = reread(db, pull.id)
        assert refreshed is not None
        assert refreshed.raw_deleted is True
        assert not os.path.exists(store.day_path('2026-01-01'))
        assert store.is_day_done('2026-01-01') is True

    def test_leaves_raw_alone_before_its_expiry(self, app, db, user, account,
                                                isolated_instance):
        pull = make_pull(db, user, account, status=LogPull.STATUS_COMPLETE,
                         raw_expires_at=datetime.utcnow() + timedelta(days=1))
        store = PullStore(isolated_instance, pull.id)
        with store.open_day('2026-01-01') as writer:
            writer.write([{'a': 1}])

        assert run_log_pull_cleanup(app) == 0
        assert reread(db, pull.id).raw_deleted is False
        assert os.path.exists(store.day_path('2026-01-01'))

    def test_never_reaps_a_running_pull(self, app, db, user, account,
                                        isolated_instance):
        pull = make_pull(db, user, account, status=LogPull.STATUS_RUNNING,
                         raw_expires_at=datetime.utcnow() - timedelta(days=99))
        assert run_log_pull_cleanup(app) == 0
        assert reread(db, pull.id).raw_deleted is False

    def test_deletes_the_whole_pull_past_the_result_window(self, app, db, user,
                                                           account, isolated_instance):
        old = datetime.utcnow() - timedelta(days=LOG_PULL_RESULT_RETENTION_DAYS + 1)
        pull = make_pull(db, user, account, status=LogPull.STATUS_COMPLETE,
                         created_at=old, raw_deleted=True)
        pull_id = pull.id
        store = PullStore(isolated_instance, pull_id)
        store.write_meta({'pull_id': pull_id})

        assert run_log_pull_cleanup(app) == 1
        assert reread(db, pull_id) is None
        assert not os.path.isdir(store.root)

    def test_keeps_a_pull_inside_the_result_window(self, app, db, user, account,
                                                   isolated_instance):
        recent = datetime.utcnow() - timedelta(days=LOG_PULL_RESULT_RETENTION_DAYS - 1)
        pull = make_pull(db, user, account, status=LogPull.STATUS_COMPLETE,
                         created_at=recent, raw_deleted=True)
        assert run_log_pull_cleanup(app) == 0
        assert reread(db, pull.id) is not None

    def test_retention_windows_are_distinct(self):
        assert LOG_PULL_RAW_RETENTION_DAYS < LOG_PULL_RESULT_RETENTION_DAYS


class TestReconcileOnStartup:
    def test_marks_stale_running_pulls_interrupted(self, app, db, user, account):
        """A row still claiming to be running after a restart is lying — the
        greenlet died with the process."""
        running = make_pull(db, user, account, status=LogPull.STATUS_RUNNING)
        pending = make_pull(db, user, account, status=LogPull.STATUS_PENDING)
        done = make_pull(db, user, account, status=LogPull.STATUS_COMPLETE)

        assert reconcile_interrupted_pulls(app) == 2

        assert reread(db, running.id).status == LogPull.STATUS_INTERRUPTED
        assert reread(db, pending.id).status == LogPull.STATUS_INTERRUPTED
        assert reread(db, done.id).status == LogPull.STATUS_COMPLETE
        assert 'resuming' in reread(db, running.id).error_message

    def test_is_a_noop_with_nothing_stale(self, app, db, user, account):
        make_pull(db, user, account, status=LogPull.STATUS_COMPLETE)
        assert reconcile_interrupted_pulls(app) == 0


# --- routes -------------------------------------------------------------


@pytest.fixture
def logged_in_client(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True
    return client


@pytest.fixture
def stub_api(monkeypatch, account, tmp_path):
    """Stub out everything the create path touches beyond the DB."""
    spawned = []
    monkeypatch.setattr('app.routes.traffic.socketio.start_background_task',
                        lambda fn, *a, **kw: spawned.append((fn.__name__, a)))
    monkeypatch.setattr('app.routes.traffic.get_client_for_account',
                        lambda account_id: (object(), account, True))
    monkeypatch.setattr('app.routes.traffic.corpus_bytes', lambda path: 0)
    return spawned


def stub_preflight(monkeypatch, *, rows=1000, blocked=False,
                   requires_confirmation=False, corpus_full=False):
    def _fake(source, start, end, path, **kwargs):
        option = {
            'mode': 'x', 'rows': rows, 'seconds': 10, 'bytes': rows * 61,
            'sample_rate': 1.0,
            'disk': {'blocked': blocked, 'free_bytes': 100 * 1024 ** 3,
                     'ok': not blocked},
        }
        return {
            'total_rows': rows, 'range_start': start, 'range_end': end,
            'options': {MODE_SAMPLE: dict(option), MODE_FULL: dict(option)},
            'recommended_mode': MODE_SAMPLE,
            'full_requires_confirmation': requires_confirmation,
            'corpus_bytes': 0, 'corpus_max_bytes': 1, 'corpus_full': corpus_full,
        }
    monkeypatch.setattr('app.routes.traffic.preflight', _fake)


class TestTrafficRoutes:
    def test_index_lists_only_this_users_pulls(self, logged_in_client, db, user,
                                               account, app):
        other = User(username='someone-else', email='x@example.com', role='user')
        other.set_password('x')
        db.session.add(other)
        db.session.commit()
        mine = make_pull(db, user, account, app_name='mine.example.com')
        make_pull(db, other, account, app_name='theirs.example.com')

        resp = logged_in_client.get('/traffic/')
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert 'mine.example.com' in body
        assert 'theirs.example.com' not in body
        assert mine.user_id == user.id

    def test_another_users_pull_is_not_reachable(self, logged_in_client, db, user,
                                                 account):
        other = User(username='nosy', email='n@example.com', role='user')
        other.set_password('x')
        db.session.add(other)
        db.session.commit()
        theirs = make_pull(db, other, account)

        assert logged_in_client.get(f'/traffic/{theirs.id}/status').status_code == 404
        assert logged_in_client.get(f'/traffic/{theirs.id}/results').status_code == 404

    def test_status_reports_durable_progress(self, logged_in_client, db, user, account):
        pull = make_pull(db, user, account, status=LogPull.STATUS_RUNNING,
                         rows_expected=1000, rows_fetched=250, eta_seconds=3600)
        payload = logged_in_client.get(f'/traffic/{pull.id}/status').get_json()
        assert payload['percent'] == 25
        assert payload['eta_label'] == '1h'
        assert payload['results_url'].endswith('/results')

    def test_only_one_pull_runs_at_a_time(self, logged_in_client, db, user, account,
                                          stub_api, monkeypatch):
        """Two concurrent multi-hour pulls would contend for the single
        gevent worker and finish no sooner."""
        stub_preflight(monkeypatch)
        running = make_pull(db, user, account, status=LogPull.STATUS_RUNNING)

        resp = logged_in_client.post('/traffic/new', data={
            'account_id': account.id, 'app_id': 'app-2.example.com',
            'mode': MODE_SAMPLE, 'window_days': 7,
        })
        assert resp.status_code == 302
        assert f'/traffic/{running.id}/watch' in resp.headers['Location']
        assert LogPull.query.count() == 1
        assert not stub_api

    def test_creates_and_spawns_when_the_slot_is_free(self, logged_in_client, db,
                                                      user, account, stub_api,
                                                      monkeypatch):
        stub_preflight(monkeypatch, rows=5000)
        resp = logged_in_client.post('/traffic/new', data={
            'account_id': account.id, 'app_id': 'app-1.example.com',
            'app_name': 'app-1.example.com', 'mode': MODE_SAMPLE, 'window_days': 7,
        })
        assert resp.status_code == 302

        pull = LogPull.query.one()
        assert pull.mode == MODE_SAMPLE
        assert pull.window_days == 7
        assert pull.rows_expected == 5000
        assert pull.range_end - pull.range_start == 7 * 86400
        assert stub_api[0][0] == 'run_log_pull'

    def test_full_mode_needs_explicit_confirmation(self, logged_in_client, db, user,
                                                   account, stub_api, monkeypatch):
        """A full pull of a busy app is a day and a half. The user has to say
        so out loud rather than click through it."""
        stub_preflight(monkeypatch, rows=5_000_000, requires_confirmation=True)
        resp = logged_in_client.post('/traffic/new', data={
            'account_id': account.id, 'app_id': 'app-1.example.com',
            'mode': MODE_FULL, 'window_days': 30,
        })
        assert resp.status_code == 302
        assert LogPull.query.count() == 0
        assert not stub_api

    def test_full_mode_proceeds_once_confirmed(self, logged_in_client, db, user,
                                               account, stub_api, monkeypatch):
        stub_preflight(monkeypatch, rows=5_000_000, requires_confirmation=True)
        logged_in_client.post('/traffic/new', data={
            'account_id': account.id, 'app_id': 'app-1.example.com',
            'mode': MODE_FULL, 'window_days': 30, 'confirm_full': 'yes',
        })
        pull = LogPull.query.one()
        assert pull.mode == MODE_FULL
        assert pull.window_days == 30
        assert stub_api

    def test_refuses_to_start_without_disk(self, logged_in_client, db, user,
                                           account, stub_api, monkeypatch):
        stub_preflight(monkeypatch, blocked=True)
        logged_in_client.post('/traffic/new', data={
            'account_id': account.id, 'app_id': 'app-1.example.com',
            'mode': MODE_FULL, 'window_days': 7,
        })
        assert LogPull.query.count() == 0
        assert not stub_api

    def test_refuses_to_start_when_the_corpus_is_full(self, logged_in_client, db,
                                                      user, account, stub_api,
                                                      monkeypatch):
        stub_preflight(monkeypatch, corpus_full=True)
        logged_in_client.post('/traffic/new', data={
            'account_id': account.id, 'app_id': 'app-1.example.com',
            'mode': MODE_SAMPLE, 'window_days': 7,
        })
        assert LogPull.query.count() == 0
        assert not stub_api

    def test_window_days_outside_the_allowed_set_falls_back_to_7(
            self, logged_in_client, db, user, account, stub_api, monkeypatch):
        stub_preflight(monkeypatch)
        logged_in_client.post('/traffic/new', data={
            'account_id': account.id, 'app_id': 'app-1.example.com',
            'mode': MODE_SAMPLE, 'window_days': 365,
        })
        assert LogPull.query.one().window_days == 7

    def test_cancel_sets_the_flag_rather_than_killing_the_greenlet(
            self, logged_in_client, db, user, account):
        """Cooperative: the runner checks at window boundaries, so collected
        data survives."""
        pull = make_pull(db, user, account, status=LogPull.STATUS_RUNNING)
        resp = logged_in_client.post(f'/traffic/{pull.id}/cancel')
        assert resp.status_code == 302
        assert db.session.get(LogPull, pull.id).cancel_requested is True
        assert db.session.get(LogPull, pull.id).status == LogPull.STATUS_RUNNING

    def test_cancel_is_a_noop_on_a_finished_pull(self, logged_in_client, db, user,
                                                 account):
        pull = make_pull(db, user, account, status=LogPull.STATUS_COMPLETE)
        logged_in_client.post(f'/traffic/{pull.id}/cancel')
        assert db.session.get(LogPull, pull.id).cancel_requested is False

    def test_resume_restarts_an_interrupted_pull(self, logged_in_client, db, user,
                                                 account, stub_api):
        pull = make_pull(db, user, account, status=LogPull.STATUS_INTERRUPTED,
                         error_message='Interrupted by a portal restart.')
        old_session = pull.session_id

        resp = logged_in_client.post(f'/traffic/{pull.id}/resume')
        assert resp.status_code == 302

        refreshed = db.session.get(LogPull, pull.id)
        assert refreshed.status == LogPull.STATUS_PENDING
        assert refreshed.session_id != old_session
        assert refreshed.error_message is None
        assert stub_api[0][0] == 'run_log_pull'

    def test_resume_refuses_once_the_raw_data_has_expired(self, logged_in_client,
                                                          db, user, account, stub_api):
        pull = make_pull(db, user, account, status=LogPull.STATUS_INTERRUPTED,
                         raw_deleted=True)
        logged_in_client.post(f'/traffic/{pull.id}/resume')
        assert db.session.get(LogPull, pull.id).status == LogPull.STATUS_INTERRUPTED
        assert not stub_api

    def test_resume_refuses_a_completed_pull(self, logged_in_client, db, user,
                                             account, stub_api):
        pull = make_pull(db, user, account, status=LogPull.STATUS_COMPLETE)
        logged_in_client.post(f'/traffic/{pull.id}/resume')
        assert not stub_api

    def test_resume_respects_the_single_slot(self, logged_in_client, db, user,
                                             account, stub_api):
        make_pull(db, user, account, status=LogPull.STATUS_RUNNING)
        stalled = make_pull(db, user, account, status=LogPull.STATUS_INTERRUPTED)
        logged_in_client.post(f'/traffic/{stalled.id}/resume')
        assert db.session.get(LogPull, stalled.id).status == LogPull.STATUS_INTERRUPTED
        assert not stub_api

    def test_watch_redirects_once_complete(self, logged_in_client, db, user, account):
        pull = make_pull(db, user, account, status=LogPull.STATUS_COMPLETE)
        resp = logged_in_client.get(f'/traffic/{pull.id}/watch')
        assert resp.status_code == 302
        assert f'/traffic/{pull.id}/results' in resp.headers['Location']

    def test_results_renders_a_finished_pull(self, logged_in_client, db, user, account):
        pull = make_pull(db, user, account, status=LogPull.STATUS_COMPLETE)
        pull.result = {
            'rows_sampled': 120, 'rows_total_exact': 2880, 'scale': 24.0,
            'truncated_windows': 0,
            'per_day': [{'date': '2026-01-01', 'day_total': 1440,
                         'sampled_rows': 60, 'scale': 24.0, 'windows': 12,
                         'truncated': []}],
        }
        db.session.commit()

        body = logged_in_client.get(f'/traffic/{pull.id}/results').get_data(as_text=True)
        assert '2026-01-01' in body
        assert '24.00' in body

    def test_preflight_requires_an_account_and_app(self, logged_in_client):
        resp = logged_in_client.post('/traffic/preflight', json={})
        assert resp.status_code == 400

    def test_preflight_returns_both_modes(self, logged_in_client, account, stub_api,
                                          monkeypatch):
        stub_preflight(monkeypatch, rows=240_000)
        payload = logged_in_client.post('/traffic/preflight', json={
            'account_id': account.id, 'app_id': 'app-1.example.com',
            'window_days': 30,
        }).get_json()

        assert payload['window_days'] == 30
        assert set(payload['options']) == {MODE_SAMPLE, MODE_FULL}
        assert payload['options'][MODE_FULL]['duration_label'] == '10s'
        assert payload['busy'] is False

    def test_preflight_reports_the_busy_slot(self, logged_in_client, db, user,
                                             account, stub_api, monkeypatch):
        stub_preflight(monkeypatch)
        make_pull(db, user, account, status=LogPull.STATUS_RUNNING)
        payload = logged_in_client.post('/traffic/preflight', json={
            'account_id': account.id, 'app_id': 'app-1.example.com',
        }).get_json()
        assert payload['busy'] is True


class TestAdminStorage:
    @pytest.fixture
    def admin_client(self, client, db):
        admin = User(username='lp-admin', email='a@example.com', role='admin',
                     is_active=True)
        admin.set_password('x')
        db.session.add(admin)
        db.session.commit()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(admin.id)
            sess['_fresh'] = True
        return client

    def test_page_lists_every_pull(self, admin_client, db, user, account,
                                   isolated_instance):
        make_pull(db, user, account, app_name='listed.example.com',
                  status=LogPull.STATUS_COMPLETE)
        body = admin_client.get('/admin/storage').get_data(as_text=True)
        assert 'listed.example.com' in body

    def test_requires_admin(self, logged_in_client):
        resp = logged_in_client.get('/admin/storage')
        assert resp.status_code in (302, 403)

    def test_delete_raw_keeps_the_row(self, admin_client, db, user, account,
                                      isolated_instance):
        pull = make_pull(db, user, account, status=LogPull.STATUS_COMPLETE)
        store = PullStore(isolated_instance, pull.id)
        with store.open_day('2026-01-01') as writer:
            writer.write([{'a': i} for i in range(200)])

        admin_client.post(f'/admin/storage/{pull.id}/delete-raw')
        refreshed = reread(db, pull.id)
        assert refreshed is not None
        assert refreshed.raw_deleted is True
        assert not os.path.exists(store.day_path('2026-01-01'))

    def test_delete_removes_row_and_files(self, admin_client, db, user, account,
                                          isolated_instance):
        pull = make_pull(db, user, account, status=LogPull.STATUS_COMPLETE)
        pull_id = pull.id
        store = PullStore(isolated_instance, pull_id)
        with store.open_day('2026-01-01') as writer:
            writer.write([{'a': 1}])

        admin_client.post(f'/admin/storage/{pull_id}/delete')
        assert reread(db, pull_id) is None
        assert not os.path.isdir(store.root)

    def test_will_not_delete_a_running_pull(self, admin_client, db, user, account,
                                            isolated_instance):
        pull = make_pull(db, user, account, status=LogPull.STATUS_RUNNING)
        admin_client.post(f'/admin/storage/{pull.id}/delete')
        assert reread(db, pull.id) is not None

    def test_reap_runs_the_sweep(self, admin_client, db, user, account,
                                 isolated_instance):
        pull = make_pull(db, user, account, status=LogPull.STATUS_COMPLETE,
                         raw_expires_at=datetime.utcnow() - timedelta(days=1))
        store = PullStore(isolated_instance, pull.id)
        with store.open_day('2026-01-01') as writer:
            writer.write([{'a': 1}])

        admin_client.post('/admin/storage/reap')
        assert reread(db, pull.id).raw_deleted is True
