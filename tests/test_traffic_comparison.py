"""Tests for the comparison service, scheduler and routes.

The load-bearing behaviour here is not the arithmetic — `test_traffic_compare`
covers that — but the lifecycle: which windows exist when, what holds the
single collection slot, and what a restart leaves behind. Those are the parts
that fail quietly and only on a real deployment.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app import db as _db
from app.models import LogPull, TrafficComparison, User, WaasAccount
from app.traffic_comparison import (
    DEFAULT_DURATION,
    arm,
    auto_segments,
    ensure_after_window,
    pending_windows,
    plan_for,
    preflight,
    verdict,
)

HOUR = 3600
#: Minute-aligned, and far enough back that `before` and one control day have
#: both settled while `after` has not.
CHANGE_AT = 1_791_300_000


@pytest.fixture
def user(app, db):
    u = User(username='cmp-tester', email='cmp@example.com', role='user',
             is_active=True)
    u.set_password('x')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def account(app, db, user):
    acct = WaasAccount(user_id=user.id, account_name='Acme WaaS', is_active=True)
    acct.api_key = 'v4-key'
    db.session.add(acct)
    db.session.commit()
    return acct


class CountingSource:
    """Stands in for `LogSource`; records which windows were counted."""

    def __init__(self, rows=1000):
        self.rows = rows
        self.counted = []

    def count(self, window):
        self.counted.append((window.start, window.end))
        return self.rows


# --- pre-flight ------------------------------------------------------------


def test_preflight_counts_settled_windows_and_projects_the_future_one(app):
    from app.logpull.compare import plan_comparison

    now = CHANGE_AT + HOUR          # `after` has not elapsed
    plan = plan_comparison(CHANGE_AT, 2 * HOUR, guard=180, control_days=1,
                           now=now, allow_future=True)
    source = CountingSource(rows=500)

    report = preflight(source, plan, app.instance_path, now=now)

    by_label = {w['label']: w for w in report['windows']}
    assert by_label['before']['exact'] is True
    # A count against a window that has not happened measures nothing, so the
    # after window is projected from `before` rather than counted.
    assert by_label['after']['exact'] is False
    assert by_label['after']['rows'] == by_label['before']['rows']
    assert len(source.counted) == 3          # before + two control windows


def test_preflight_splits_the_cost_into_now_and_later(app):
    from app.logpull.compare import plan_comparison

    now = CHANGE_AT + HOUR
    plan = plan_comparison(CHANGE_AT, 2 * HOUR, guard=180, control_days=1,
                           now=now, allow_future=True)
    report = preflight(CountingSource(rows=4570), plan, app.instance_path, now=now)

    assert report['windows_total'] == 4
    assert report['total_rows'] == 4 * 4570
    # Three windows are collectable immediately, one is not.
    assert report['now_seconds'] > 0
    assert report['later_seconds'] > 0
    assert report['now_seconds'] > report['later_seconds']


def test_preflight_has_nothing_to_defer_when_every_window_has_elapsed(app):
    from app.logpull.compare import plan_comparison

    now = CHANGE_AT + 10 * HOUR
    plan = plan_comparison(CHANGE_AT, 2 * HOUR, guard=180, control_days=1,
                           now=now, allow_future=True)
    report = preflight(CountingSource(), plan, app.instance_path, now=now)

    assert all(w['exact'] for w in report['windows'])
    assert report['later_seconds'] == 0


# --- arming ----------------------------------------------------------------


def _arm(user, account, *, now, control_days=1, **kwargs):
    from app.logpull.compare import plan_comparison

    plan = plan_comparison(CHANGE_AT, DEFAULT_DURATION, guard=180,
                           control_days=control_days, now=now, allow_future=True)
    counts = preflight(CountingSource(rows=1000), plan,
                       '/tmp', now=int(now.timestamp()))['windows']
    return arm(user.id, account, app_id='app-1.example.com',
               app_name='app-1.example.com', change_at=CHANGE_AT,
               duration=DEFAULT_DURATION, guard=180, control_days=control_days,
               counts=counts, now=int(now.timestamp()), **kwargs)


def test_arming_does_not_create_the_after_window(app, db, user, account):
    """The single most important invariant in this feature.

    `LogPull.STATUS_PENDING` counts as active and the portal runs one pull at
    a time, so an `after` row created at arming would hold that slot for the
    entire wait and block every other user.
    """
    now = datetime.fromtimestamp(CHANGE_AT + HOUR, tz=timezone.utc)
    comparison = _arm(user, account, now=now)

    labels = {pull.window_label for pull in comparison.windows}
    assert 'after' not in labels
    assert labels == {'before', 'control-1d-before', 'control-1d-after'}
    assert comparison.windows_total == 4      # the plan still knows about it


def test_arming_records_an_exact_denominator_including_the_deferred_window(
        app, db, user, account):
    now = datetime.fromtimestamp(CHANGE_AT + HOUR, tz=timezone.utc)
    comparison = _arm(user, account, now=now)

    # Four windows at 1000 rows each, even though only three rows exist yet —
    # otherwise the bar would read 100% before the last window started.
    assert comparison.rows_expected == 4000
    assert all(pull.rows_expected == 1000 for pull in comparison.windows)


def test_arming_sets_when_the_after_window_becomes_collectable(app, db, user,
                                                               account):
    now = datetime.fromtimestamp(CHANGE_AT + HOUR, tz=timezone.utc)
    comparison = _arm(user, account, now=now)

    plan = plan_for(comparison, now=int(now.timestamp()))
    assert comparison.after_due_at == datetime.utcfromtimestamp(
        plan['after_collectable_at'])
    assert comparison.after_due_at > datetime.utcfromtimestamp(plan['after'].end)


def test_arming_a_past_change_collects_every_window_at_once(app, db, user,
                                                            account):
    now = datetime.fromtimestamp(CHANGE_AT + 10 * HOUR, tz=timezone.utc)
    comparison = _arm(user, account, now=now)

    labels = {pull.window_label for pull in comparison.windows}
    assert 'after' in labels
    assert len(labels) == 4


def test_windows_inherit_full_mode_and_the_comparison_retention(app, db, user,
                                                                account):
    from app.background_tasks import COMPARISON_RAW_RETENTION_DAYS

    now = datetime.fromtimestamp(CHANGE_AT + 10 * HOUR, tz=timezone.utc)
    comparison = _arm(user, account, now=now)

    for pull in comparison.windows:
        # Sampling a two-hour window would put extrapolation error on the one
        # figure the whole exercise is measuring.
        assert pull.mode == 'full'
        assert pull.comparison_id == comparison.id
        assert pull.raw_expires_at > (datetime.utcnow() + timedelta(
            days=COMPARISON_RAW_RETENTION_DAYS - 1))


def test_pinned_windows_never_expire(app, db, user, account):
    now = datetime.fromtimestamp(CHANGE_AT + 10 * HOUR, tz=timezone.utc)
    comparison = _arm(user, account, now=now, pinned=True)

    assert all(pull.pinned for pull in comparison.windows)
    assert all(pull.raw_expires_at is None for pull in comparison.windows)


# --- deferred window -------------------------------------------------------


def test_ensure_after_window_refuses_before_the_window_has_settled(app, db,
                                                                   user, account):
    now = CHANGE_AT + HOUR
    comparison = _arm(user, account,
                      now=datetime.fromtimestamp(now, tz=timezone.utc))
    assert ensure_after_window(comparison, now=now) is None
    assert comparison.window('after') is None


def test_ensure_after_window_creates_it_once_settled(app, db, user, account):
    comparison = _arm(user, account,
                      now=datetime.fromtimestamp(CHANGE_AT + HOUR, tz=timezone.utc))
    child = ensure_after_window(comparison, now=CHANGE_AT + 10 * HOUR)

    assert child is not None
    assert child.window_label == 'after'
    assert child.comparison_id == comparison.id
    # Projected from `before`, which has an exact count.
    assert child.rows_expected == (comparison.window('before').rows_fetched or 0)


def test_ensure_after_window_is_idempotent(app, db, user, account):
    comparison = _arm(user, account,
                      now=datetime.fromtimestamp(CHANGE_AT + HOUR, tz=timezone.utc))
    first = ensure_after_window(comparison, now=CHANGE_AT + 10 * HOUR)
    _db.session.refresh(comparison)
    second = ensure_after_window(comparison, now=CHANGE_AT + 10 * HOUR)

    assert first.id == second.id
    assert len([p for p in comparison.windows if p.window_label == 'after']) == 1


def test_pending_windows_skips_finished_ones(app, db, user, account):
    comparison = _arm(user, account,
                      now=datetime.fromtimestamp(CHANGE_AT + 10 * HOUR,
                                                 tz=timezone.utc))
    comparison.windows[0].status = LogPull.STATUS_COMPLETE
    _db.session.commit()

    assert len(pending_windows(comparison)) == len(comparison.windows) - 1


# --- parent progress -------------------------------------------------------


def test_eta_ignores_time_spent_waiting(app, db, user, account):
    """A comparison can sit in `waiting` for hours between windows.

    Measuring throughput against the parent's wall-clock would make the
    estimate grow the longer the portal waits, which is backwards.
    """
    comparison = _arm(user, account,
                      now=datetime.fromtimestamp(CHANGE_AT + 10 * HOUR,
                                                 tz=timezone.utc))
    comparison.status = TrafficComparison.STATUS_COLLECTING
    comparison.started_at = datetime.utcnow() - timedelta(hours=5)

    pull = comparison.windows[0]
    pull.started_at = datetime.utcnow() - timedelta(seconds=10)
    pull.completed_at = datetime.utcnow()
    pull.rows_fetched = 1000
    pull.status = LogPull.STATUS_COMPLETE
    _db.session.commit()

    # 100 rows/s observed over 10s of real collection, not over 5 hours.
    assert comparison.observed_rate == pytest.approx(100.0, rel=0.2)
    assert comparison.eta_seconds == pytest.approx(30, abs=5)


def test_eta_is_withheld_while_waiting(app, db, user, account):
    comparison = _arm(user, account,
                      now=datetime.fromtimestamp(CHANGE_AT + HOUR,
                                                 tz=timezone.utc))
    comparison.status = TrafficComparison.STATUS_WAITING
    comparison.after_due_at = datetime.utcnow() + timedelta(minutes=90)
    pull = comparison.windows[0]
    pull.started_at = datetime.utcnow() - timedelta(seconds=10)
    pull.completed_at = datetime.utcnow()
    pull.rows_fetched = 1000
    _db.session.commit()

    # Reporting a two-minute collection estimate beside a 90-minute wait is
    # worse than reporting nothing.
    assert comparison.eta_seconds is None
    assert comparison.waiting_seconds == pytest.approx(5400, abs=60)


def test_percent_uses_the_exact_denominator_and_is_capped_while_running(
        app, db, user, account):
    comparison = _arm(user, account,
                      now=datetime.fromtimestamp(CHANGE_AT + 10 * HOUR,
                                                 tz=timezone.utc))
    for pull in comparison.windows:
        pull.rows_fetched = 1000
    _db.session.commit()

    assert comparison.rows_fetched == 4000
    assert comparison.percent == 99          # capped until status is complete
    comparison.status = TrafficComparison.STATUS_COMPLETE
    assert comparison.percent == 100


def test_waiting_does_not_count_as_busy(app, db, user, account):
    """A comparison parked on wall-clock holds no collection slot."""
    assert TrafficComparison.STATUS_WAITING not in TrafficComparison.BUSY_STATUSES


# --- scheduler -------------------------------------------------------------


def test_due_check_skips_a_comparison_whose_window_has_not_elapsed(app, db,
                                                                   user, account):
    from app.background_tasks import run_due_comparisons

    comparison = _arm(user, account,
                      now=datetime.fromtimestamp(CHANGE_AT + HOUR,
                                                 tz=timezone.utc))
    comparison.status = TrafficComparison.STATUS_WAITING
    comparison.after_due_at = datetime.utcnow() + timedelta(hours=2)
    _db.session.commit()

    assert run_due_comparisons(app) == 0


def test_due_check_defers_while_a_pull_holds_the_slot(app, db, user, account):
    from app.background_tasks import run_due_comparisons

    comparison = _arm(user, account,
                      now=datetime.fromtimestamp(CHANGE_AT + HOUR,
                                                 tz=timezone.utc))
    comparison.status = TrafficComparison.STATUS_WAITING
    comparison.after_due_at = datetime.utcnow() - timedelta(minutes=1)
    comparison.windows[0].status = LogPull.STATUS_RUNNING
    _db.session.commit()

    # Arriving a tick late costs nothing: the window is a fixed range in the
    # past, so the rows do not move while it waits.
    assert run_due_comparisons(app) == 0


def test_a_failed_window_does_not_stay_running(app, db, user, account):
    """A stale RUNNING child holds the single collection slot against everyone.

    The startup reconciler only fixes this on restart, so the collector has
    to settle the child itself on the way out.
    """
    from app.background_tasks import _collect_comparison_window

    comparison = _arm(user, account,
                      now=datetime.fromtimestamp(CHANGE_AT + 10 * HOUR,
                                                 tz=timezone.utc))
    pull = comparison.windows[0]

    class Exploding:
        def count(self, window):
            raise RuntimeError('upstream is down')

        def page(self, window, page):
            raise RuntimeError('upstream is down')

    import app.logpull.runner as runner_module
    original = runner_module.PullRunner.run
    runner_module.PullRunner.run = lambda self: (_ for _ in ()).throw(
        RuntimeError('upstream is down'))
    try:
        with pytest.raises(RuntimeError):
            _collect_comparison_window(app, comparison, pull, Exploding(),
                                       lambda *a, **k: None)
    finally:
        runner_module.PullRunner.run = original

    _db.session.refresh(pull)
    assert pull.status == LogPull.STATUS_ERROR
    assert not pull.is_active


def test_restart_leaves_a_comparison_resumable(app, db, user, account):
    from app.background_tasks import reconcile_interrupted_comparisons

    comparison = _arm(user, account,
                      now=datetime.fromtimestamp(CHANGE_AT + 10 * HOUR,
                                                 tz=timezone.utc))
    comparison.status = TrafficComparison.STATUS_COLLECTING
    comparison.current_label = 'control-1d-before'
    _db.session.commit()

    assert reconcile_interrupted_comparisons(app) == 1
    _db.session.refresh(comparison)
    assert comparison.status == TrafficComparison.STATUS_INTERRUPTED
    assert comparison.current_label is None
    assert 'restart' in comparison.error_message


# --- retention -------------------------------------------------------------


def test_sweep_leaves_pinned_windows_alone(app, db, user, account):
    from app.background_tasks import run_log_pull_cleanup

    comparison = _arm(user, account,
                      now=datetime.fromtimestamp(CHANGE_AT + 10 * HOUR,
                                                 tz=timezone.utc),
                      pinned=True)
    for pull in comparison.windows:
        pull.status = LogPull.STATUS_COMPLETE
        pull.raw_expires_at = datetime.utcnow() - timedelta(days=1)
    _db.session.commit()

    run_log_pull_cleanup(app)
    assert all(not pull.raw_deleted for pull in comparison.windows)


def test_sweep_does_not_reap_a_live_comparisons_windows(app, db, user, account):
    from app.background_tasks import run_log_pull_cleanup

    comparison = _arm(user, account,
                      now=datetime.fromtimestamp(CHANGE_AT + 10 * HOUR,
                                                 tz=timezone.utc))
    comparison.status = TrafficComparison.STATUS_COMPLETE
    for pull in comparison.windows:
        pull.status = LogPull.STATUS_COMPLETE
        # Old enough for the whole-pull sweep, were it not a comparison window.
        pull.created_at = datetime.utcnow() - timedelta(days=90)
    _db.session.commit()
    window_ids = [p.id for p in comparison.windows]

    run_log_pull_cleanup(app)
    # The parent is young, so neither it nor its windows should go.
    assert LogPull.query.filter(LogPull.id.in_(window_ids)).count() == len(window_ids)


def test_sweep_removes_an_expired_comparison_with_its_windows(app, db, user,
                                                              account):
    from app.background_tasks import run_log_pull_cleanup

    comparison = _arm(user, account,
                      now=datetime.fromtimestamp(CHANGE_AT + 10 * HOUR,
                                                 tz=timezone.utc))
    comparison.status = TrafficComparison.STATUS_COMPLETE
    comparison.created_at = datetime.utcnow() - timedelta(days=90)
    for pull in comparison.windows:
        pull.status = LogPull.STATUS_COMPLETE
    _db.session.commit()
    comparison_id = comparison.id
    window_ids = [p.id for p in comparison.windows]

    run_log_pull_cleanup(app)

    # The sweep runs in its own app context, which under Flask-SQLAlchemy
    # means its own session; without expiring, the assertions below would read
    # this session's cached copies rather than what was committed.
    _db.session.expire_all()

    # SQLite's FK cascade is inert, so the children must go explicitly or they
    # orphan, each still owning a directory on disk.
    assert _db.session.get(TrafficComparison, comparison_id) is None
    assert LogPull.query.filter(LogPull.id.in_(window_ids)).count() == 0


# --- presentation ----------------------------------------------------------


def test_auto_segments_ranks_by_bytes_not_requests():
    # A crawler making few very large requests outranks one making many small
    # ones — and it is the former that moves the bill.
    window = {'segments': {
        'Chatty': {'segment': 'Chatty', 'bytes': 1_000, 'requests': 10_000},
        'Heavy': {'segment': 'Heavy', 'bytes': 9_000_000, 'requests': 5},
    }}
    assert auto_segments(window, limit=1) == ['Heavy']


def test_verdict_calls_out_a_result_inside_the_control_range():
    result = {
        'segments': ['Googlebot'],
        'attribution': {'Googlebot': {'bytes_per_hour': {
            'observed': {'before': 100.0, 'after': 90.0, 'pct': -0.1},
            'control_count': 3,
            'outside_control_range': False,
            'attributable_abs': -1.0,
            'attributable_pct': -0.01,
        }}},
    }
    out = verdict(result)
    assert out['tone'] == 'neutral'
    assert 'not' in out['confidence'] and 'distinguishable' in out['confidence']


def test_verdict_warns_when_no_control_days_were_collected():
    result = {
        'segments': ['Googlebot'],
        'attribution': {'Googlebot': {'bytes_per_hour': {
            'observed': {'before': 100.0, 'after': 1.0, 'pct': -0.99},
            'control_count': 0, 'outside_control_range': None,
            'attributable_abs': None, 'attributable_pct': None,
        }}},
    }
    out = verdict(result)
    assert out['tone'] == 'warning'
    assert 'No control days' in out['confidence']


def test_verdict_is_absent_when_the_baseline_was_zero():
    result = {
        'segments': ['Googlebot'],
        'attribution': {'Googlebot': {'bytes_per_hour': {
            'observed': {'before': 0.0, 'after': 10.0, 'pct': None},
            'control_count': 1,
        }}},
    }
    # "It went from nothing to something" is a real result, and it is not a
    # percentage — so there is no headline to state.
    assert verdict(result) is None
