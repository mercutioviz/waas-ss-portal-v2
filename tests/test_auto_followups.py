"""Tests for the opt-in origin follow-ups after a collection
(`_run_followups` in app/background_tasks.py).

The header audit and the robots.txt proposal both send live requests to the
customer's own web servers, which collecting logs never does. Automating them
therefore has to preserve one property above all: a pull where the user did not
tick the box must touch the origin exactly zero times.

The rest of what is pinned here produces a wrong answer rather than an error:

- Follow-ups must run *before* STATUS_COMPLETE. `watch.html` redirects the
  moment it sees that status, so running them afterwards drops the user on a
  results page whose cards fill in behind them.
- A probe that raises must not cost a completed collection. The rows are the
  expensive part; the same rule `_analyze_collected` follows.
- An analysis that errored must not trigger probes — that is sending real
  traffic to someone's origin on the basis of nothing.
- An auto-generated robots proposal was measured against the file *as WaaS
  serves it*, not the origin's file, because nobody was present to paste one.
  It has to say so, and a later manual run with pasted text has to clear that.
"""
import uuid

import pytest

from app import background_tasks
from app.background_tasks import _run_followups
from app.logpull.windows import MODE_FULL, MODE_SAMPLE
from app.models import LogPull, User, WaasAccount


@pytest.fixture
def user(app, db):
    u = User(username='af-tester', email='af@example.com', role='user',
             is_active=True)
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


@pytest.fixture
def logged_in_client(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True
    return client


def make_pull(db, user, account, **kwargs):
    defaults = dict(
        user_id=user.id, account_id=account.id,
        app_id='app-1.example.com', app_name='app-1.example.com',
        mode=MODE_SAMPLE, window_days=7,
        range_start=1_767_225_600, range_end=1_767_398_400,
        session_id=str(uuid.uuid4()),
        status=LogPull.STATUS_RUNNING, phase=LogPull.PHASE_ANALYZING,
        auto_followups=True,
    )
    defaults.update(kwargs)
    pull = LogPull(**defaults)
    db.session.add(pull)
    db.session.commit()
    return pull


WITH_TARGETS = {'analysis': {'audit_targets': [{'host': 'h', 'url': '/a.js'}],
                             'audit_skipped_hosts': []}}


@pytest.fixture
def probes(monkeypatch):
    """Capture every would-be outbound call instead of making one."""
    calls = {'audit': [], 'robots': []}

    def fake_audit(pull):
        calls['audit'].append(pull.id)
        return {'assets': [], 'findings': [], 'probed': 1, 'requested': 1}

    def fake_robots(app, pull, *, current_text=None, on_progress=None,
                    auto=False):
        calls['robots'].append((pull.id, current_text, auto))
        return {'host': 'h', 'findings': [], 'proposal': {},
                'auto_generated': bool(auto) and current_text is None}

    monkeypatch.setattr(background_tasks, '_header_audit_for', fake_audit)
    monkeypatch.setattr(background_tasks, '_robots_proposal_for', fake_robots)
    return calls


class TestConsent:
    def test_opting_in_runs_both(self, app, db, user, account, probes):
        pull = make_pull(db, user, account, result=WITH_TARGETS)
        _run_followups(app, pull, lambda payload: None)
        assert probes['audit'] == [pull.id]
        assert len(probes['robots']) == 1

    def test_opting_out_touches_the_origin_zero_times(self, app, db, user,
                                                      account, probes):
        """The property the whole feature has to preserve."""
        pull = make_pull(db, user, account, auto_followups=False,
                         result=WITH_TARGETS)
        _run_followups(app, pull, lambda payload: None)
        assert probes['audit'] == []
        assert probes['robots'] == []
        assert (pull.report or {}) == {}

    def test_results_are_stored_on_the_row(self, app, db, user, account,
                                           probes):
        pull = make_pull(db, user, account, result=WITH_TARGETS)
        _run_followups(app, pull, lambda payload: None)
        db.session.refresh(pull)
        assert 'header_audit' in pull.report
        assert 'robots' in pull.report


class TestSkipConditions:
    def test_an_errored_analysis_probes_nothing(self, app, db, user, account,
                                                probes):
        """Probing on the strength of a failed analysis is sending real
        traffic on the basis of nothing."""
        pull = make_pull(db, user, account,
                         result={'analysis': {'error': 'boom'}})
        _run_followups(app, pull, lambda payload: None)
        assert probes['audit'] == []
        assert probes['robots'] == []

    def test_no_audit_targets_skips_the_audit_but_still_proposes(
            self, app, db, user, account, probes):
        pull = make_pull(db, user, account,
                         result={'analysis': {'audit_targets': []}})
        _run_followups(app, pull, lambda payload: None)
        assert probes['audit'] == []
        assert len(probes['robots']) == 1

    def test_a_sampled_pull_still_runs_both(self, app, db, user, account,
                                            probes):
        pull = make_pull(db, user, account, mode=MODE_SAMPLE,
                         result=WITH_TARGETS)
        _run_followups(app, pull, lambda payload: None)
        assert probes['audit'] and probes['robots']

    def test_a_full_pull_runs_both(self, app, db, user, account, probes):
        pull = make_pull(db, user, account, mode=MODE_FULL,
                         result=WITH_TARGETS)
        _run_followups(app, pull, lambda payload: None)
        assert probes['audit'] and probes['robots']


class TestFailureIsNeverFatal:
    def test_an_audit_that_raises_does_not_stop_the_proposal(
            self, app, db, user, account, probes, monkeypatch):
        def boom(pull):
            raise RuntimeError('origin unreachable')
        monkeypatch.setattr(background_tasks, '_header_audit_for', boom)

        pull = make_pull(db, user, account, result=WITH_TARGETS)
        _run_followups(app, pull, lambda payload: None)

        assert len(probes['robots']) == 1
        assert pull.status == LogPull.STATUS_RUNNING  # never flipped to error

    def test_a_proposal_that_raises_leaves_the_audit_stored(
            self, app, db, user, account, probes, monkeypatch):
        def boom(app_, pull, **kwargs):
            raise RuntimeError('fetch failed')
        monkeypatch.setattr(background_tasks, '_robots_proposal_for', boom)

        pull = make_pull(db, user, account, result=WITH_TARGETS)
        _run_followups(app, pull, lambda payload: None)
        db.session.refresh(pull)

        assert 'header_audit' in (pull.report or {})
        assert pull.status == LogPull.STATUS_RUNNING

    def test_both_raising_still_returns_cleanly(self, app, db, user, account,
                                                monkeypatch):
        monkeypatch.setattr(background_tasks, '_header_audit_for',
                            lambda pull: (_ for _ in ()).throw(RuntimeError()))
        monkeypatch.setattr(background_tasks, '_robots_proposal_for',
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError()))
        pull = make_pull(db, user, account, result=WITH_TARGETS)
        _run_followups(app, pull, lambda payload: None)  # must not raise

    def test_a_failing_emit_does_not_escape(self, app, db, user, account,
                                            probes):
        """`emit` is a socket write between the two phases. A dead socket is
        not a reason to lose an hours-long collection."""
        def bad_emit(payload):
            raise RuntimeError('socket gone')

        pull = make_pull(db, user, account, result=WITH_TARGETS)
        _run_followups(app, pull, bad_emit)  # must not raise
        assert pull.status == LogPull.STATUS_RUNNING


class TestOrdering:
    def test_followups_finish_before_the_status_goes_complete(
            self, app, db, user, account, monkeypatch):
        """watch.html redirects on STATUS_COMPLETE, so anything that runs
        after it is invisible to the user who is watching."""
        seen = {}

        def fake_audit(pull):
            seen['status_during_audit'] = pull.status
            return {}
        monkeypatch.setattr(background_tasks, '_header_audit_for', fake_audit)
        monkeypatch.setattr(background_tasks, '_robots_proposal_for',
                            lambda *a, **k: {})

        pull = make_pull(db, user, account, result=WITH_TARGETS)
        _run_followups(app, pull, lambda payload: None)
        assert seen['status_during_audit'] != LogPull.STATUS_COMPLETE

    def test_each_followup_announces_its_phase(self, app, db, user, account,
                                               probes):
        phases = []
        _run_followups(
            app, make_pull(db, user, account, result=WITH_TARGETS),
            lambda payload: phases.append(payload.get('phase')),
        )
        assert LogPull.PHASE_PROBING in phases
        assert LogPull.PHASE_PROPOSING in phases


class TestRobotsProvenance:
    def test_an_auto_proposal_is_marked_as_fetched_not_pasted(
            self, app, db, user, account, probes):
        pull = make_pull(db, user, account, result=WITH_TARGETS)
        _run_followups(app, pull, lambda payload: None)
        db.session.refresh(pull)
        assert pull.report['robots']['auto_generated'] is True

    def test_the_auto_run_passes_no_pasted_text(self, app, db, user, account,
                                                probes):
        pull = make_pull(db, user, account, result=WITH_TARGETS)
        _run_followups(app, pull, lambda payload: None)
        _pull_id, current_text, auto = probes['robots'][0]
        assert current_text is None
        assert auto is True

    def test_pasted_text_clears_the_marker(self, app, db, user, account,
                                           monkeypatch, tmp_path):
        """A manual re-run with the origin's real file takes precedence."""
        monkeypatch.setattr(
            'app.logpull.robots.build_report',
            lambda *a, **k: {'host': 'h', 'findings': [], 'proposal': {}})
        pull = make_pull(db, user, account, result=WITH_TARGETS)
        fragment = background_tasks._robots_proposal_for(
            app, pull, current_text='User-agent: *\n', auto=True)
        assert fragment['auto_generated'] is False

    def _rendered(self, logged_in_client, db, user, account, auto):
        # The robots card lives inside the `{% elif analysis %}` branch, so a
        # real analysis has to be present for it to render at all. Built from
        # the aggregator rather than hand-rolled so the shape cannot drift
        # from what the template actually reads.
        from app.logpull.analysis import CacheAggregator
        empty = CacheAggregator().result(
            scale=1.0, sample={}, check_host=lambda h, resolve=True: False)
        pull = make_pull(db, user, account, status=LogPull.STATUS_COMPLETE,
                         phase=LogPull.PHASE_DONE,
                         result={'analysis': empty})
        pull.report = {'robots': {'host': 'h', 'findings': [],
                                  'proposal': {}, 'auto_generated': auto}}
        db.session.commit()
        return logged_in_client.get(f'/traffic/{pull.id}/results')

    def test_the_results_page_warns_about_an_auto_proposal(
            self, logged_in_client, db, user, account):
        resp = self._rendered(logged_in_client, db, user, account, True)
        assert resp.status_code == 200
        assert b'as WaaS serves it' in resp.data

    def test_no_warning_when_the_text_was_pasted(self, logged_in_client, db,
                                                 user, account):
        resp = self._rendered(logged_in_client, db, user, account, False)
        assert resp.status_code == 200
        assert b'as WaaS serves it' not in resp.data


class TestReanalysisIsExempt:
    def test_re_analysis_does_not_chain_followups(self, app, db, user,
                                                  account, probes,
                                                  monkeypatch):
        """Re-analysis is cheap and frequent; re-probing the customer's origin
        every time someone re-runs it is not."""
        monkeypatch.setattr(background_tasks, '_analyze_collected',
                            lambda *a, **k: {'audit_targets': []})
        pull = make_pull(db, user, account, status=LogPull.STATUS_COMPLETE,
                         phase=LogPull.PHASE_DONE, result=WITH_TARGETS)
        background_tasks.run_log_pull_analysis(app, pull.id)
        assert probes['audit'] == []
        assert probes['robots'] == []


@pytest.fixture
def stub_api(monkeypatch, account):
    """Stub out everything the create path touches beyond the DB."""
    spawned = []
    monkeypatch.setattr('app.routes.traffic.socketio.start_background_task',
                        lambda fn, *a, **kw: spawned.append((fn.__name__, a)))
    monkeypatch.setattr('app.routes.traffic.get_client_for_account',
                        lambda account_id: (object(), account, True))
    monkeypatch.setattr('app.routes.traffic.corpus_bytes', lambda path: 0)
    return spawned


def stub_preflight(monkeypatch, *, rows=1000):
    def _fake(source, start, end, path, **kwargs):
        option = {
            'mode': 'x', 'rows': rows, 'seconds': 10, 'bytes': rows * 61,
            'sample_rate': 1.0,
            'disk': {'blocked': False, 'free_bytes': 100 * 1024 ** 3,
                     'ok': True},
        }
        return {
            'total_rows': rows, 'range_start': start, 'range_end': end,
            'options': {MODE_SAMPLE: dict(option), MODE_FULL: dict(option)},
            'recommended_mode': MODE_SAMPLE,
            'full_requires_confirmation': False,
            'corpus_bytes': 0, 'corpus_max_bytes': 1, 'corpus_full': False,
        }
    monkeypatch.setattr('app.routes.traffic.preflight', _fake)


class TestFormRoundTrip:
    def _create(self, client, account, monkeypatch, **extra):
        stub_preflight(monkeypatch)
        form = {'account_id': account.id, 'app_id': 'app-1.example.com',
                'app_name': 'app-1.example.com', 'mode': MODE_SAMPLE,
                'window_days': 7}
        form.update(extra)
        resp = client.post('/traffic/new', data=form)
        assert resp.status_code == 302
        return LogPull.query.one()

    def test_a_ticked_box_stores_true(self, logged_in_client, db, user,
                                      account, stub_api, monkeypatch):
        pull = self._create(logged_in_client, account, monkeypatch,
                            auto_followups='yes')
        assert pull.auto_followups is True

    def test_an_unticked_box_stores_false(self, logged_in_client, db, user,
                                          account, stub_api, monkeypatch):
        """An unchecked checkbox submits nothing at all, so the absence of the
        field has to read as a deliberate no — not as missing input to be
        defaulted generously."""
        pull = self._create(logged_in_client, account, monkeypatch)
        assert pull.auto_followups is False

    def test_a_junk_value_is_not_consent(self, logged_in_client, db, user,
                                         account, stub_api, monkeypatch):
        pull = self._create(logged_in_client, account, monkeypatch,
                            auto_followups='maybe')
        assert pull.auto_followups is False

    def test_the_choice_is_recorded_in_the_audit_log(self, logged_in_client,
                                                     db, user, account,
                                                     stub_api, monkeypatch):
        from app.models import AuditLog
        self._create(logged_in_client, account, monkeypatch,
                     auto_followups='yes')
        entry = AuditLog.query.filter_by(action='logpull_start').one()
        assert 'probe origin' in entry.details
