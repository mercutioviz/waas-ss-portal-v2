"""Tests for the account-overview dashboard charts: the pure helpers in
app/overview_dashboard.py and the main.dashboard_chart_data endpoint.

The endpoint used to call get_application() (the full config export) once per
sampled app purely to tally server health — ~1.8s each, 40 calls for an 8-account
user, which pushed the whole request past nginx's 60s proxy timeout and surfaced
in the browser as "Failed to load". Health now comes off the application list
response, so several tests here pin that get_application() is never called and
that health covers every app rather than only the sampled ones.
"""
from datetime import datetime, timezone

import pytest

from app.models import User, WaasAccount
from app.overview_dashboard import (
    accumulate_log_entries,
    app_names,
    build_chart_payload,
    extract_app_list,
    run_in_pool,
    tally_server_health,
)
from app.waas_client import WaasApiError


def _epoch_ms(dt):
    """Treat a naive datetime as UTC and convert to epoch milliseconds."""
    return int(dt.replace(tzinfo=timezone.utc).timestamp() * 1000)


def _app(name, *healths):
    return {'name': name, 'servers': [{'health': h} for h in healths]}


class TestExtractAppList:
    def test_bare_list_passes_through(self):
        assert extract_app_list([{'name': 'a'}]) == [{'name': 'a'}]

    @pytest.mark.parametrize('key', ['results', 'data', 'applications'])
    def test_wrapped_shapes(self, key):
        assert extract_app_list({key: [{'name': 'a'}]}) == [{'name': 'a'}]

    def test_unrecognised_shapes_give_empty_list(self):
        assert extract_app_list(None) == []
        assert extract_app_list({'count': 3}) == []
        assert extract_app_list('nope') == []

    def test_non_list_under_known_key_is_not_returned(self):
        assert extract_app_list({'results': 'not-a-list'}) == []


class TestTallyServerHealth:
    def test_counts_up_down_and_unknown(self):
        apps = [_app('a', 'Up', 'Up', 'Down'), _app('b', 'Out of Service')]
        assert tally_server_health(apps) == {'up': 2, 'down': 1, 'unknown': 1}

    def test_health_matching_is_case_and_whitespace_insensitive(self):
        apps = [_app('a', ' up ', 'DOWN')]
        assert tally_server_health(apps) == {'up': 1, 'down': 1, 'unknown': 0}

    def test_app_with_no_servers_contributes_nothing(self):
        assert tally_server_health([{'name': 'a'}]) == {'up': 0, 'down': 0, 'unknown': 0}

    def test_missing_health_field_counts_unknown(self):
        apps = [{'name': 'a', 'servers': [{'host': '1.2.3.4'}]}]
        assert tally_server_health(apps) == {'up': 0, 'down': 0, 'unknown': 1}

    def test_accumulates_into_a_caller_supplied_dict(self):
        health = {'up': 5, 'down': 0, 'unknown': 0}
        tally_server_health([_app('a', 'Up')], health)
        assert health == {'up': 6, 'down': 0, 'unknown': 0}

    def test_malformed_entries_are_skipped(self):
        apps = ['junk', {'name': 'a', 'servers': ['junk', {'health': 'Up'}]}]
        assert tally_server_health(apps) == {'up': 1, 'down': 0, 'unknown': 0}


class TestAppNames:
    def test_returns_names_in_order(self):
        assert app_names([_app('b'), _app('a')]) == ['b', 'a']

    def test_honours_limit(self):
        assert app_names([_app('a'), _app('b'), _app('c')], limit=2) == ['a', 'b']

    def test_skips_unnamed_and_malformed_entries(self):
        assert app_names([{'servers': []}, 'junk', _app('a')]) == ['a']


class TestRunInPool:
    def test_runs_every_task_and_counts_them(self):
        seen = []
        done = run_in_pool([lambda i=i: seen.append(i) for i in range(5)], 10.0)
        assert done == 5
        assert sorted(seen) == [0, 1, 2, 3, 4]

    def test_empty_task_list(self):
        assert run_in_pool([], 10.0) == 0

    def test_work_done_before_the_deadline_survives_the_kill(self):
        """Tasks report through their closures, so a task killed at the
        deadline still leaves behind whatever it finished first."""
        import gevent

        collected = []

        def slow():
            collected.append('first')
            gevent.sleep(5)
            collected.append('never')

        done = run_in_pool([slow], 0.2)
        assert done == 0          # it did not finish
        assert collected == ['first']  # but its earlier work was kept


class TestAccumulateLogEntries:
    def test_buckets_timeline_by_utc_hour(self):
        ts = _epoch_ms(datetime(2026, 8, 24, 12, 30, 0))
        timeline, _, _, _ = accumulate_log_entries([{'EpochTime': ts}, {'EpochTime': ts}])
        assert dict(timeline) == {'08-24 12:00': 2}

    def test_counts_ips_and_prefers_attack_group_over_action(self):
        entries = [
            {'ClientIP': '1.1.1.1', 'AttackGroup': 'SQLi', 'Action': 'DENY'},
            {'ClientIP': '1.1.1.1', 'Action': 'DENY'},
        ]
        _, ips, types, attacks = accumulate_log_entries(entries)
        assert ips == {'1.1.1.1': 2}
        assert types == {'SQLi': 1, 'DENY': 1}
        assert attacks == 2

    def test_placeholder_attack_type_is_ignored(self):
        _, _, types, attacks = accumulate_log_entries([{'Action': '-'}])
        assert types == {}
        assert attacks == 0

    def test_bad_timestamps_do_not_raise_and_do_not_bucket(self):
        entries = [{'EpochTime': 'not-a-number'}, {'EpochTime': 10 ** 18}, {}]
        timeline, _, _, _ = accumulate_log_entries(entries)
        assert dict(timeline) == {}

    def test_malformed_entries_are_skipped(self):
        _, ips, _, _ = accumulate_log_entries(['junk', {'ClientIP': '2.2.2.2'}])
        assert ips == {'2.2.2.2': 1}


class TestBuildChartPayload:
    def test_sorts_timeline_and_caps_top_n(self):
        from collections import Counter

        timeline = {'08-24 13:00': 2, '08-24 12:00': 1}
        ips = Counter({f'ip{i}': i for i in range(15)})
        types = Counter({f't{i}': i for i in range(12)})
        payload = build_chart_payload(
            timeline, ips, types, {'up': 1, 'down': 0, 'unknown': 0},
            total_requests=3, total_attacks=2, apps_sampled=1,
            apps_total=9, partial=False,
        )
        assert payload['attack_timeline']['labels'] == ['08-24 12:00', '08-24 13:00']
        assert payload['attack_timeline']['data'] == [1, 2]
        assert len(payload['top_ips']['labels']) == 10
        assert len(payload['top_attack_types']['labels']) == 8

    def test_summary_reports_sampling_coverage(self):
        from collections import Counter

        payload = build_chart_payload(
            {}, Counter(), Counter(), {'up': 0, 'down': 0, 'unknown': 0},
            total_requests=0, total_attacks=0, apps_sampled=5,
            apps_total=59, partial=True,
        )
        assert payload['summary']['apps_checked'] == 5
        assert payload['summary']['apps_total'] == 59
        assert payload['summary']['partial'] is True


class StubWaasClient:
    """Stands in for WaasClient, recording which endpoints get hit."""

    def __init__(self, apps, logs=None, count=None, logs_error=None, list_error=None,
                 certs=None, certs_error=None):
        self.apps = apps
        self.certs = certs if certs is not None else []
        self.certs_error = certs_error
        self.logs = logs if logs is not None else []
        self.count = count if count is not None else len(self.logs)
        self.logs_error = logs_error
        self.list_error = list_error
        self.log_calls = []
        self.export_calls = []

    def list_applications(self, params=None):
        if self.list_error:
            raise self.list_error
        return self.apps

    def get_application(self, app_id):
        # The old implementation called this once per sampled app. Record any
        # call so the tests can assert it never happens again.
        self.export_calls.append(app_id)
        return {'servers': []}

    def list_certificates(self, app_name=None):
        if self.certs_error:
            raise self.certs_error
        return self.certs

    def get_logs(self, app_name, quick_range='r_24h', page=1, items_per_page=50,
                 from_epoch=None, to_epoch=None, filter_fields=None, timeout=None):
        self.log_calls.append({'app': app_name, 'range': quick_range, 'timeout': timeout})
        if self.logs_error:
            raise self.logs_error
        return {'results': self.logs, 'count': self.count}


@pytest.fixture
def user(app, db):
    u = User(username='overview-tester', email='overview@example.com', role='user', is_active=True)
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


def _patch_client(monkeypatch, stub):
    monkeypatch.setattr('app.waas_client.WaasClient.from_account', lambda acc: stub)


class TestChartDataEndpoint:
    def test_health_covers_every_app_not_just_sampled_ones(self, logged_in_client, account, monkeypatch):
        """Nine apps, only five get sampled for logs — but health must count
        the servers on all nine, because it is free from the list response."""
        apps = [_app(f'app{i}.example.com', 'Up', 'Down') for i in range(9)]
        stub = StubWaasClient(apps)
        _patch_client(monkeypatch, stub)

        resp = logged_in_client.get('/dashboard/chart-data?range=r_24h')
        assert resp.status_code == 200
        data = resp.get_json()

        assert data['server_health'] == {'up': 9, 'down': 9, 'unknown': 0}
        assert data['summary']['apps_checked'] == 5
        assert data['summary']['apps_total'] == 9

    def test_never_calls_the_application_export(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient([_app(f'app{i}', 'Up') for i in range(9)])
        _patch_client(monkeypatch, stub)

        logged_in_client.get('/dashboard/chart-data')

        assert stub.export_calls == []

    def test_one_list_call_and_at_most_five_log_calls_per_account(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient([_app(f'app{i}', 'Up') for i in range(20)])
        _patch_client(monkeypatch, stub)

        logged_in_client.get('/dashboard/chart-data')

        assert len(stub.log_calls) == 5
        assert [c['app'] for c in stub.log_calls] == [f'app{i}' for i in range(5)]

    def test_log_calls_carry_a_bounded_timeout(self, logged_in_client, account, monkeypatch):
        """A single hung log call must not be able to eat the whole budget."""
        from app.overview_dashboard import LOG_REQUEST_TIMEOUT_SECONDS

        stub = StubWaasClient([_app('app0', 'Up')])
        _patch_client(monkeypatch, stub)

        logged_in_client.get('/dashboard/chart-data')

        assert stub.log_calls[0]['timeout'] == LOG_REQUEST_TIMEOUT_SECONDS

    def test_aggregates_log_entries_into_charts(self, logged_in_client, account, monkeypatch):
        ts = _epoch_ms(datetime(2026, 8, 24, 12, 0, 0))
        logs = [
            {'EpochTime': ts, 'ClientIP': '1.1.1.1', 'AttackGroup': 'SQLi'},
            {'EpochTime': ts, 'ClientIP': '2.2.2.2', 'AttackGroup': 'XSS'},
        ]
        stub = StubWaasClient([_app('app0', 'Up')], logs=logs, count=2)
        _patch_client(monkeypatch, stub)

        data = logged_in_client.get('/dashboard/chart-data').get_json()

        assert data['attack_timeline'] == {'labels': ['08-24 12:00'], 'data': [2]}
        assert sorted(data['top_ips']['labels']) == ['1.1.1.1', '2.2.2.2']
        assert sorted(data['top_attack_types']['labels']) == ['SQLi', 'XSS']
        assert data['summary']['total_requests'] == 2
        assert data['summary']['total_attacks'] == 2

    def test_range_is_passed_through_to_the_api(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient([_app('app0', 'Up')])
        _patch_client(monkeypatch, stub)

        logged_in_client.get('/dashboard/chart-data?range=r_7d')

        assert stub.log_calls[0]['range'] == 'r_7d'

    def test_budget_exhaustion_returns_partial_rather_than_hanging(self, logged_in_client, account, monkeypatch):
        """With the budget at zero the log pass stops immediately — health is
        still complete, and the payload says the sampling was cut short."""
        monkeypatch.setattr('app.overview_dashboard.LOG_FETCH_BUDGET_SECONDS', 0.0)
        stub = StubWaasClient([_app(f'app{i}', 'Up') for i in range(5)])
        _patch_client(monkeypatch, stub)

        data = logged_in_client.get('/dashboard/chart-data').get_json()

        assert stub.log_calls == []
        assert data['summary']['partial'] is True
        assert data['summary']['apps_checked'] == 0
        assert data['server_health']['up'] == 5

    def test_log_failure_on_one_app_does_not_sink_the_response(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient([_app('app0', 'Up')], logs_error=WaasApiError('search too slow'))
        _patch_client(monkeypatch, stub)

        resp = logged_in_client.get('/dashboard/chart-data')

        assert resp.status_code == 200
        data = resp.get_json()
        assert data['server_health']['up'] == 1
        assert any('search too slow' in e for e in data['errors'])

    def test_list_failure_is_reported_without_a_500(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient([], list_error=WaasApiError('account unreachable'))
        _patch_client(monkeypatch, stub)

        resp = logged_in_client.get('/dashboard/chart-data')

        assert resp.status_code == 200
        data = resp.get_json()
        assert data['server_health'] == {'up': 0, 'down': 0, 'unknown': 0}
        assert any('account unreachable' in e for e in data['errors'])

    def test_account_id_filter_limits_the_fan_out(self, logged_in_client, account, app, db, user, monkeypatch):
        other = WaasAccount(user_id=user.id, account_name='Second', is_active=True)
        other.api_key = 'k2'
        db.session.add(other)
        db.session.commit()

        stub = StubWaasClient([_app('app0', 'Up')])
        _patch_client(monkeypatch, stub)

        data = logged_in_client.get(f'/dashboard/chart-data?account_id={account.id}').get_json()

        # Only the one account's apps were listed and sampled.
        assert data['summary']['apps_total'] == 1
        assert len(stub.log_calls) == 1

    def test_requires_login(self, client):
        resp = client.get('/dashboard/chart-data')
        assert resp.status_code == 302


class TestDashboardCountsEndpoint:
    def test_totals_and_per_account_counts(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient(
            [_app(f'app{i}', 'Up') for i in range(3)],
            certs=[{'name': 'c1', 'expiry': '2099-01-01'}, {'name': 'c2', 'expiry': '2099-01-01'}],
        )
        _patch_client(monkeypatch, stub)

        data = logged_in_client.get('/dashboard/counts').get_json()

        assert data['app_count'] == 3
        assert data['cert_count'] == 2
        assert len(data['accounts']) == 1
        assert data['accounts'][0]['app_count'] == 3
        assert data['accounts'][0]['cert_count'] == 2
        assert data['accounts'][0]['status'] == 'ok'

    def test_every_account_gets_an_entry_even_when_unreachable(
        self, logged_in_client, account, app, db, user, monkeypatch
    ):
        """The dashboard cards sit on a spinner until their account appears in
        this payload, so an account we could not call must still come back —
        flagged, not omitted."""
        broken = WaasAccount(user_id=user.id, account_name='Broken', is_active=True)
        broken.api_key = 'k'
        db.session.add(broken)
        db.session.commit()

        stub = StubWaasClient([_app('app0', 'Up')])

        def from_account(acc):
            if acc.account_name == 'Broken':
                raise WaasApiError('no credentials')
            return stub

        monkeypatch.setattr('app.waas_client.WaasClient.from_account', from_account)

        data = logged_in_client.get('/dashboard/counts').get_json()

        ids = {a['id']: a for a in data['accounts']}
        assert set(ids) == {account.id, broken.id}
        assert ids[broken.id]['status'] == 'error'
        assert ids[broken.id]['app_count'] == 0
        assert any('no credentials' in e for e in data['errors'])

    def test_account_too_slow_to_finish_is_flagged_not_reported_as_zero(
        self, logged_in_client, account, monkeypatch
    ):
        """A greenlet killed at the deadline must not leave a card showing a
        confident 0 apps / 0 certs."""
        import gevent

        monkeypatch.setattr('app.overview_dashboard.COUNTS_FETCH_BUDGET_SECONDS', 0.2)

        class SlowStub(StubWaasClient):
            def list_applications(self, params=None):
                gevent.sleep(3)
                return self.apps

        stub = SlowStub([_app('app0', 'Up')], certs=[{'name': 'c1'}])
        _patch_client(monkeypatch, stub)

        data = logged_in_client.get('/dashboard/counts').get_json()

        assert data['accounts'][0]['status'] == 'error'
        assert any('did not answer in time' in e for e in data['errors'])

    def test_partial_work_before_the_deadline_is_still_kept(
        self, logged_in_client, account, monkeypatch
    ):
        """App count arrives before the slow cert call; it should survive the
        kill, but the account still reads as incomplete."""
        import gevent

        monkeypatch.setattr('app.overview_dashboard.COUNTS_FETCH_BUDGET_SECONDS', 0.3)

        class SlowCertsStub(StubWaasClient):
            def list_certificates(self, app_name=None):
                gevent.sleep(3)
                return self.certs

        stub = SlowCertsStub([_app('app0', 'Up'), _app('app1', 'Up')], certs=[{'name': 'c1'}])
        _patch_client(monkeypatch, stub)

        data = logged_in_client.get('/dashboard/counts').get_json()

        assert data['accounts'][0]['app_count'] == 2   # kept
        assert data['accounts'][0]['cert_count'] == 0  # never arrived
        assert data['accounts'][0]['status'] == 'error'

    def test_expiring_certs_are_surfaced(self, logged_in_client, account, monkeypatch):
        from datetime import date, timedelta

        soon = (date.today() + timedelta(days=5)).isoformat()
        stub = StubWaasClient(
            [_app('app0', 'Up')],
            certs=[{'name': 'expiring-soon', 'expiry': soon, '_app_name': 'app0'},
                   {'name': 'fine', 'expiry': '2099-01-01'}],
        )
        _patch_client(monkeypatch, stub)

        data = logged_in_client.get('/dashboard/counts').get_json()

        names = [c['name'] for c in data['expiring_certs']]
        assert names == ['expiring-soon']
        assert data['expiring_certs'][0]['days_remaining'] == 5

    def test_cert_failure_still_reports_app_count(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient(
            [_app('app0', 'Up'), _app('app1', 'Up')],
            certs_error=WaasApiError('cert listing broke'),
        )
        _patch_client(monkeypatch, stub)

        data = logged_in_client.get('/dashboard/counts').get_json()

        assert data['app_count'] == 2
        assert data['cert_count'] == 0
        assert data['accounts'][0]['status'] == 'ok'
        assert any('cert listing broke' in e for e in data['errors'])

    def test_requires_login(self, client):
        assert client.get('/dashboard/counts').status_code == 302
