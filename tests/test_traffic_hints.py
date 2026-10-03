"""Tests for the application-list traffic hints: the AppTrafficSnapshot cache,
app/traffic_hints.py's fetch/upsert layer, and the two JSON routes.

The thing most worth pinning down here is the difference between "not
measured" and "measured as zero". Bandwidth is unavailable on an API-key-only
account, and a hint column that renders that as 0 B would quietly tell a user
an app is idle when nobody ever asked.
"""
from datetime import datetime, timedelta

import pytest

from app.background_tasks import run_traffic_hint_cleanup, TRAFFIC_HINT_RETENTION_DAYS
from app.models import AppTrafficSnapshot, User, WaasAccount
from app.waas_client import WaasApiError
from app import traffic_hints


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture
def user(app, db):
    u = User(username='hint-tester', email='hints@example.com', role='user', is_active=True)
    u.set_password('x')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def account(app, db, user):
    """API-key-only account — the common case, and the one with no bandwidth."""
    acc = WaasAccount(user_id=user.id, account_name='Acme WaaS', is_active=True)
    acc.api_key = 'v4-key'
    db.session.add(acc)
    db.session.commit()
    return acc


@pytest.fixture
def v2_account(app, db, user):
    acc = WaasAccount(user_id=user.id, account_name='Acme v2', is_active=True)
    acc.api_key = 'v4-key'
    acc.waas_email = 'a@example.com'
    acc.waas_password = 'secret'
    db.session.add(acc)
    db.session.commit()
    return acc


@pytest.fixture
def logged_in_client(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True
    return client


def _bw_row(name, metered=1000, total=10.0, bad=0.5):
    good = total - bad if isinstance(bad, (int, float)) else total
    return {'app_id': 1, 'name': name, 'metered_bytes': metered,
            'app_total_sum': total, 'app_out_sum': total, 'app_good_sum': good,
            'app_bad_sum': bad, 'total_out_included_sum': total}


class StubClient:
    """Stands in for WaasClient. Counts are served by patching LogSource."""

    def __init__(self, bandwidth_rows=None, bandwidth_error=None, apps=None,
                 upstream='Acme v2 (default account)'):
        self.bandwidth_rows = bandwidth_rows if bandwidth_rows is not None else []
        self.bandwidth_error = bandwidth_error
        self.upstream = upstream
        # By default the v4 app list agrees with the bandwidth report, which is
        # the case when both credentials point at the same WaaS account.
        self._apps = (apps if apps is not None
                      else [r['name'] for r in self.bandwidth_rows if r.get('name')])
        self.bandwidth_calls = 0

    def get_bandwidth_summary(self, quick_range='r_30d', app_ids=None):
        self.bandwidth_calls += 1
        if self.bandwidth_error:
            raise self.bandwidth_error
        return {'data': {'bandwidth_data': self.bandwidth_rows},
                'account': {'name': self.upstream}}

    def list_applications(self):
        return [{'name': n} for n in self._apps]


def patch_counts(monkeypatch, counts, errors=None):
    """Make LogSource(...).count() return from a dict instead of the API."""
    errors = errors or {}

    class FakeSource:
        def __init__(self, client, app_name, **kwargs):
            self.app_name = app_name

        def count(self, window):
            if self.app_name in errors:
                raise errors[self.app_name]
            return counts[self.app_name]

    monkeypatch.setattr('app.traffic_hints.LogSource', FakeSource)


# --------------------------------------------------------------------------
# Model
# --------------------------------------------------------------------------

class TestAppTrafficSnapshotModel:
    def test_to_dict_round_trip(self, app, db, account):
        row = AppTrafficSnapshot(account_id=account.id, app_name='a.example.com',
                                 window_days=30, requests=5, metered_bytes=10**10,
                                 bad_share=0.25)
        db.session.add(row)
        db.session.commit()

        d = db.session.get(AppTrafficSnapshot, row.id).to_dict()
        assert d['app_name'] == 'a.example.com'
        assert d['requests'] == 5
        assert d['metered_bytes'] == 10**10
        assert d['bad_share'] == 0.25
        assert d['error'] is None

    def test_measures_are_independently_nullable(self, app, db, account):
        """An API-key-only account gets requests and no bytes. That must store."""
        row = AppTrafficSnapshot(account_id=account.id, app_name='a.example.com',
                                 window_days=30, requests=12)
        db.session.add(row)
        db.session.commit()
        assert db.session.get(AppTrafficSnapshot, row.id).metered_bytes is None


# --------------------------------------------------------------------------
# bad_share
# --------------------------------------------------------------------------

class TestBadShare:
    def test_ratio(self):
        assert traffic_hints._bad_share(_bw_row('x', total=10.0, bad=0.5)) == 0.05

    def test_zero_total_is_none_not_zero(self):
        """No traffic means the share is undefined, not 0% clean."""
        assert traffic_hints._bad_share(_bw_row('x', total=0.0, bad=0.0)) is None

    def test_missing_bad_field_is_none(self):
        row = _bw_row('x')
        del row['app_bad_sum']
        assert traffic_hints._bad_share(row) is None

    def test_clamped_to_unit_interval(self):
        assert traffic_hints._bad_share(_bw_row('x', total=1.0, bad=5.0)) == 1.0

    def test_non_numeric_is_none(self):
        assert traffic_hints._bad_share(_bw_row('x', total=10.0, bad='n/a')) is None

    def test_unit_switch_does_not_change_the_ratio(self):
        """The *_sum floats are MB at r_7d and GB at r_30d; the ratio is not."""
        mb = traffic_hints._bad_share(_bw_row('x', total=386.54, bad=6.14))
        gb = traffic_hints._bad_share(_bw_row('x', total=0.38654, bad=0.00614))
        assert mb == pytest.approx(gb)


# --------------------------------------------------------------------------
# fetch_bandwidth
# --------------------------------------------------------------------------

class TestFetchBandwidth:
    def test_returns_empty_without_v2_credentials(self, app, db, account):
        client = StubClient(bandwidth_rows=[_bw_row('a.example.com')])
        assert traffic_hints.fetch_bandwidth(client, account) == {}
        assert client.bandwidth_calls == 0, 'must not call an endpoint that will 401'

    def test_maps_rows_by_name(self, app, db, v2_account):
        client = StubClient(bandwidth_rows=[
            _bw_row('a.example.com', metered=2048, total=10.0, bad=0.5),
            _bw_row('b.example.com', metered=4096, total=10.0, bad=0.0),
        ])
        out = traffic_hints.fetch_bandwidth(client, v2_account)
        assert out['a.example.com'] == {'metered_bytes': 2048, 'bad_share': 0.05}
        assert out['b.example.com']['metered_bytes'] == 4096

    def test_duplicate_names_are_summed(self, app, db, v2_account):
        """Two apps really can share a display name; dropping one loses traffic."""
        client = StubClient(bandwidth_rows=[
            _bw_row('Test App', metered=100, total=10.0, bad=0.1),
            _bw_row('Test App', metered=400, total=10.0, bad=0.9),
        ])
        out = traffic_hints.fetch_bandwidth(client, v2_account)
        assert out['Test App']['metered_bytes'] == 500
        assert out['Test App']['bad_share'] == pytest.approx(0.09)

    def test_unnamed_rows_skipped(self, app, db, v2_account):
        client = StubClient(bandwidth_rows=[{'app_id': 9, 'metered_bytes': 1}])
        assert traffic_hints.fetch_bandwidth(client, v2_account) == {}


# --------------------------------------------------------------------------
# fetch_counts
# --------------------------------------------------------------------------

class TestFetchCounts:
    def test_returns_counts(self, app, monkeypatch):
        patch_counts(monkeypatch, {'a': 10, 'b': 20})
        out = traffic_hints.fetch_counts(StubClient(), ['a', 'b'])
        assert out == {'a': (10, None), 'b': (20, None)}

    def test_one_failure_does_not_cost_the_others(self, app, monkeypatch):
        patch_counts(monkeypatch, {'a': 10, 'c': 30},
                     errors={'b': WaasApiError('boom')})
        out = traffic_hints.fetch_counts(StubClient(), ['a', 'b', 'c'])
        assert out['a'] == (10, None)
        assert out['c'] == (30, None)
        assert out['b'][0] is None and 'boom' in out['b'][1]

    def test_error_text_fits_the_column(self, app, monkeypatch):
        patch_counts(monkeypatch, {}, errors={'a': WaasApiError('x' * 500)})
        assert len(traffic_hints.fetch_counts(StubClient(), ['a'])['a'][1]) <= 255


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------

class TestCache:
    def test_upsert_then_load(self, app, db, account):
        traffic_hints.upsert(account.id, {'a': {'requests': 7}})
        cached = traffic_hints.load_cached(account.id, ['a'])
        assert cached['a']['requests'] == 7

    def test_upsert_refreshes_in_place(self, app, db, account):
        traffic_hints.upsert(account.id, {'a': {'requests': 7}})
        traffic_hints.upsert(account.id, {'a': {'requests': 9}})
        rows = AppTrafficSnapshot.query.filter_by(account_id=account.id).all()
        assert len(rows) == 1, 'cache, not history'
        assert rows[0].requests == 9

    def test_partial_upsert_preserves_the_other_measure(self, app, db, account):
        """Bandwidth and counts land in separate calls; the second must not
        erase what the first wrote."""
        traffic_hints.upsert(account.id, {'a': {'metered_bytes': 500, 'bad_share': 0.1}})
        traffic_hints.upsert(account.id, {'a': {'requests': 7}})
        row = traffic_hints.load_cached(account.id, ['a'])['a']
        assert row['requests'] == 7
        assert row['metered_bytes'] == 500
        assert row['bad_share'] == 0.1

    def test_expired_rows_are_not_returned(self, app, db, account):
        traffic_hints.upsert(account.id, {'a': {'requests': 7}})
        stale = datetime.utcnow() - timedelta(seconds=traffic_hints.TTL_SECONDS + 60)
        AppTrafficSnapshot.query.filter_by(account_id=account.id).one().captured_at = stale
        db.session.commit()
        assert traffic_hints.load_cached(account.id, ['a']) == {}

    def test_scoped_to_account(self, app, db, user, account):
        other = WaasAccount(user_id=user.id, account_name='Other', is_active=True)
        other.api_key = 'k'
        db.session.add(other)
        db.session.commit()
        traffic_hints.upsert(account.id, {'a': {'requests': 7}})
        assert traffic_hints.load_cached(other.id, ['a']) == {}

    def test_empty_inputs_are_noops(self, app, db, account):
        assert traffic_hints.load_cached(account.id, []) == {}
        assert traffic_hints.upsert(account.id, {}) == {}


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

class TestBandwidthRoute:
    def test_unavailable_without_v2_credentials(self, app, db, account, logged_in_client):
        r = logged_in_client.get(f'/applications/api/{account.id}/traffic-hints/bandwidth')
        assert r.status_code == 200
        body = r.get_json()
        assert body['available'] is False
        assert body['apps'] == {}
        assert body['reason'], 'the UI needs something to explain the blank column'

    def test_returns_and_caches(self, app, db, v2_account, logged_in_client, monkeypatch):
        stub = StubClient(bandwidth_rows=[_bw_row('a.example.com', metered=2048,
                                                  total=10.0, bad=0.5)])
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account',
                            lambda acc: stub)

        r = logged_in_client.get(f'/applications/api/{v2_account.id}/traffic-hints/bandwidth')
        body = r.get_json()
        assert body['available'] is True
        assert body['apps']['a.example.com']['metered_bytes'] == 2048
        assert body['apps']['a.example.com']['bad_share'] == 0.05
        assert traffic_hints.load_cached(v2_account.id, ['a.example.com'])

    def test_api_error_is_502(self, app, db, v2_account, logged_in_client, monkeypatch):
        stub = StubClient(bandwidth_error=WaasApiError('upstream down'))
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account',
                            lambda acc: stub)
        r = logged_in_client.get(f'/applications/api/{v2_account.id}/traffic-hints/bandwidth')
        assert r.status_code == 502

    def test_unknown_account_is_404(self, app, db, logged_in_client):
        r = logged_in_client.get('/applications/api/9999/traffic-hints/bandwidth')
        assert r.status_code == 404

    def test_wrong_upstream_account_is_refused(self, app, db, v2_account,
                                               logged_in_client, monkeypatch):
        """The v2 login can belong to a different WaaS account than the API key.

        Seen live: two portal accounts sharing one v2 login both received the
        login's default account, so the second was being offered another
        account's bytes under its own app names.
        """
        stub = StubClient(bandwidth_rows=[_bw_row('somebody-elses-app')],
                          apps=['our-app-a', 'our-app-b'],
                          upstream='other.example (default account)')
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account',
                            lambda acc: stub)

        body = logged_in_client.get(
            f'/applications/api/{v2_account.id}/traffic-hints/bandwidth').get_json()
        assert body['available'] is False
        assert body['apps'] == {}
        assert 'other.example' in body['reason']
        assert AppTrafficSnapshot.query.count() == 0, 'must not cache foreign bytes'

    def test_foreign_apps_are_filtered_out(self, app, db, v2_account,
                                           logged_in_client, monkeypatch):
        """Deleted or out-of-scope apps still carry traffic history upstream."""
        stub = StubClient(bandwidth_rows=[_bw_row('ours'), _bw_row('not-ours')],
                          apps=['ours'])
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account',
                            lambda acc: stub)

        body = logged_in_client.get(
            f'/applications/api/{v2_account.id}/traffic-hints/bandwidth').get_json()
        assert body['available'] is True
        assert list(body['apps']) == ['ours']

    def test_app_list_failure_still_serves_bandwidth(self, app, db, v2_account,
                                                    logged_in_client, monkeypatch):
        """The scope check is a guard, not a second dependency to fail on."""
        stub = StubClient(bandwidth_rows=[_bw_row('a.example.com', metered=2048)])
        monkeypatch.setattr(stub, 'list_applications',
                            lambda: (_ for _ in ()).throw(WaasApiError('list down')))
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account',
                            lambda acc: stub)

        body = logged_in_client.get(
            f'/applications/api/{v2_account.id}/traffic-hints/bandwidth').get_json()
        assert body['available'] is True
        assert body['apps']['a.example.com']['metered_bytes'] == 2048


class TestScopeMatches:
    def test_overlap_passes(self):
        assert traffic_hints.scope_matches({'a': {}, 'b': {}}, ['b', 'c'])

    def test_no_overlap_fails(self):
        assert not traffic_hints.scope_matches({'a': {}}, ['b', 'c'])

    def test_unknown_app_list_does_not_block(self):
        """A failed app-list lookup must not suppress data we did get."""
        assert traffic_hints.scope_matches({'a': {}}, set())

    def test_empty_report_is_not_a_mismatch(self):
        """An account with no traffic reports no rows; that is not a wrong account."""
        assert traffic_hints.scope_matches({}, ['a', 'b'])


class TestRequestsRoute:
    def _client(self, monkeypatch):
        stub = StubClient()
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account',
                            lambda acc: stub)
        return stub

    def test_counts_and_caches(self, app, db, account, logged_in_client, monkeypatch):
        self._client(monkeypatch)
        patch_counts(monkeypatch, {'a': 10, 'b': 20})

        r = logged_in_client.get(
            f'/applications/api/{account.id}/traffic-hints/requests?apps=a,b')
        assert r.get_json()['apps'] == {'a': {'requests': 10, 'error': None},
                                        'b': {'requests': 20, 'error': None}}
        assert traffic_hints.load_cached(account.id, ['a'])['a']['requests'] == 10

    def test_second_call_is_served_from_cache(self, app, db, account,
                                              logged_in_client, monkeypatch):
        self._client(monkeypatch)
        patch_counts(monkeypatch, {'a': 10})
        logged_in_client.get(f'/applications/api/{account.id}/traffic-hints/requests?apps=a')

        # Any count attempt now would raise, so a pass proves the cache was used.
        patch_counts(monkeypatch, {}, errors={'a': AssertionError('refetched')})
        r = logged_in_client.get(
            f'/applications/api/{account.id}/traffic-hints/requests?apps=a')
        assert r.get_json()['apps']['a']['requests'] == 10

    def test_batch_is_capped(self, app, db, account, logged_in_client, monkeypatch):
        self._client(monkeypatch)
        names = [f'app{i}' for i in range(traffic_hints.MAX_COUNT_BATCH + 5)]
        patch_counts(monkeypatch, {n: 1 for n in names})

        r = logged_in_client.get(
            f'/applications/api/{account.id}/traffic-hints/requests?apps=' + ','.join(names))
        assert len(r.get_json()['apps']) == traffic_hints.MAX_COUNT_BATCH

    def test_failure_reported_per_app(self, app, db, account, logged_in_client, monkeypatch):
        self._client(monkeypatch)
        patch_counts(monkeypatch, {'a': 10}, errors={'b': WaasApiError('nope')})

        apps = logged_in_client.get(
            f'/applications/api/{account.id}/traffic-hints/requests?apps=a,b'
        ).get_json()['apps']
        assert apps['a']['requests'] == 10
        assert apps['b']['requests'] is None
        assert 'nope' in apps['b']['error']

    def test_no_apps_is_empty_not_an_error(self, app, db, account, logged_in_client):
        r = logged_in_client.get(f'/applications/api/{account.id}/traffic-hints/requests')
        assert r.status_code == 200
        assert r.get_json()['apps'] == {}

    def test_unknown_account_is_404(self, app, db, logged_in_client):
        r = logged_in_client.get('/applications/api/9999/traffic-hints/requests?apps=a')
        assert r.status_code == 404

    def test_login_required(self, app, db, account, client):
        r = client.get(f'/applications/api/{account.id}/traffic-hints/requests?apps=a')
        assert r.status_code in (301, 302, 401)


# --------------------------------------------------------------------------
# Retention
# --------------------------------------------------------------------------

class TestCleanup:
    def test_deletes_only_rows_past_retention(self, app, db, account):
        traffic_hints.upsert(account.id, {'fresh': {'requests': 1}})
        traffic_hints.upsert(account.id, {'old': {'requests': 1}})
        old = AppTrafficSnapshot.query.filter_by(app_name='old').one()
        old.captured_at = datetime.utcnow() - timedelta(days=TRAFFIC_HINT_RETENTION_DAYS + 1)
        db.session.commit()

        assert run_traffic_hint_cleanup(app) == 1
        assert [r.app_name for r in AppTrafficSnapshot.query.all()] == ['fresh']
