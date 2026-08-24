"""Tests for the per-app security dashboard: the aggregate_waf_logs() helper
(app/security_dashboard.py) and the route/data endpoint (app/routes/applications.py)."""

from datetime import datetime, timezone

import pytest

from app.security_dashboard import aggregate_waf_logs
from app.models import User, WaasAccount


def _epoch_ms(dt):
    """Treat a naive datetime as UTC and convert to epoch milliseconds —
    avoids local-timezone drift from datetime.timestamp() on naive values."""
    return int(dt.replace(tzinfo=timezone.utc).timestamp() * 1000)


def _entry(epoch_ms, action='DENY', ip='1.1.1.1', url='/login', rule_id='r1', attack='SQLi'):
    return {
        'EpochTime': epoch_ms,
        'Action': action,
        'ClientIP': ip,
        'URL': url,
        'RuleID': rule_id,
        'Attack': attack,
    }


class TestAggregateWafLogs:
    def test_empty_logs_returns_zeroed_summary(self):
        now = datetime(2026, 8, 24, 12, 0, 0)
        result = aggregate_waf_logs([], 'r_1h', now=now)
        assert result['total_events'] == 0
        assert result['blocked_count'] == 0
        assert result['unique_ip_count'] == 0
        assert result['unique_rule_count'] == 0
        assert len(result['timeline']) == 12
        assert all(b['count'] == 0 for b in result['timeline'])
        assert result['top_rules'] == []
        assert result['truncated'] is False

    def test_counts_deny_vs_log_actions(self):
        now = datetime(2026, 8, 24, 12, 0, 0)
        now_ms = _epoch_ms(now)
        logs = [
            _entry(now_ms, action='DENY'),
            _entry(now_ms, action='DENY'),
            _entry(now_ms, action='LOG'),
        ]
        result = aggregate_waf_logs(logs, 'r_1h', now=now)
        assert result['total_events'] == 3
        assert result['blocked_count'] == 2

    def test_unique_ip_and_rule_counts(self):
        now = datetime(2026, 8, 24, 12, 0, 0)
        now_ms = _epoch_ms(now)
        logs = [
            _entry(now_ms, ip='1.1.1.1', rule_id='r1'),
            _entry(now_ms, ip='1.1.1.1', rule_id='r1'),
            _entry(now_ms, ip='2.2.2.2', rule_id='r2'),
        ]
        result = aggregate_waf_logs(logs, 'r_1h', now=now)
        assert result['unique_ip_count'] == 2
        assert result['unique_rule_count'] == 2

    def test_top_n_sorted_descending_by_count(self):
        now = datetime(2026, 8, 24, 12, 0, 0)
        now_ms = _epoch_ms(now)
        logs = (
            [_entry(now_ms, ip='9.9.9.9')] * 1
            + [_entry(now_ms, ip='8.8.8.8')] * 3
            + [_entry(now_ms, ip='7.7.7.7')] * 2
        )
        result = aggregate_waf_logs(logs, 'r_1h', now=now)
        assert [item['key'] for item in result['top_ips']] == ['8.8.8.8', '7.7.7.7', '9.9.9.9']
        assert [item['count'] for item in result['top_ips']] == [3, 2, 1]

    def test_top_n_capped_at_five(self):
        now = datetime(2026, 8, 24, 12, 0, 0)
        now_ms = _epoch_ms(now)
        logs = [_entry(now_ms, ip=f'10.0.0.{i}') for i in range(8)]
        result = aggregate_waf_logs(logs, 'r_1h', now=now)
        assert len(result['top_ips']) == 5

    def test_entries_bucketed_into_correct_5min_slot_for_1h_range(self):
        now = datetime(2026, 8, 24, 12, 0, 0)
        # r_1h uses 12 x 5-minute buckets covering [now - 1h, now).
        # An entry exactly 2 minutes before `now` should land in the last bucket.
        entry_time = datetime(2026, 8, 24, 11, 58, 0)
        entry_ms = _epoch_ms(entry_time)
        result = aggregate_waf_logs([_entry(entry_ms)], 'r_1h', now=now)
        counts = [b['count'] for b in result['timeline']]
        assert counts == [0] * 11 + [1]

    def test_entries_before_window_start_are_dropped_from_timeline_but_still_counted(self):
        now = datetime(2026, 8, 24, 12, 0, 0)
        stale_time = datetime(2026, 8, 24, 1, 0, 0)  # well before the 1h window
        stale_ms = _epoch_ms(stale_time)
        result = aggregate_waf_logs([_entry(stale_ms)], 'r_1h', now=now)
        assert result['total_events'] == 1  # headline counters still see it
        assert sum(b['count'] for b in result['timeline']) == 0  # but not the trend

    def test_unknown_quick_range_falls_back_to_default_buckets(self):
        now = datetime(2026, 8, 24, 12, 0, 0)
        result = aggregate_waf_logs([], 'not_a_real_range', now=now)
        assert len(result['timeline']) == 24

    def test_truncated_flag_set_when_api_count_exceeds_fetched_logs(self):
        now = datetime(2026, 8, 24, 12, 0, 0)
        now_ms = _epoch_ms(now)
        logs = [_entry(now_ms)]
        result = aggregate_waf_logs(logs, 'r_1h', total_from_api=500, now=now)
        assert result['truncated'] is True
        assert result['total_from_api'] == 500

    def test_truncated_flag_false_when_counts_match(self):
        now = datetime(2026, 8, 24, 12, 0, 0)
        now_ms = _epoch_ms(now)
        logs = [_entry(now_ms)]
        result = aggregate_waf_logs(logs, 'r_1h', total_from_api=1, now=now)
        assert result['truncated'] is False

    def test_entries_missing_epoch_time_are_ignored_by_timeline_not_totals(self):
        now = datetime(2026, 8, 24, 12, 0, 0)
        entry = _entry(None)
        del entry['EpochTime']
        result = aggregate_waf_logs([entry], 'r_1h', now=now)
        assert result['total_events'] == 1
        assert sum(b['count'] for b in result['timeline']) == 0


class StubWaasClient:
    """Minimal stub standing in for WaasClient.get_logs()."""

    def __init__(self, logs=None, count=None, raise_error=None):
        self.logs = logs or []
        self.count = count if count is not None else len(self.logs)
        self.raise_error = raise_error
        self.last_call = None

    def get_logs(self, app_id, quick_range='r_24h', page=1, items_per_page=50, filter_fields=None):
        self.last_call = {'app_id': app_id, 'quick_range': quick_range, 'filter_fields': filter_fields}
        if self.raise_error:
            raise self.raise_error
        return {'results': self.logs, 'count': self.count}


@pytest.fixture
def user(app, db):
    u = User(username='secdash-tester', email='secdash@example.com', role='user', is_active=True)
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


class TestSecurityDashboardRoute:
    def test_page_renders_for_owned_account(self, logged_in_client, account):
        resp = logged_in_client.get(f'/applications/{account.id}/app1.example.com/dashboard')
        assert resp.status_code == 200
        assert b'Security Dashboard' in resp.data

    def test_page_redirects_for_unowned_account(self, logged_in_client, app, db):
        other = User(username='other', email='other@example.com', role='user', is_active=True)
        other.set_password('x')
        db.session.add(other)
        db.session.commit()
        other_acc = WaasAccount(user_id=other.id, account_name='Not Yours', is_active=True)
        other_acc.api_key = 'k'
        db.session.add(other_acc)
        db.session.commit()

        resp = logged_in_client.get(f'/applications/{other_acc.id}/app1.example.com/dashboard')
        assert resp.status_code == 302

    def test_data_endpoint_returns_aggregated_json(self, logged_in_client, account, monkeypatch):
        now_ms = _epoch_ms(datetime(2026, 8, 24, 12, 0, 0))
        stub = StubWaasClient(logs=[_entry(now_ms), _entry(now_ms, action='LOG')], count=2)
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/applications/{account.id}/app1.example.com/dashboard/data?quick_range=r_1h')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['total_events'] == 2
        assert data['blocked_count'] == 1
        assert data['quick_range'] == 'r_1h'
        assert stub.last_call['filter_fields'] == {'LogType': [{'condition': 'is', 'value': 'WF'}]}

    def test_data_endpoint_falls_back_to_r_1h_for_invalid_range(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient(logs=[])
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/applications/{account.id}/app1.example.com/dashboard/data?quick_range=bogus')
        assert resp.status_code == 200
        assert stub.last_call['quick_range'] == 'r_1h'

    def test_data_endpoint_returns_502_on_api_error(self, logged_in_client, account, monkeypatch):
        from app.waas_client import WaasApiError
        stub = StubWaasClient(raise_error=WaasApiError('upstream down'))
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/applications/{account.id}/app1.example.com/dashboard/data')
        assert resp.status_code == 502
