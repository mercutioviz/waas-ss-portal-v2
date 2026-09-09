"""Tests for Phase 3 — security metric trend persistence:
SecurityMetricSnapshot model, app/background_tasks.py's capture/cleanup
functions, and the dashboard's /dashboard/trend route."""

from datetime import datetime, timedelta

import pytest

from app.background_tasks import (
    capture_security_metrics, run_security_metric_cleanup, SECURITY_METRIC_RETENTION_DAYS,
)
from app.models import User, WaasAccount, SecurityMetricSnapshot
from app.waas_client import WaasApiError


class TestSecurityMetricSnapshotModel:
    def test_json_properties_round_trip(self, app, db):
        snap = SecurityMetricSnapshot(
            account_id=1, app_id='app1.example.com', app_name='app1.example.com',
            quick_range='r_1h',
        )
        snap.top_rules = [{'key': 'SQLi (#r1)', 'count': 5}]
        snap.top_ips = [{'key': '1.1.1.1', 'count': 3}]
        snap.top_urls = [{'key': '/login', 'count': 2}]
        db.session.add(snap)
        db.session.commit()

        fetched = db.session.get(SecurityMetricSnapshot, snap.id)
        assert fetched.top_rules == [{'key': 'SQLi (#r1)', 'count': 5}]
        assert fetched.top_ips == [{'key': '1.1.1.1', 'count': 3}]
        assert fetched.top_urls == [{'key': '/login', 'count': 2}]

    def test_unset_json_properties_default_to_empty_list(self, app, db):
        snap = SecurityMetricSnapshot(
            account_id=1, app_id='app1.example.com', app_name='app1.example.com',
            quick_range='r_1h',
        )
        assert snap.top_rules == []
        assert snap.top_ips == []
        assert snap.top_urls == []

    def test_to_dict(self, app, db):
        snap = SecurityMetricSnapshot(
            account_id=1, app_id='app1.example.com', app_name='app1.example.com',
            quick_range='r_1h', blocked_count=4, unique_ip_count=2, unique_rule_count=1,
        )
        d = snap.to_dict()
        assert d['app_id'] == 'app1.example.com'
        assert d['blocked_count'] == 4
        assert d['top_rules'] == []


class StubWaasClient:
    """Minimal stub standing in for WaasClient used by capture_security_metrics()."""

    def __init__(self, apps=None, waf_logs=None, list_error=None, logs_error=None):
        self.apps = apps if apps is not None else [{'name': 'app1.example.com'}]
        self.waf_logs = waf_logs or []
        self.list_error = list_error
        self.logs_error = logs_error

    def list_applications(self):
        if self.list_error:
            raise self.list_error
        return {'results': self.apps}

    def get_logs(self, app_id, quick_range='r_1h', page=1, items_per_page=1000, filter_fields=None):
        if self.logs_error:
            raise self.logs_error
        return {'results': self.waf_logs, 'count': len(self.waf_logs)}


def _waf_entry(ip='1.1.1.1', action='DENY', rule_id='r1', url='/login'):
    return {
        'EpochTime': 1756000000000,
        'Action': action,
        'ClientIP': ip,
        'URL': url,
        'RuleID': rule_id,
        'Attack': 'SQLi',
    }


@pytest.fixture
def user(app, db):
    u = User(username='metrics-tester', email='metrics@example.com', role='user', is_active=True)
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


class TestCaptureSecurityMetrics:
    def test_persists_one_snapshot_per_app(self, app, db, account, monkeypatch):
        stub = StubWaasClient(
            apps=[{'name': 'app1.example.com'}, {'name': 'app2.example.com'}],
            waf_logs=[_waf_entry(), _waf_entry(action='LOG')],
        )
        monkeypatch.setattr('app.background_tasks.WaasClient.from_account', lambda acc: stub)

        captured = capture_security_metrics(app)

        assert captured == 2
        snapshots = SecurityMetricSnapshot.query.filter_by(account_id=account.id).all()
        assert len(snapshots) == 2
        assert {s.app_id for s in snapshots} == {'app1.example.com', 'app2.example.com'}
        assert snapshots[0].blocked_count == 1
        assert snapshots[0].quick_range == 'r_1h'

    def test_skips_inactive_accounts(self, app, db, user, monkeypatch):
        inactive = WaasAccount(user_id=user.id, account_name='Disabled', is_active=False)
        inactive.api_key = 'k'
        db.session.add(inactive)
        db.session.commit()

        stub = StubWaasClient()
        monkeypatch.setattr('app.background_tasks.WaasClient.from_account', lambda acc: stub)

        captured = capture_security_metrics(app)
        assert captured == 0
        assert SecurityMetricSnapshot.query.filter_by(account_id=inactive.id).count() == 0

    def test_continues_past_list_applications_error(self, app, db, account, monkeypatch):
        stub = StubWaasClient(list_error=WaasApiError('upstream down'))
        monkeypatch.setattr('app.background_tasks.WaasClient.from_account', lambda acc: stub)

        captured = capture_security_metrics(app)
        assert captured == 0

    def test_continues_past_get_logs_error_for_one_app(self, app, db, account, monkeypatch):
        stub = StubWaasClient(
            apps=[{'name': 'app1.example.com'}, {'name': 'app2.example.com'}],
            logs_error=WaasApiError('boom'),
        )
        monkeypatch.setattr('app.background_tasks.WaasClient.from_account', lambda acc: stub)

        captured = capture_security_metrics(app)
        assert captured == 0

    def test_app_entries_missing_name_are_skipped(self, app, db, account, monkeypatch):
        stub = StubWaasClient(apps=[{'id': 'no-name-field'}])
        monkeypatch.setattr('app.background_tasks.WaasClient.from_account', lambda acc: stub)

        captured = capture_security_metrics(app)
        assert captured == 0


class TestRunSecurityMetricCleanup:
    def test_deletes_only_rows_older_than_retention_window(self, app, db, account):
        old = SecurityMetricSnapshot(
            account_id=account.id, app_id='app1.example.com', app_name='app1.example.com',
            quick_range='r_1h',
            captured_at=datetime.utcnow() - timedelta(days=SECURITY_METRIC_RETENTION_DAYS + 1),
        )
        recent = SecurityMetricSnapshot(
            account_id=account.id, app_id='app1.example.com', app_name='app1.example.com',
            quick_range='r_1h',
            captured_at=datetime.utcnow() - timedelta(days=1),
        )
        db.session.add_all([old, recent])
        db.session.commit()

        deleted = run_security_metric_cleanup(app)

        assert deleted == 1
        remaining = SecurityMetricSnapshot.query.all()
        assert len(remaining) == 1
        assert remaining[0].id == recent.id


class TestSecurityDashboardTrendRoute:
    def test_returns_points_within_window(self, logged_in_client, account, db):
        in_window = SecurityMetricSnapshot(
            account_id=account.id, app_id='app1.example.com', app_name='app1.example.com',
            quick_range='r_1h', blocked_count=3,
            captured_at=datetime.utcnow() - timedelta(days=5),
        )
        out_of_window = SecurityMetricSnapshot(
            account_id=account.id, app_id='app1.example.com', app_name='app1.example.com',
            quick_range='r_1h', blocked_count=9,
            captured_at=datetime.utcnow() - timedelta(days=40),
        )
        other_app = SecurityMetricSnapshot(
            account_id=account.id, app_id='other.example.com', app_name='other.example.com',
            quick_range='r_1h', blocked_count=7,
            captured_at=datetime.utcnow() - timedelta(days=1),
        )
        db.session.add_all([in_window, out_of_window, other_app])
        db.session.commit()

        resp = logged_in_client.get(f'/applications/{account.id}/app1.example.com/dashboard/trend?days=30')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['days'] == 30
        assert len(data['points']) == 1
        assert data['points'][0]['blocked_count'] == 3

    def test_invalid_days_falls_back_to_30(self, logged_in_client, account):
        resp = logged_in_client.get(f'/applications/{account.id}/app1.example.com/dashboard/trend?days=999')
        assert resp.status_code == 200
        assert resp.get_json()['days'] == 30

    def test_accepts_60_days(self, logged_in_client, account):
        resp = logged_in_client.get(f'/applications/{account.id}/app1.example.com/dashboard/trend?days=60')
        assert resp.status_code == 200
        assert resp.get_json()['days'] == 60

    def test_returns_404_for_unowned_account(self, logged_in_client, app, db):
        other = User(username='other2', email='other2@example.com', role='user', is_active=True)
        other.set_password('x')
        db.session.add(other)
        db.session.commit()
        other_acc = WaasAccount(user_id=other.id, account_name='Not Yours', is_active=True)
        other_acc.api_key = 'k'
        db.session.add(other_acc)
        db.session.commit()

        resp = logged_in_client.get(f'/applications/{other_acc.id}/app1.example.com/dashboard/trend')
        assert resp.status_code == 404
