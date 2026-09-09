"""Tests for Phase 5 — FP action workaround:
logs.create_fp_allow_rule(), which creates a URL allow rule from a
high-FP-confidence group and records a ConfigSnapshot(resource_type=
'fp_url_allow_create') for history/rollback. Not a true per-rule exception
(the WaaS API has no rule-ID-aware exception endpoint) — see CLAUDE.md /
the plan for why this is scoped down."""

import pytest

from app.models import User, WaasAccount, ConfigSnapshot
from app.waas_client import WaasApiError


class StubWaasClient:
    """Minimal stub standing in for WaasClient used by create_fp_allow_rule()."""

    def __init__(self, create_error=None):
        self.create_error = create_error
        self.created = []

    def create_url_access_rule(self, app_id, data):
        if self.create_error:
            raise self.create_error
        self.created.append((app_id, data))
        return {'name': data['name']}


@pytest.fixture
def user(app, db):
    u = User(username='fp-action-tester', email='fp-action@example.com', role='user', is_active=True)
    u.set_password('x')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def viewer(app, db):
    u = User(username='fp-action-viewer', email='fp-action-viewer@example.com', role='viewer', is_active=True)
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


def _login_as(client, u):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(u.id)
        sess['_fresh'] = True
    return client


@pytest.fixture
def logged_in_client(client, user):
    return _login_as(client, user)


class TestCreateFpAllowRule:
    def test_creates_rule_and_records_snapshot(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient()
        monkeypatch.setattr('app.routes.logs.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.post(
            f'/logs/{account.id}/app1.example.com/fp-allow-rule',
            data={'rule_name': 'fp-allow-r1', 'url_match': '/checkout'},
        )

        assert resp.status_code == 302
        assert stub.created == [('app1.example.com', {
            'name': 'fp-allow-r1', 'url_match': '/checkout', 'action_type': 'Allow',
        })]

        snap = ConfigSnapshot.query.filter_by(resource_type='fp_url_allow_create').first()
        assert snap is not None
        assert snap.app_id == 'app1.example.com'
        assert snap.payload_before_dict == {}
        assert snap.payload_applied_dict == {
            'name': 'fp-allow-r1', 'url_match': '/checkout', 'action_type': 'Allow',
        }

    def test_missing_url_does_not_create_rule_or_snapshot(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient()
        monkeypatch.setattr('app.routes.logs.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.post(
            f'/logs/{account.id}/app1.example.com/fp-allow-rule',
            data={'rule_name': 'fp-allow-r1', 'url_match': ''},
        )

        assert resp.status_code == 302
        assert stub.created == []
        assert ConfigSnapshot.query.filter_by(resource_type='fp_url_allow_create').count() == 0

    def test_waas_api_error_does_not_record_snapshot(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient(create_error=WaasApiError('upstream down'))
        monkeypatch.setattr('app.routes.logs.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.post(
            f'/logs/{account.id}/app1.example.com/fp-allow-rule',
            data={'rule_name': 'fp-allow-r1', 'url_match': '/checkout'},
        )

        assert resp.status_code == 302
        assert ConfigSnapshot.query.filter_by(resource_type='fp_url_allow_create').count() == 0

    def test_viewer_role_cannot_create_rule(self, client, viewer, account, monkeypatch):
        stub = StubWaasClient()
        monkeypatch.setattr('app.routes.logs.WaasClient.from_account', lambda acc: stub)
        _login_as(client, viewer)

        resp = client.post(
            f'/logs/{account.id}/app1.example.com/fp-allow-rule',
            data={'rule_name': 'fp-allow-r1', 'url_match': '/checkout'},
        )

        assert resp.status_code == 302
        assert stub.created == []
        assert ConfigSnapshot.query.filter_by(resource_type='fp_url_allow_create').count() == 0

    def test_unowned_account_returns_redirect_without_creating(self, app, db, client, monkeypatch):
        other = User(username='fp-action-other', email='fp-action-other@example.com', role='user', is_active=True)
        other.set_password('x')
        db.session.add(other)
        db.session.commit()
        other_acc = WaasAccount(user_id=other.id, account_name='Not Yours', is_active=True)
        other_acc.api_key = 'k'
        db.session.add(other_acc)
        db.session.commit()

        requester = User(username='fp-action-requester', email='fp-action-requester@example.com', role='user', is_active=True)
        requester.set_password('x')
        db.session.add(requester)
        db.session.commit()
        _login_as(client, requester)

        stub = StubWaasClient()
        monkeypatch.setattr('app.routes.logs.WaasClient.from_account', lambda acc: stub)

        resp = client.post(
            f'/logs/{other_acc.id}/app1.example.com/fp-allow-rule',
            data={'rule_name': 'fp-allow-r1', 'url_match': '/checkout'},
        )

        assert resp.status_code == 302
        assert stub.created == []
        assert ConfigSnapshot.query.filter_by(resource_type='fp_url_allow_create').count() == 0
