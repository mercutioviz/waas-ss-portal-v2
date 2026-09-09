"""Tests for Phase 4 — baseline/template comparison:
templates.compare_baseline() route, which diffs a live app's security config
against a ConfigTemplate baseline by reusing applications/compare.html."""

import pytest

from app.models import User, WaasAccount, ConfigTemplate
from app.waas_client import WaasApiError


class StubWaasClient:
    """Minimal stub standing in for WaasClient used by compare_baseline()."""

    def __init__(self, security_config=None, config_error=None):
        self.security_config = security_config if security_config is not None else {
            'protection_mode': 'Active',
            'request_limits': {'max_url_length': 8192},
        }
        self.config_error = config_error

    def get_security_config(self, app_id):
        if self.config_error:
            raise self.config_error
        return self.security_config


@pytest.fixture
def user(app, db):
    u = User(username='baseline-tester', email='baseline@example.com', role='user', is_active=True)
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
def template(app, db, user):
    t = ConfigTemplate(user_id=user.id, name='Baseline Hardened')
    t.config_dict = {
        'protection_mode': 'Active',
        'request_limits': {'max_url_length': 4096},
    }
    db.session.add(t)
    db.session.commit()
    return t


@pytest.fixture
def logged_in_client(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True
    return client


class TestCompareBaseline:
    def test_renders_diff_between_live_app_and_template(self, logged_in_client, account, template, monkeypatch):
        stub = StubWaasClient()
        monkeypatch.setattr('app.routes.templates.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(
            f'/templates/{template.id}/compare/{account.id}/app1.example.com'
        )

        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert 'app1.example.com' in body
        assert 'Baseline Hardened' in body
        # max_url_length differs (8192 vs 4096) -> should render both values
        assert '8192' in body
        assert '4096' in body

    def test_returns_404_for_nonexistent_template(self, logged_in_client, account):
        resp = logged_in_client.get(f'/templates/9999/compare/{account.id}/app1.example.com')
        assert resp.status_code == 404

    def test_redirects_for_template_owned_by_another_user(self, logged_in_client, app, db, account):
        other = User(username='other-owner', email='other-owner@example.com', role='user', is_active=True)
        other.set_password('x')
        db.session.add(other)
        db.session.commit()
        other_template = ConfigTemplate(user_id=other.id, name='Not Yours', is_global=False)
        other_template.config_dict = {}
        db.session.add(other_template)
        db.session.commit()

        resp = logged_in_client.get(f'/templates/{other_template.id}/compare/{account.id}/app1.example.com')
        assert resp.status_code == 302

    def test_redirects_for_unowned_account(self, logged_in_client, app, db, template):
        other = User(username='other-acct-owner', email='other-acct@example.com', role='user', is_active=True)
        other.set_password('x')
        db.session.add(other)
        db.session.commit()
        other_acc = WaasAccount(user_id=other.id, account_name='Not Yours', is_active=True)
        other_acc.api_key = 'k'
        db.session.add(other_acc)
        db.session.commit()

        resp = logged_in_client.get(f'/templates/{template.id}/compare/{other_acc.id}/app1.example.com')
        assert resp.status_code == 302

    def test_redirects_on_waas_api_error(self, logged_in_client, account, template, monkeypatch):
        stub = StubWaasClient(config_error=WaasApiError('upstream down'))
        monkeypatch.setattr('app.routes.templates.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(
            f'/templates/{template.id}/compare/{account.id}/app1.example.com'
        )
        assert resp.status_code == 302
