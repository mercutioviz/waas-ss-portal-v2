"""Tests for goal 5: persistent account scope (session-backed g.current_account,
navbar switcher, /accounts/switch) and the global search backend (/search/api)
that feeds the command palette."""
import pytest

from app.models import User, WaasAccount, ConfigTemplate
import app.routes.search as search_mod


@pytest.fixture(autouse=True)
def _clear_search_cache():
    # The in-process app/cert cache is keyed by account id, which restarts
    # from 1 in every fresh per-test SQLite DB — clear it so tests don't see
    # another test's cached (and possibly monkeypatched) results.
    search_mod._account_resource_cache.clear()
    yield
    search_mod._account_resource_cache.clear()


@pytest.fixture(autouse=True)
def _stub_waas_fetches(monkeypatch):
    # Accounts in these tests carry fake API keys — never let a search query
    # reach the real WaaS API. Individual tests override with real payloads
    # via their own monkeypatch.setattr call when they want app/cert hits.
    monkeypatch.setattr(search_mod, '_fetch_app_list', lambda acct: [])
    monkeypatch.setattr(search_mod, '_fetch_cert_list', lambda acct: [])


@pytest.fixture
def user(app, db):
    u = User(username='scope-tester', email='scope@example.com', role='user', is_active=True)
    u.set_password('x')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def other_user(app, db):
    u = User(username='scope-other', email='scope-other@example.com', role='user', is_active=True)
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
def other_account(app, db, other_user):
    acc = WaasAccount(user_id=other_user.id, account_name='Not Yours', is_active=True)
    acc.api_key = 'k'
    db.session.add(acc)
    db.session.commit()
    return acc


@pytest.fixture
def logged_in_client(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True
    return client


class TestPersistentAccountScope:
    def test_single_account_is_auto_selected_into_session(self, logged_in_client, account):
        resp = logged_in_client.get('/dashboard')
        assert resp.status_code == 200
        with logged_in_client.session_transaction() as sess:
            assert sess.get('current_account_id') == account.id

    def test_foreign_account_id_in_session_is_rejected(self, logged_in_client, other_account):
        with logged_in_client.session_transaction() as sess:
            sess['current_account_id'] = other_account.id

        resp = logged_in_client.get('/dashboard')

        assert resp.status_code == 200
        with logged_in_client.session_transaction() as sess:
            assert sess.get('current_account_id') != other_account.id

    def test_switch_account_sets_session_for_owned_account(self, logged_in_client, account):
        resp = logged_in_client.post(
            '/accounts/switch', data={'account_id': account.id, 'next': '/dashboard'}
        )
        assert resp.status_code == 302
        with logged_in_client.session_transaction() as sess:
            assert sess.get('current_account_id') == account.id

    def test_switch_account_rejects_account_owned_by_another_user(self, logged_in_client, other_account):
        resp = logged_in_client.post(
            '/accounts/switch', data={'account_id': other_account.id, 'next': '/dashboard'}
        )
        assert resp.status_code == 302
        with logged_in_client.session_transaction() as sess:
            assert sess.get('current_account_id') != other_account.id

    def test_switch_account_ignores_off_site_next_url(self, logged_in_client, account):
        resp = logged_in_client.post(
            '/accounts/switch',
            data={'account_id': account.id, 'next': 'https://evil.example.com/'},
        )
        assert resp.status_code == 302
        assert resp.headers['Location'] not in ('https://evil.example.com/',)


class TestGlobalSearch:
    def test_short_queries_return_no_results(self, logged_in_client, account):
        resp = logged_in_client.get('/search/api', query_string={'q': 'a'})
        assert resp.status_code == 200
        assert resp.get_json() == {'results': []}

    def test_finds_owned_template_by_name(self, app, db, logged_in_client, user, account):
        tpl = ConfigTemplate(user_id=user.id, name='Zero Trust Baseline', config_data='{}')
        db.session.add(tpl)
        db.session.commit()

        resp = logged_in_client.get('/search/api', query_string={'q': 'zero trust'})
        results = resp.get_json()['results']

        assert any(r['category'] == 'Templates' and r['title'] == 'Zero Trust Baseline' for r in results)

    def test_does_not_leak_other_users_templates(self, app, db, logged_in_client, other_user, account):
        tpl = ConfigTemplate(user_id=other_user.id, name='Not Mine Template', config_data='{}')
        db.session.add(tpl)
        db.session.commit()

        resp = logged_in_client.get('/search/api', query_string={'q': 'not mine'})
        results = resp.get_json()['results']

        assert results == []

    def test_account_results_carry_a_switch_action_not_a_url(self, logged_in_client, account):
        resp = logged_in_client.get('/search/api', query_string={'q': 'acme'})
        results = resp.get_json()['results']

        acct_hits = [r for r in results if r['category'] == 'Accounts']
        assert acct_hits
        assert acct_hits[0]['action'] == 'switch_account'
        assert acct_hits[0]['account_id'] == account.id
        assert acct_hits[0]['url'] is None

    def test_applications_are_scoped_to_the_current_account(self, logged_in_client, account, monkeypatch):
        monkeypatch.setattr(search_mod, '_fetch_app_list', lambda acct: [{'name': 'shop.example.com'}])
        with logged_in_client.session_transaction() as sess:
            sess['current_account_id'] = account.id

        resp = logged_in_client.get('/search/api', query_string={'q': 'shop'})
        results = resp.get_json()['results']

        assert any(r['category'] == 'Applications' and r['title'] == 'shop.example.com' for r in results)

    def test_no_application_results_without_a_scoped_account(self, app, db, logged_in_client, user, account, monkeypatch):
        # A second owned account means auto-select doesn't kick in, so no
        # account is in scope — Applications/Certificates must stay silent
        # rather than guessing which account's apps to search.
        second = WaasAccount(user_id=user.id, account_name='Second Acme', is_active=True)
        second.api_key = 'k2'
        db.session.add(second)
        db.session.commit()
        monkeypatch.setattr(search_mod, '_fetch_app_list', lambda acct: [{'name': 'shop.example.com'}])

        resp = logged_in_client.get('/search/api', query_string={'q': 'shop'})
        results = resp.get_json()['results']

        assert results == []
