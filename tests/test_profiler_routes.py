"""Smoke tests for the profiler blueprint. Background greenlets are
stubbed out — we're testing the request-time behavior only."""

import json

import pytest

from app.models import SiteProfile, User, WaasAccount


@pytest.fixture
def user(app, db):
    """A signed-in test user."""
    u = User(username='profiler-tester', email='pt@example.com', role='user', is_active=True)
    u.set_password('x')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def account(app, db, user):
    """A WaasAccount owned by `user`, with v2 credentials so the profiler
    treats it as create-capable."""
    acc = WaasAccount(user_id=user.id, account_name='Acme WaaS', is_active=True)
    acc.waas_email = 'ops@acme.example.com'
    acc.waas_password = 'secret'
    db.session.add(acc)
    db.session.commit()
    return acc


@pytest.fixture
def account_no_v2(app, db, user):
    """WaasAccount without v2 creds — profiler should refuse to start."""
    acc = WaasAccount(user_id=user.id, account_name='Legacy', is_active=True)
    acc.api_key = 'v4-only-key'
    db.session.add(acc)
    db.session.commit()
    return acc


@pytest.fixture
def logged_in_client(client, user):
    """Test client with the user logged in via Flask-Login session state."""
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True
    return client


@pytest.fixture
def spawn_stub(monkeypatch):
    """Prevent tests from launching real greenlets.

    Returns a list that will be populated with (fn, args) tuples for
    assertions.
    """
    calls = []
    def _fake_spawn(fn, *args, **kwargs):
        calls.append((fn.__name__, args, kwargs))
    monkeypatch.setattr(
        'app.routes.profiler.socketio.start_background_task',
        _fake_spawn,
    )
    return calls


class TestGetNewProfile:
    def test_auto_selects_when_user_has_one_v2_account(self, logged_in_client, account):
        # `account` fixture is the only v2-capable account for this user →
        # /profiler/new (no arg) should skip the picker and go straight in.
        resp = logged_in_client.get('/profiler/new', follow_redirects=False)
        assert resp.status_code == 302
        assert f'/profiler/new?account_id={account.id}' in resp.headers['Location']

    def test_shows_picker_when_multiple_v2_accounts(self, logged_in_client, account, db, user):
        # Add a second v2-capable account so the picker is the right response.
        second = WaasAccount(user_id=user.id, account_name='Beta WaaS', is_active=True)
        second.waas_email = 'ops@beta.example.com'
        second.waas_password = 'secret'
        db.session.add(second); db.session.commit()

        resp = logged_in_client.get('/profiler/new')
        assert resp.status_code == 200
        assert b'Acme WaaS' in resp.data
        assert b'Beta WaaS' in resp.data
        assert b'Which WaaS account' in resp.data

    def test_shows_no_accounts_template_when_no_v2_creds_anywhere(
        self, logged_in_client, account_no_v2,
    ):
        # Only a v4-key-only account exists — profiler cannot use it, so the
        # empty-state template should render with a link to manage accounts.
        resp = logged_in_client.get('/profiler/new')
        assert resp.status_code == 200
        assert b'No accounts with v2 credentials' in resp.data
        assert b'Manage accounts' in resp.data

    def test_404_on_foreign_account(self, logged_in_client, account):
        resp = logged_in_client.get(f'/profiler/new?account_id={account.id + 9999}')
        assert resp.status_code == 404

    def test_redirects_when_selected_account_has_no_v2_creds(
        self, logged_in_client, account_no_v2,
    ):
        # Passing an account_id that's real but not v2-capable → bounce back
        # to /profiler/new (which renders the picker or empty state).
        resp = logged_in_client.get(
            f'/profiler/new?account_id={account_no_v2.id}',
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert '/profiler/new' in resp.headers['Location']
        assert 'account_id' not in resp.headers['Location']

    def test_renders_form_with_valid_account(self, logged_in_client, account):
        resp = logged_in_client.get(f'/profiler/new?account_id={account.id}')
        assert resp.status_code == 200
        assert b'Profile a site' in resp.data
        assert b'target_url' in resp.data


class TestPostNewProfile:
    def test_creates_row_and_spawns_greenlet(self, logged_in_client, account, spawn_stub, db):
        resp = logged_in_client.post(
            f'/profiler/new?account_id={account.id}',
            data={'target_url': 'https://example.com/'},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert '/profiler/' in resp.headers['Location']
        assert '/watch' in resp.headers['Location']

        row = SiteProfile.query.first()
        assert row is not None
        assert row.target_url == 'https://example.com/'
        assert row.status == SiteProfile.STATUS_PENDING
        assert row.session_id
        assert len(spawn_stub) == 1
        assert spawn_stub[0][0] == 'run_site_profile'

    def test_bare_hostname_gets_https_scheme(self, logged_in_client, account, spawn_stub, db):
        resp = logged_in_client.post(
            f'/profiler/new?account_id={account.id}',
            data={'target_url': 'example.com'},
        )
        assert resp.status_code == 302
        row = SiteProfile.query.first()
        assert row.target_url == 'https://example.com'

    def test_cooldown_reuses_recent_profile(self, logged_in_client, account, spawn_stub, db):
        # First submission
        logged_in_client.post(
            f'/profiler/new?account_id={account.id}',
            data={'target_url': 'https://example.com/'},
        )
        first = SiteProfile.query.first()
        # Immediate re-submission
        resp = logged_in_client.post(
            f'/profiler/new?account_id={account.id}',
            data={'target_url': 'https://example.com/'},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert f'/profiler/{first.id}/watch' in resp.headers['Location']
        # Only one row + one greenlet spawn
        assert SiteProfile.query.count() == 1
        assert len(spawn_stub) == 1


class TestWatchProfile:
    def test_renders_watch_page(self, logged_in_client, account, db):
        row = SiteProfile(
            user_id=account.user_id, account_id=account.id,
            target_url='https://example.com/', status=SiteProfile.STATUS_PROBING,
            session_id='room-123',
        )
        db.session.add(row); db.session.commit()

        resp = logged_in_client.get(f'/profiler/{row.id}/watch')
        assert resp.status_code == 200
        assert b'room-123' in resp.data
        assert b'profile_progress' in resp.data

    def test_completed_profile_bounces_to_results(self, logged_in_client, account, db):
        row = SiteProfile(
            user_id=account.user_id, account_id=account.id,
            target_url='https://example.com/', status=SiteProfile.STATUS_COMPLETE,
            session_id='room-done',
        )
        db.session.add(row); db.session.commit()

        resp = logged_in_client.get(f'/profiler/{row.id}/watch', follow_redirects=False)
        assert resp.status_code == 302
        assert f'/profiler/{row.id}/results' in resp.headers['Location']

    def test_foreign_profile_is_404(self, logged_in_client, account, db):
        # Another user's profile — must not be visible.
        other = User(username='someone-else', email='e@e', role='user', is_active=True)
        other.set_password('x')
        db.session.add(other); db.session.commit()
        row = SiteProfile(
            user_id=other.id, account_id=account.id,
            target_url='https://example.com/', status=SiteProfile.STATUS_COMPLETE,
            session_id='room-foreign',
        )
        db.session.add(row); db.session.commit()

        resp = logged_in_client.get(f'/profiler/{row.id}/watch')
        assert resp.status_code == 404


class TestStatusEndpoint:
    def test_returns_status_and_redirect_when_complete(self, logged_in_client, account, db):
        row = SiteProfile(
            user_id=account.user_id, account_id=account.id,
            target_url='https://example.com/', status=SiteProfile.STATUS_COMPLETE,
            session_id='room-s1',
        )
        db.session.add(row); db.session.commit()

        resp = logged_in_client.get(f'/profiler/{row.id}/status')
        assert resp.status_code == 200
        assert resp.get_json()['status'] == 'complete'
        assert f'/profiler/{row.id}/results' in resp.get_json()['redirect_url']

    def test_reports_error_status(self, logged_in_client, account, db):
        row = SiteProfile(
            user_id=account.user_id, account_id=account.id,
            target_url='https://example.com/', status=SiteProfile.STATUS_ERROR,
            session_id='room-s2', error_message='cert expired',
        )
        db.session.add(row); db.session.commit()

        resp = logged_in_client.get(f'/profiler/{row.id}/status')
        payload = resp.get_json()
        assert payload['status'] == 'error'
        assert payload['error_message'] == 'cert expired'

    def test_probing_status_has_no_redirect(self, logged_in_client, account, db):
        row = SiteProfile(
            user_id=account.user_id, account_id=account.id,
            target_url='https://example.com/', status=SiteProfile.STATUS_PROBING,
            session_id='room-s3',
        )
        db.session.add(row); db.session.commit()

        payload = logged_in_client.get(f'/profiler/{row.id}/status').get_json()
        assert payload['status'] == 'probing'
        assert 'redirect_url' not in payload

    def test_foreign_profile_is_404(self, logged_in_client, account, db):
        other = User(username='other', email='o@o', role='user', is_active=True)
        other.set_password('x'); db.session.add(other); db.session.commit()
        row = SiteProfile(
            user_id=other.id, account_id=account.id,
            target_url='https://example.com/', status=SiteProfile.STATUS_COMPLETE,
            session_id='room-s4',
        )
        db.session.add(row); db.session.commit()

        resp = logged_in_client.get(f'/profiler/{row.id}/status')
        assert resp.status_code == 404


class TestResults:
    def test_renders_prefilled_form(self, logged_in_client, account, db):
        recommendation = {
            'form_fields': {
                'application_name': {'value': 'acme', 'rationale': 'Derived from hostname'},
                'hostname': {'value': 'acme.example.com', 'rationale': 'The URL you probed'},
                'backend_ip': {'value': '', 'rationale': 'You must supply the origin'},
                'backend_port': {'value': 443, 'rationale': 'HTTPS detected'},
                'backend_type': {'value': 'HTTPS', 'rationale': 'TLS OK'},
                'malicious_traffic': {'value': 'Passive', 'rationale': 'Start passive'},
                'use_https': {'value': True, 'rationale': 'TLS works'},
                'use_http': {'value': True, 'rationale': 'legacy links'},
                'redirect_http': {'value': True, 'rationale': 'follows the site'},
            },
            'advisories': [
                {'severity': 'info', 'title': 'WordPress detected', 'body': 'Consider a WP template'},
                {'severity': 'warning', 'title': 'Public IP is Cloudflare', 'body': 'Enter the origin, not the CDN IP'},
            ],
        }
        row = SiteProfile(
            user_id=account.user_id, account_id=account.id,
            target_url='https://acme.example.com/',
            status=SiteProfile.STATUS_COMPLETE,
            session_id='room-r',
        )
        row.recommendation = recommendation
        db.session.add(row); db.session.commit()

        resp = logged_in_client.get(f'/profiler/{row.id}/results')
        assert resp.status_code == 200
        # Field values pre-filled
        assert b'value="acme"' in resp.data
        assert b'value="acme.example.com"' in resp.data
        # Advisory titles surface
        assert b'WordPress detected' in resp.data
        assert b'Public IP is Cloudflare' in resp.data
        # Hidden profile_id present for audit-source tagging on submit
        assert f'value="{row.id}"'.encode() in resp.data
        assert b'name="profile_id"' in resp.data

    def test_incomplete_profile_bounces_to_watch(self, logged_in_client, account, db):
        row = SiteProfile(
            user_id=account.user_id, account_id=account.id,
            target_url='https://example.com/', status=SiteProfile.STATUS_PROBING,
            session_id='room-inc',
        )
        db.session.add(row); db.session.commit()

        resp = logged_in_client.get(f'/profiler/{row.id}/results', follow_redirects=False)
        assert resp.status_code == 302
        assert '/watch' in resp.headers['Location']
