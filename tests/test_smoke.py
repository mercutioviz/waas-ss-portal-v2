"""Smoke tests — verify the app factory produces a runnable Flask app and
that the auth boundary behaves as expected. These are the first tests in the
v2 tree; adding a real feature should extend this file (or split it) rather
than delete these."""


def test_app_factory_produces_testing_app(app):
    assert app.testing is True
    assert 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI']


def test_login_page_renders(client):
    resp = client.get('/auth/login')
    assert resp.status_code == 200
    assert b'<form' in resp.data


def test_dashboard_requires_auth(client):
    resp = client.get('/dashboard', follow_redirects=False)
    assert resp.status_code == 302
    assert '/auth/login' in resp.headers.get('Location', '')
