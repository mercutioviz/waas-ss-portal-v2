"""Pytest fixtures for the portal.

Sets SKIP_DB_INIT before importing the app so the factory's eager
create_all/seed block stays out of test setup — each test controls schema
lifecycle explicitly via the `db` fixture.
"""
import os

os.environ.setdefault('SKIP_DB_INIT', '1')

import pytest

from app import create_app, db as _db


@pytest.fixture
def app(tmp_path):
    """Flask app bound to a fresh per-test SQLite DB.

    Overrides SQLALCHEMY_DATABASE_URI to a file under pytest's tmp_path so
    tables persist across connections (in-memory SQLite doesn't, without extra
    pool wiring) and so each test starts with a clean DB.
    """
    app = create_app('testing')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{tmp_path}/test.db'

    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def db(app):
    """Access the SQLAlchemy handle inside an app context."""
    return _db
