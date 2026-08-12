"""WSGI entry point for production (Gunicorn)."""

from gevent import monkey
monkey.patch_all()

import os

os.environ.setdefault('FLASK_ENV', 'production')

from app import create_app, db, socketio
from app.models import User, Feature

app = create_app('production')

# Ensure tables exist and seed admin on first run
with app.app_context():
    db.create_all()
    if User.query.count() == 0:
        admin = User(
            username='admin',
            email='admin@localhost',
            first_name='Administrator',
            role='admin',
            is_active=True,
        )
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()
        app.logger.info('Created default admin user (admin/admin)')

    # Seed predefined features
    from run import seed_features
    created = seed_features()
    if created:
        app.logger.info(f'Seeded {created} predefined features.')
