#!/usr/bin/env python3
"""WaaS Self-Service Portal - Entry Point"""

import json
import os
from app import create_app, db, socketio
from app.models import User, Feature
from app.seed import seed_features  # moved out of this module so wsgi
                                     # can import it without triggering
                                     # a second create_app() call.

app = create_app()


@app.cli.command('init-db')
def init_db():
    """Initialize the database and create tables."""
    db.create_all()
    print('Database tables created.')


@app.cli.command('create-admin')
def create_admin():
    """Create the default admin user if it doesn't exist."""
    db.create_all()
    admin = User.query.filter_by(username='admin').first()
    if admin:
        print('Admin user already exists.')
    else:
        admin = User(
            username='admin',
            email='admin@localhost',
            first_name='Administrator',
            role='admin',
            is_active=True
        )
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()
        print('Admin user created. Username: admin, Password: admin')
        print('*** Change the default password immediately! ***')


@app.cli.command('run-reports')
def run_reports():
    """Run all due scheduled reports immediately."""
    from app.report_service import run_scheduled_reports
    run_scheduled_reports(app)
    print('Scheduled reports processed.')


@app.cli.command('cleanup-site-profiles')
def cleanup_site_profiles():
    """Delete profiler results older than the retention window immediately."""
    from app.background_tasks import run_site_profile_cleanup
    deleted = run_site_profile_cleanup(app)
    print(f'Deleted {deleted} site profile(s) older than the retention window.')


@app.cli.command('seed')
def seed():
    """Initialize DB and create admin user (convenience command)."""
    db.create_all()
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@localhost',
            first_name='Administrator',
            role='admin',
            is_active=True
        )
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()
        print('Database initialized with admin user.')
        print('Username: admin / Password: admin')
    else:
        print('Database already initialized. Admin user exists.')

    created = seed_features()
    if created:
        print(f'Seeded {created} predefined features.')
    else:
        print('Predefined features already exist.')


if __name__ == '__main__':
    # Auto-create tables on first run
    with app.app_context():
        db.create_all()
        # Create admin if no users exist
        if User.query.count() == 0:
            admin = User(
                username='admin',
                email='admin@localhost',
                first_name='Administrator',
                role='admin',
                is_active=True
            )
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
            print('Created default admin user (admin/admin)')

        # Seed predefined features
        created = seed_features()
        if created:
            print(f'Seeded {created} predefined features.')

    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '1') == '1'
    socketio.run(app, host='0.0.0.0', port=port, debug=debug, allow_unsafe_werkzeug=True)