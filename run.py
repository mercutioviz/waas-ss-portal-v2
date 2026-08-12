#!/usr/bin/env python3
"""WaaS Self-Service Portal - Entry Point"""

import json
import os
from app import create_app, db, socketio
from app.models import User, Feature

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


def seed_features():
    """Seed predefined features (idempotent)."""
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        return 0

    predefined = [
        {
            'name': 'Harden TLS 1.2+',
            'description': 'Disable TLS 1.0 and 1.1, enable only TLS 1.2 and 1.3 for stronger encryption.',
            'category': 'Security Hardening',
            'api_endpoint': '/applications/{app_id}/endpoints/',
            'api_method': 'PATCH',
            'config_data': {
                'https': {
                    'enable_tls_1': False,
                    'enable_tls_1_1': False,
                    'enable_tls_1_2': True,
                    'enable_tls_1_3': True,
                    'enable_ssl_3': False,
                }
            },
        },
        {
            'name': 'Enable Active Protection',
            'description': 'Switch WAF protection mode from Passive (monitor) to Active (block malicious traffic).',
            'category': 'Security Hardening',
            'api_endpoint': '/applications/{app_id}/basic_security/',
            'api_method': 'PATCH',
            'config_data': {
                'protection_mode': 'Active',
            },
        },
        {
            'name': 'Strict Request Limits',
            'description': 'Apply restrictive request size limits to defend against oversized payloads and buffer overflow attacks.',
            'category': 'Security Hardening',
            'api_endpoint': '/applications/{app_id}/request_limits/',
            'api_method': 'PATCH',
            'config_data': {
                'max_request_length': 32768,
                'max_request_line_length': 4096,
                'max_number_of_headers': 50,
                'max_header_value_length': 4096,
                'max_number_of_cookies': 20,
                'max_cookie_value_length': 2048,
            },
        },
        {
            'name': 'Enable Clickjacking Protection',
            'description': 'Enable clickjacking prevention by adding X-Frame-Options and Content-Security-Policy frame-ancestors headers.',
            'category': 'Compliance',
            'api_endpoint': '/applications/{app_id}/clickjacking_protection/',
            'api_method': 'PATCH',
            'config_data': {
                'status': 'On',
                'options': 'Same Origin',
            },
        },
        {
            'name': 'Enable Data Theft Protection',
            'description': 'Enable masking of credit card numbers and Social Security Numbers in HTTP responses.',
            'category': 'Compliance',
            'api_endpoint': '/applications/{app_id}/data_theft_protection/',
            'api_method': 'PATCH',
            'config_data': {
                'status': 'On',
                'credit_card_numbers': 'On',
                'social_security_numbers': 'On',
            },
        },
    ]

    created = 0
    updated = 0
    for feat_data in predefined:
        existing = Feature.query.filter_by(name=feat_data['name'], is_predefined=True).first()
        if not existing:
            feature = Feature(
                user_id=admin.id,
                name=feat_data['name'],
                description=feat_data['description'],
                category=feat_data['category'],
                is_global=True,
                is_predefined=True,
                api_endpoint=feat_data.get('api_endpoint', '/applications/{app_id}/import/'),
                api_method=feat_data.get('api_method', 'PATCH'),
            )
            feature.config_dict = feat_data['config_data']
            db.session.add(feature)
            created += 1
        else:
            # Update existing predefined features with api_endpoint, api_method, and config
            changed = False
            new_endpoint = feat_data.get('api_endpoint', '/applications/{app_id}/import/')
            new_method = feat_data.get('api_method', 'PATCH')
            if existing.api_endpoint != new_endpoint:
                existing.api_endpoint = new_endpoint
                changed = True
            if existing.api_method != new_method:
                existing.api_method = new_method
                changed = True
            new_config = json.dumps(feat_data['config_data'], indent=2)
            if existing.config_data != new_config:
                existing.config_dict = feat_data['config_data']
                changed = True
            if changed:
                updated += 1

    if created or updated:
        db.session.commit()
    return created


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