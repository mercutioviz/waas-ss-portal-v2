"""Idempotent seeding of predefined records.

Kept out of run.py so wsgi.py (and anything else that needs seeding
without spinning up a CLI-wired app instance) can import from here
without triggering run.py's module-level `app = create_app()` — that
side-effect double-inits Flask-SocketIO and silently unregisters the
handlers, which manifests as the profiler watch page never receiving
`profile_progress` events.

Must be called inside an active Flask app context.
"""

import json

from app import db
from app.models import Feature, User


PREDEFINED_FEATURES = [
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
        'config_data': {'protection_mode': 'Active'},
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
        'config_data': {'status': 'On', 'options': 'Same Origin'},
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


def seed_features() -> int:
    """Insert or update the predefined Feature rows. Idempotent.

    Returns the number of features created (updates don't count).
    """
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        return 0

    created = 0
    updated = 0
    for feat_data in PREDEFINED_FEATURES:
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
