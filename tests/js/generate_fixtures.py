#!/usr/bin/env python3
"""Generate test fixtures for the config transformer JS tests.

Run from the project root:
    python3 tests/js/generate_fixtures.py

Writes two files next to this script:
    constants.json   — SECTION_DEFINITIONS + STRIP_CONSTANTS (mirrors what Flask
                       injects into the template at render time)
    fixtures.json    — test cases: each has input, selections, and the Python-
                       computed expected output so JS tests can cross-validate.
"""
import json, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from app.config_transformer import (
    SECTION_DEFINITIONS,
    SERVER_RUNTIME_STRIP,
    ENDPOINT_CERT_ALWAYS_STRIP,
    ENDPOINT_PORT_ALWAYS_STRIP,
    get_section_metadata,
    transform_config,
)

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# 1. constants.json
# ---------------------------------------------------------------------------
strip_constants = {
    'server_runtime': sorted(SERVER_RUNTIME_STRIP),
    'endpoint_cert':  sorted(ENDPOINT_CERT_ALWAYS_STRIP),
    'endpoint_port':  sorted(ENDPOINT_PORT_ALWAYS_STRIP),
}
constants = {
    'SECTION_DEFINITIONS': SECTION_DEFINITIONS,
    'STRIP_CONSTANTS': strip_constants,
}
with open(os.path.join(HERE, 'constants.json'), 'w') as f:
    json.dump(constants, f, indent=2)
print('Wrote constants.json')

# ---------------------------------------------------------------------------
# 2. fixtures.json — test inputs with Python-computed expected outputs
# ---------------------------------------------------------------------------

# ------ shared sample data -------------------------------------------------

SAMPLE_ENDPOINTS = {
    'https': {'tls_10': False, 'tls_11': False, 'tls_12': True, 'tls_13': True},
    'advanced': {'session_timeout': 60, 'enable_http2': True},
    'ports': [
        {
            'protocol': 'HTTPS',
            'port': 443,
            'ca_name': 'Let\'s Encrypt (Barracuda Managed)',
            'waf_container_exposed_port': 32768,
            'advanced_configuration': {'session_timeout': 60},
        },
        {
            'protocol': 'HTTP',
            'port': 80,
            'ca_name': None,
            'waf_container_exposed_port': 32769,
        },
    ],
    'certificate': {
        'ssl_certificate': 'CERT_PEM_DATA',
        'encrypted_ssl_private_key': 'ENC_KEY_DATA',
        'aes_key_encrypted': 'AES_ENC',
        'aes_key_customer_container': 'AES_CC',
        'ssl_private_key_customer_container': 'PK_CC',
        'use_automatic': True,
        'enable_container_secret': False,
    },
    'deployment': {'primary_region': 'westus', 'secondary_region': 'eastus'},
    'domains': ['www.example.com', 'api.example.com'],
    'sni_certificates': [],           # empty — present=False
    'cname': 'app123.waas.example.com',  # always stripped at app level
}

SAMPLE_SERVERS = [
    {
        'name': 'backend-primary',
        'host': '10.0.0.10',
        'port': 8080,
        'health': 'up',              # runtime — stripped
        'mode': 'active',            # runtime — stripped
        'backend_test_result': 'ok', # runtime — stripped
        'viewed_backend_result': True,
        'last_test_time': 1700000000,
        'testing_backend_connectivity': False,
        'ssl_to_backend': False,
    },
    {
        'name': 'backend-secondary',
        'host': '10.0.0.11',
        'port': 8080,
        'health': 'down',
        'mode': 'standby',
        'ssl_to_backend': True,
    },
]

SAMPLE_ALLOWED_IPS = [
    {'ip': '192.168.1.0/24', 'note': 'Corporate LAN'},
    {'ip': '10.0.0.0/8',     'note': 'Internal VPN'},
    {'ip': '203.0.113.5',    'note': ''},
]

SAMPLE_CLIENT_EVAL = {
    'captcha_type': 'reCAPTCHA',
    'client_risk_score': True,
    'rules': [
        {'name': 'block-bots',   'threshold': 80, 'action': 'block'},
        {'name': 'captcha-mid',  'threshold': 50, 'action': 'captcha'},
        {'name': 'allow-clean',  'threshold': 20, 'action': 'allow'},
    ],
}

SAMPLE_IP_REPUTATION = {
    'geo_blocking': True,
    'exceptions': [
        {'ip': '1.2.3.4', 'comment': 'Partner IP'},
        {'ip': '5.6.7.8', 'comment': ''},
    ],
}

SAMPLE_RESPONSE_PAGES = {
    'pages': [
        {'name': 'default-block',  'type': 'block',   'body': '<html>Blocked</html>'},
        {'name': 'captcha-page',   'type': 'captcha',  'body': '<html>CAPTCHA</html>'},
        {'name': 'error-page',     'type': 'error',    'body': '<html>Error</html>'},
    ],
}

FULL_CONFIG = {
    'endpoints':               SAMPLE_ENDPOINTS,
    'servers':                 SAMPLE_SERVERS,
    'allowed_ips':             SAMPLE_ALLOWED_IPS,
    'blocked_bots':            {'search_engines': False, 'scanners': True, 'scrapers': True},
    'client_evaluation':       SAMPLE_CLIENT_EVAL,
    'ip_reputation':           SAMPLE_IP_REPUTATION,
    'request_limits':          {'max_url_length': 8192, 'max_query_string_length': 4096},
    'response_cloaking':       {'status_code_normalization': True},
    'response_page_component': SAMPLE_RESPONSE_PAGES,
    'slow_client_prevention':  {'min_data_rate': 100},
    'url_protection':          {'max_url_length': 2048, 'enabled': True},
    'violation_responses':     {
        'policies': [
            {'name': 'high-risk',  'threshold': 90, 'action': 'block'},
            {'name': 'medium-risk','threshold': 60, 'action': 'tarpit'},
        ],
    },
}

# ---------------------------------------------------------------------------
# Helper to build a fixture entry
# ---------------------------------------------------------------------------
def make_fixture(name, description, config, selections=None):
    sections = get_section_metadata(config)
    transformed = transform_config(config, selections) if selections is not None else None
    return {
        'name': name,
        'description': description,
        'config': config,
        'selections': selections,
        'expected_sections': sections,
        'expected_transform': transformed,
    }

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
fixtures = []

# 1. Empty config → no sections
fixtures.append(make_fixture(
    'empty_config',
    'Empty JSON object has no matching sections',
    config={},
))

# 2. Unknown keys → ignored
fixtures.append(make_fixture(
    'unknown_keys',
    'Keys not in SECTION_DEFINITIONS are silently ignored',
    config={'totally_unknown_key': {'foo': 'bar'}, 'url_protection': {'enabled': True}},
))

# 3. Simple section only
fixtures.append(make_fixture(
    'simple_section',
    'url_protection is a simple section (count=null, no items)',
    config={'url_protection': {'enabled': True, 'max_url_length': 8192}},
    selections={'url_protection': {'include': True}},
))

# 4. Simple section excluded
fixtures.append(make_fixture(
    'simple_section_excluded',
    'include=false means section is omitted from transform output',
    config={'url_protection': {'enabled': True}, 'request_limits': {'max_url_length': 8192}},
    selections={'url_protection': {'include': False}, 'request_limits': {'include': True}},
))

# 5. Named list — all servers (items=null)
fixtures.append(make_fixture(
    'servers_all',
    'Named list: all servers selected (items=null), runtime fields stripped',
    config={'servers': SAMPLE_SERVERS},
    selections={'servers': {'include': True, 'items': None}},
))

# 6. Named list — filtered servers
fixtures.append(make_fixture(
    'servers_filtered',
    'Named list: only selected server names included in transform output',
    config={'servers': SAMPLE_SERVERS},
    selections={'servers': {'include': True, 'items': ['backend-primary']}},
))

# 7. IP list — all items (items=null), label_fields join
fixtures.append(make_fixture(
    'allowed_ips_all',
    'IP list: all IPs, label joins ip+note with em dash',
    config={'allowed_ips': SAMPLE_ALLOWED_IPS},
    selections={'allowed_ips': {'include': True, 'items': None}},
))

# 8. IP list — filtered
fixtures.append(make_fixture(
    'allowed_ips_filtered',
    'IP list: only selected IPs in transform output',
    config={'allowed_ips': SAMPLE_ALLOWED_IPS},
    selections={'allowed_ips': {'include': True, 'items': ['10.0.0.0/8', '203.0.113.5']}},
))

# 9. Subsection — all items (items=null), non-list fields preserved
fixtures.append(make_fixture(
    'client_eval_all',
    'Subsection: all rules, non-list fields (captcha_type) preserved',
    config={'client_evaluation': SAMPLE_CLIENT_EVAL},
    selections={'client_evaluation': {'include': True, 'items': None}},
))

# 10. Subsection — filtered items
fixtures.append(make_fixture(
    'client_eval_filtered',
    'Subsection: filtered rules, captcha_type still present',
    config={'client_evaluation': SAMPLE_CLIENT_EVAL},
    selections={'client_evaluation': {'include': True, 'items': ['block-bots', 'allow-clean']}},
))

# 11. Subsection — ip_reputation has label_fields=['ip','comment']
fixtures.append(make_fixture(
    'ip_reputation_labels',
    'Subsection with label_fields: items use ip+comment join',
    config={'ip_reputation': SAMPLE_IP_REPUTATION},
))

# 12. Endpoints — parse: sub-section present flags
fixtures.append(make_fixture(
    'endpoints_present_flags',
    'Endpoints: present=True for populated sub-sections, sni_certificates=False when empty',
    config={'endpoints': SAMPLE_ENDPOINTS},
))

# 13. Endpoints — transform: only https + advanced
fixtures.append(make_fixture(
    'endpoints_https_advanced_only',
    'Endpoints transform: only https and advanced sub-sections selected',
    config={'endpoints': SAMPLE_ENDPOINTS},
    selections={'endpoints': {
        'include': True,
        'sub': {'https': True, 'advanced': True, 'ports': False,
                'certificate': False, 'deployment': False, 'domains': False, 'sni_certificates': False},
    }},
))

# 14. Endpoints — certificate fields stripped
fixtures.append(make_fixture(
    'endpoints_cert_strip',
    'Endpoints transform: certificate sub-section strips encrypted key material',
    config={'endpoints': SAMPLE_ENDPOINTS},
    selections={'endpoints': {
        'include': True,
        'sub': {'https': False, 'advanced': False, 'ports': False,
                'certificate': True, 'deployment': False, 'domains': False, 'sni_certificates': False},
    }},
))

# 15. Endpoints — port fields stripped (ca_name, waf_container_exposed_port)
fixtures.append(make_fixture(
    'endpoints_port_strip',
    'Endpoints transform: ports sub-section strips ca_name and container port',
    config={'endpoints': SAMPLE_ENDPOINTS},
    selections={'endpoints': {
        'include': True,
        'sub': {'https': False, 'advanced': False, 'ports': True,
                'certificate': False, 'deployment': False, 'domains': False, 'sni_certificates': False},
    }},
))

# 16. Endpoints — sni_certificates empty → not present
fixtures.append(make_fixture(
    'endpoints_sni_empty',
    'sni_certificates present=False when list is empty',
    config={'endpoints': {**SAMPLE_ENDPOINTS, 'sni_certificates': []}},
))

# 17. Endpoints — sni_certificates populated → present
fixtures.append(make_fixture(
    'endpoints_sni_populated',
    'sni_certificates present=True when list has items',
    config={'endpoints': {**SAMPLE_ENDPOINTS, 'sni_certificates': [{'domain': 'alt.example.com'}]}},
))

# 18. Response pages — subsection with label_fields=['name','type']
fixtures.append(make_fixture(
    'response_pages_labels',
    'Response pages: label joins name+type, filtered to one page',
    config={'response_page_component': SAMPLE_RESPONSE_PAGES},
    selections={'response_page_component': {'include': True, 'items': ['captcha-page']}},
))

# 19. Full config — all sections selected
all_selected = {}
for key in FULL_CONFIG:
    section_meta = next((s for s in get_section_metadata(FULL_CONFIG) if s['key'] == key), None)
    if section_meta is None:
        continue
    if section_meta['type'] == 'endpoints':
        all_selected[key] = {'include': True, 'sub': {
            sub['key']: True for sub in section_meta.get('sub_sections', [])
        }}
    elif section_meta.get('items'):
        all_selected[key] = {'include': True, 'items': None}
    else:
        all_selected[key] = {'include': True}

fixtures.append(make_fixture(
    'full_config_all_selected',
    'Full config with all sections selected — integration cross-validation',
    config=FULL_CONFIG,
    selections=all_selected,
))

# 20. Empty selections → empty transform output
fixtures.append(make_fixture(
    'all_excluded',
    'All sections excluded → transform returns empty object',
    config={'url_protection': {'enabled': True}, 'request_limits': {'max_url_length': 8192}},
    selections={'url_protection': {'include': False}, 'request_limits': {'include': False}},
))

# ---------------------------------------------------------------------------
# Write output
# ---------------------------------------------------------------------------
with open(os.path.join(HERE, 'fixtures.json'), 'w') as f:
    json.dump(fixtures, f, indent=2)

print(f'Wrote fixtures.json ({len(fixtures)} test cases)')
