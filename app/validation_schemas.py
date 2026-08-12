"""Validation schemas for AJAX endpoints."""

from app.validators import FieldValidator

# ---- Server Configuration ----

SERVER_FIELDS = {
    'host': FieldValidator('string', max_length=255),
    'port': FieldValidator('int', min_val=1, max_val=65535),
    'protocol': FieldValidator('string', allowed=['HTTP', 'HTTPS']),
    'weight': FieldValidator('int', min_val=1, max_val=256),
    'mode': FieldValidator('string', allowed=['In Service', 'Out of Service']),
    'is_backup': FieldValidator('bool'),
}

SERVER_SSL_FIELDS = {
    'protocol_tls_1_0_enabled': FieldValidator('bool'),
    'protocol_tls_1_1_enabled': FieldValidator('bool'),
    'protocol_tls_1_2_enabled': FieldValidator('bool'),
    'protocol_tls_1_3_enabled': FieldValidator('bool'),
    'validate_ssl_certificate': FieldValidator('bool'),
    'enable_http2': FieldValidator('bool'),
    'enable_sni': FieldValidator('bool'),
}

SERVER_HEALTH_FIELDS = {
    'enable_oob_health_checks': FieldValidator('bool'),
    'interval': FieldValidator('int', min_val=1, max_val=3600),
    'url': FieldValidator('string', max_length=2048),
    'method': FieldValidator('string', allowed=['GET', 'HEAD']),
    'status_code': FieldValidator('int', min_val=100, max_val=599),
}

SERVER_ADVANCED_FIELDS = {
    'max_connections': FieldValidator('int', min_val=0, max_val=100000),
    'max_requests': FieldValidator('int', min_val=0, max_val=100000),
    'timeout': FieldValidator('int', min_val=0, max_val=300),
    'connection_pooling': FieldValidator('bool'),
}

# ---- Endpoint / Frontend TLS Configuration ----

ENDPOINT_TLS_FIELDS = {
    'enable_ssl_3': FieldValidator('bool'),
    'enable_tls_1': FieldValidator('bool'),
    'enable_tls_1_1': FieldValidator('bool'),
    'enable_tls_1_2': FieldValidator('bool'),
    'enable_tls_1_3': FieldValidator('bool'),
    'enable_pfs': FieldValidator('bool'),
    'cipher_suite_name': FieldValidator('string', allowed=[
        'all',
        'mozilla_old_compatibility_suite',
        'mozilla_intermediate_compatibility_suite',
        'mozilla_modern_compatibility_suite',
        'custom',
    ]),
}

ENDPOINT_PORT_FIELDS = {
    'port': FieldValidator('int', min_val=1, max_val=65535),
    'enable_web_application_firewall': FieldValidator('bool'),
    'enable_http2': FieldValidator('bool'),
}

# ---- Security Configuration ----

SECURITY_BASIC_FIELDS = {
    'protection_mode': FieldValidator('string', allowed=['Active', 'Passive']),
}

REQUEST_LIMITS_FIELDS = {
    'max_request_length': FieldValidator('int', min_val=0, max_val=1048576),
    'max_request_line_length': FieldValidator('int', min_val=0, max_val=1048576),
    'max_url_length': FieldValidator('int', min_val=0, max_val=1048576),
    'max_number_of_headers': FieldValidator('int', min_val=0, max_val=1048576),
    'max_header_value_length': FieldValidator('int', min_val=0, max_val=1048576),
    'max_cookie_name_length': FieldValidator('int', min_val=0, max_val=1048576),
    'max_cookie_value_length': FieldValidator('int', min_val=0, max_val=1048576),
}

CLICKJACKING_FIELDS = {
    'enable_clickjack_prevention': FieldValidator('bool'),
    'allowed_origin': FieldValidator('string', max_length=2048),
}

DATA_THEFT_FIELDS = {
    'enabled': FieldValidator('bool'),
    'credit_cards': FieldValidator('bool'),
    'social_security_numbers': FieldValidator('bool'),
    'custom_identity_theft_type': FieldValidator('string', max_length=255),
    'directory_traversal': FieldValidator('bool'),
}

# ---- Bulk Security Actions ----

BULK_SECURITY_ACTIONS = [
    'protection_mode_active',
    'protection_mode_passive',
    'enable_tls_1_3',
    'disable_tls_1',
    'enable_pfs',
]

# ---- Schema lookup by section name ----

SECURITY_SECTION_SCHEMAS = {
    'basic_security': SECURITY_BASIC_FIELDS,
    'request_limits': REQUEST_LIMITS_FIELDS,
    'clickjacking_protection': CLICKJACKING_FIELDS,
    'data_theft_protection': DATA_THEFT_FIELDS,
}
