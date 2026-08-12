"""WaaS Config Transformer — parse, filter, and clean WaaS export JSON for merge import.

All transform logic lives here; no Flask imports.  The Flask routes in
applications.py call get_section_metadata() and transform_config() and pass
results back to the template / AJAX caller.
"""

# ---------------------------------------------------------------------------
# Fields that are ALWAYS stripped — never safe to import to a target app.
# Documented here as the canonical reference.
# ---------------------------------------------------------------------------

# endpoints.cname is auto-assigned per account/app — meaningless on target.
ENDPOINT_ROOT_ALWAYS_STRIP = {'cname'}

# Certificate fields that are encrypted with source-account AES keys — cannot
# be decrypted by the target account.  use_automatic and enable_container_secret
# are boolean management flags and are kept when the certificate sub-section is selected.
ENDPOINT_CERT_ALWAYS_STRIP = {
    'ssl_certificate',
    'encrypted_ssl_private_key',
    'aes_key_encrypted',
    'aes_key_customer_container',
    'ssl_private_key_customer_container',
}

# Per-port fields: ca_name is WaaS-managed (Let's Encrypt assignment is automatic);
# waf_container_exposed_port is an internal infrastructure port auto-assigned per container.
ENDPOINT_PORT_ALWAYS_STRIP = {'ca_name', 'waf_container_exposed_port'}

# Server runtime fields: represent live operational state, not configuration.
SERVER_RUNTIME_STRIP = {
    'health',
    'mode',
    'backend_test_result',
    'viewed_backend_result',
    'last_test_time',
    'testing_backend_connectivity',
}

# ---------------------------------------------------------------------------
# Section definitions — single source of truth for UI metadata and transform logic.
# ---------------------------------------------------------------------------

SECTION_DEFINITIONS = [
    {
        'key': 'endpoints',
        'label': 'Endpoints',
        'type': 'endpoints',
        'description': 'Port configuration, TLS version policy, WAF toggles, and certificate assignment.',
        'always_strip_note': (
            'Certificate/key material (ssl_certificate, encrypted_ssl_private_key, AES keys) '
            'and the app CNAME are always removed. Per-port ca_name and waf_container_exposed_port '
            'are also always stripped.'
        ),
        'sub_sections': [
            {
                'key': 'https',
                'label': 'TLS Version Settings',
                'caution': False,
                'note': 'TLS 1.0–1.3 enable flags, cipher suite, PFS — safe to import.',
            },
            {
                'key': 'advanced',
                'label': 'Advanced WAF / Session Settings',
                'caution': False,
                'note': 'Session timeout, HTTP/2, WebSocket, fingerprinting, proxy-list toggles.',
            },
            {
                'key': 'ports',
                'label': 'Port Definitions',
                'caution': False,
                'note': 'Port number, protocol, per-port advanced config. ca_name and container port stripped.',
            },
            {
                'key': 'certificate',
                'label': 'Certificate Management Flags',
                'caution': True,
                'warning': (
                    'Only use_automatic and enable_container_secret are included — '
                    'all certificate/key material is always stripped.'
                ),
            },
            {
                'key': 'deployment',
                'label': 'Region / Deployment Settings',
                'caution': True,
                'warning': 'Primary/secondary region selection is account-level — may conflict with target.',
            },
            {
                'key': 'domains',
                'label': 'Domain List',
                'caution': True,
                'warning': 'Source app domains — almost certainly wrong for a different target app.',
            },
            {
                'key': 'sni_certificates',
                'label': 'SNI Certificates',
                'caution': True,
                'warning': 'May contain certificate material encrypted for the source account.',
            },
        ],
    },
    {
        'key': 'servers',
        'label': 'Servers',
        'type': 'named_list',
        'id_field': 'name',
        'description': 'Backend server host/port, SSL to backend, health check config, and connection pool settings.',
        'always_strip_note': 'Runtime fields (health, mode, backend_test_result, last_test_time) always stripped.',
    },
    {
        'key': 'allowed_ips',
        'label': 'Allowed IPs',
        'type': 'ip_list',
        'id_field': 'ip',
        'label_fields': ['ip', 'note'],
        'description': 'Client IP/CIDR entries that bypass WAF inspection.',
    },
    {
        'key': 'blocked_bots',
        'label': 'Bot Blocking',
        'type': 'simple',
        'description': 'Bot category blocking toggles (search engines, scrapers, scanners, GenAI, etc.).',
    },
    {
        'key': 'client_evaluation',
        'label': 'Client Evaluation (CAPTCHA)',
        'type': 'subsection',
        'list_field': 'rules',
        'id_field': 'name',
        'description': 'CAPTCHA type, client risk scoring rules, and mouse-event detection.',
    },
    {
        'key': 'header_allow_deny',
        'label': 'Header Allow/Deny Rules',
        'type': 'subsection',
        'list_field': 'rules',
        'id_field': 'name',
        'description': 'Per-header injection detection, metacharacter blocking, and exception patterns.',
    },
    {
        'key': 'ip_reputation',
        'label': 'IP Reputation',
        'type': 'subsection',
        'list_field': 'exceptions',
        'id_field': 'ip',
        'label_fields': ['ip', 'comment'],
        'description': 'GeoIP blocking, threat-intelligence categories, and per-IP allow exceptions.',
    },
    {
        'key': 'parameter_protection',
        'label': 'Parameter Protection',
        'type': 'simple',
        'description': 'Request parameter validation, file upload limits, and injection detection for parameters.',
    },
    {
        'key': 'referer_spam',
        'label': 'Referer Spam',
        'type': 'simple',
        'description': 'Referer spam detection toggle and exception patterns.',
    },
    {
        'key': 'request_limits',
        'label': 'Request Limits',
        'type': 'simple',
        'description': 'Maximum lengths for URL, query string, headers, cookies, and total request body.',
    },
    {
        'key': 'response_cloaking',
        'label': 'Response Cloaking',
        'type': 'simple',
        'description': 'Status code normalisation and sensitive response header suppression.',
    },
    {
        'key': 'response_page_component',
        'label': 'Response Pages',
        'type': 'subsection',
        'list_field': 'pages',
        'id_field': 'name',
        'label_fields': ['name', 'type'],
        'description': 'Custom HTML pages for blocked requests, CAPTCHA, login flows, and error responses.',
    },
    {
        'key': 'slow_client_prevention',
        'label': 'Slow Client Prevention',
        'type': 'simple',
        'description': 'Timeouts and minimum data-rate thresholds for slow HTTP attack mitigation.',
    },
    {
        'key': 'tarpit_profile',
        'label': 'Tarpit Profile',
        'type': 'simple',
        'description': 'Request backlog limit and delay interval for tarpitting abusive clients.',
    },
    {
        'key': 'trusted_hosts',
        'label': 'Trusted Hosts',
        'type': 'subsection',
        'list_field': 'trusted_hosts',
        'id_field': 'hostname',
        'label_fields': ['hostname', 'note'],
        'description': 'Named IP entries that bypass WAF inspection (internal load balancers, monitoring, etc.).',
    },
    {
        'key': 'url_access_and_redirects',
        'label': 'URL Access & Redirect Rules',
        'type': 'subsection',
        'list_field': 'url_adrs',
        'id_field': 'name',
        'description': 'URL-level allow, deny, and redirect rules with extended match conditions.',
    },
    {
        'key': 'url_protection',
        'label': 'URL Protection',
        'type': 'simple',
        'description': 'Allowed HTTP methods, content types, CSRF protection, and URL-level injection detection.',
    },
    {
        'key': 'violation_responses',
        'label': 'Violation Responses',
        'type': 'subsection',
        'list_field': 'policies',
        'id_field': 'name',
        'description': 'Actions (block, tarpit, redirect) triggered when WAF violation risk scores exceed thresholds.',
    },
    {
        'key': 'web_scraping_policy',
        'label': 'Web Scraping Policy',
        'type': 'subsection',
        'list_field': 'web_scraping_policies',
        'id_field': 'name',
        'description': 'Bot scraping detection, hidden link injection, and JavaScript challenge settings.',
    },
    {
        'key': 'website_profile',
        'label': 'Website Profile (Content Profiles)',
        'type': 'subsection',
        'list_field': 'app_profiles',
        'id_field': 'name',
        'description': 'URL-matched content type profiles for JSON, XML, and custom input validation policies.',
    },
]

# Fast lookup by key
_SECTION_BY_KEY = {s['key']: s for s in SECTION_DEFINITIONS}


# ---------------------------------------------------------------------------
# JSON error helpers
# ---------------------------------------------------------------------------

def json_error_excerpt(content, pos, context=60):
    """Return a short snippet around a JSON parse error position.

    The character at `pos` is marked with ▶ so the caller can show
    the user exactly where the parser choked.
    """
    start = max(0, pos - context)
    end = min(len(content), pos + context)
    before = content[start:pos]
    after = content[pos:end]
    if start > 0:
        before = '…' + before
    if end < len(content):
        after = after + '…'
    return before + '▶' + after


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_section_metadata(parsed_json):
    """Return UI metadata for every section present in parsed_json.

    Called by the /parse route.  Returns a list of dicts that the
    config_transformer.html template / JavaScript uses to render the
    section selector.
    """
    result = []
    for defn in SECTION_DEFINITIONS:
        key = defn['key']
        if key not in parsed_json:
            continue

        section_data = parsed_json[key]
        meta = {
            'key': key,
            'label': defn['label'],
            'type': defn['type'],
            'description': defn['description'],
            'always_strip_note': defn.get('always_strip_note'),
        }

        if defn['type'] == 'endpoints':
            meta['sub_sections'] = []
            for sub in defn['sub_sections']:
                sub_key = sub['key']
                present = sub_key in section_data
                if sub_key == 'sni_certificates':
                    present = bool(section_data.get('sni_certificates'))
                meta['sub_sections'].append({
                    'key': sub_key,
                    'label': sub['label'],
                    'caution': sub.get('caution', False),
                    'note': sub.get('note'),
                    'warning': sub.get('warning'),
                    'present': present,
                })

        elif defn['type'] == 'named_list':
            items = section_data if isinstance(section_data, list) else []
            id_field = defn['id_field']
            meta['count'] = len(items)
            meta['items'] = [
                {'id': item.get(id_field, str(i)), 'label': item.get(id_field, f'Item {i}')}
                for i, item in enumerate(items)
            ]

        elif defn['type'] == 'ip_list':
            items = section_data if isinstance(section_data, list) else []
            id_field = defn['id_field']
            label_fields = defn.get('label_fields', [id_field])
            meta['count'] = len(items)
            meta['items'] = [
                {
                    'id': item.get(id_field, str(i)),
                    'label': _join_label(item, label_fields),
                }
                for i, item in enumerate(items)
            ]

        elif defn['type'] == 'subsection':
            list_field = defn['list_field']
            id_field = defn['id_field']
            label_fields = defn.get('label_fields', [id_field])
            inner_list = section_data.get(list_field, []) if isinstance(section_data, dict) else []
            meta['count'] = len(inner_list)
            meta['list_field'] = list_field
            meta['items'] = [
                {
                    'id': item.get(id_field, str(i)),
                    'label': _join_label(item, label_fields),
                }
                for i, item in enumerate(inner_list)
            ]

        elif defn['type'] == 'simple':
            meta['count'] = None

        result.append(meta)
    return result


def transform_config(parsed_json, selections):
    """Apply selections to parsed_json and return a cleaned, import-ready dict.

    selections schema:
        {
            'endpoints': {
                'include': bool,
                'sub': {'https': bool, 'advanced': bool, 'ports': bool,
                        'certificate': bool, 'deployment': bool,
                        'domains': bool, 'sni_certificates': bool}
            },
            'servers': {'include': bool, 'items': list[str] | None},
            'allowed_ips': {'include': bool, 'items': list[str] | None},
            '<simple_key>': {'include': bool},
            '<subsection_key>': {'include': bool, 'items': list[str] | None},
        }

    items=None means "all items in the section".
    """
    result = {}

    for defn in SECTION_DEFINITIONS:
        key = defn['key']
        if key not in parsed_json:
            continue
        sel = selections.get(key, {})
        if not sel.get('include', False):
            continue

        section_type = defn['type']

        if section_type == 'simple':
            result[key] = parsed_json[key]

        elif section_type == 'named_list':
            # servers: strip runtime fields, filter by selected item names
            items = parsed_json[key] if isinstance(parsed_json[key], list) else []
            items = _filter_items(items, defn['id_field'], sel.get('items'))
            result[key] = [
                {k: v for k, v in item.items() if k not in SERVER_RUNTIME_STRIP}
                for item in items
            ]

        elif section_type == 'ip_list':
            items = parsed_json[key] if isinstance(parsed_json[key], list) else []
            result[key] = _filter_items(items, defn['id_field'], sel.get('items'))

        elif section_type == 'subsection':
            section_data = parsed_json[key]
            if not isinstance(section_data, dict):
                result[key] = section_data
                continue
            section_copy = dict(section_data)
            list_field = defn['list_field']
            id_field = defn['id_field']
            selected_items = sel.get('items')
            if list_field in section_copy and selected_items is not None:
                section_copy[list_field] = _filter_items(
                    section_copy[list_field], id_field, selected_items
                )
            result[key] = section_copy

        elif section_type == 'endpoints':
            ep = _transform_endpoints(parsed_json[key], sel.get('sub', {}))
            if ep:
                result[key] = ep

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _filter_items(items, id_field, selected_ids):
    """Return items whose id_field value is in selected_ids.
    If selected_ids is None, return all items unchanged.
    """
    if selected_ids is None:
        return items
    selected_set = set(selected_ids)
    return [item for item in items if item.get(id_field) in selected_set]


def _join_label(item, fields):
    """Build a display label from up to two non-empty fields."""
    parts = [str(item.get(f, '')) for f in fields if item.get(f)]
    return ' — '.join(parts[:2]) if parts else '(unnamed)'


def _transform_endpoints(endpoints_data, sub_selections):
    """Build a cleaned endpoints dict from selected sub-sections."""
    result = {}

    if sub_selections.get('https') and 'https' in endpoints_data:
        result['https'] = endpoints_data['https']

    if sub_selections.get('advanced') and 'advanced' in endpoints_data:
        result['advanced'] = endpoints_data['advanced']

    if sub_selections.get('ports') and 'ports' in endpoints_data:
        result['ports'] = [
            {k: v for k, v in port.items() if k not in ENDPOINT_PORT_ALWAYS_STRIP}
            for port in endpoints_data['ports']
        ]

    if sub_selections.get('certificate') and 'certificate' in endpoints_data:
        result['certificate'] = {
            k: v for k, v in endpoints_data['certificate'].items()
            if k not in ENDPOINT_CERT_ALWAYS_STRIP
        }

    if sub_selections.get('deployment') and 'deployment' in endpoints_data:
        result['deployment'] = endpoints_data['deployment']

    if sub_selections.get('domains') and 'domains' in endpoints_data:
        result['domains'] = endpoints_data['domains']

    if sub_selections.get('sni_certificates') and endpoints_data.get('sni_certificates'):
        result['sni_certificates'] = endpoints_data['sni_certificates']

    return result
