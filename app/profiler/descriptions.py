"""One-sentence platform-level explanations for each ApplicationCreateForm field.

Distinct from the per-probe `rationale` produced by the recommender — a
description says what the WaaS setting DOES; the rationale says WHY we
chose the specific value for this specific site. The results page renders
both, side by side, so a user can decide whether to accept the default.

Kept in sync with app.forms.ApplicationCreateForm (app/forms.py:304).
"""

FIELD_DESCRIPTIONS: dict[str, str] = {
    'application_name': (
        'A human-friendly label for the WaaS application. Appears in the WaaS '
        'console, audit log, and reports. Does not affect traffic handling.'
    ),
    'hostname': (
        'The public domain end users type in the browser. WaaS answers TLS and '
        'HTTP requests for this hostname and forwards the good ones to the '
        'backend server.'
    ),
    'backend_ip': (
        'The origin server address WaaS forwards clean traffic to — the machine '
        'behind the WAF. This is not visible on the public URL and cannot be '
        'probed.'
    ),
    'backend_port': (
        'TCP port WaaS uses when it connects to the origin. Typically 443 for an '
        'HTTPS origin, 80 for HTTP.'
    ),
    'backend_type': (
        'Whether WaaS speaks HTTP or HTTPS to the origin. HTTPS is preferred '
        'end-to-end; HTTP is common when the WAF terminates TLS for an internal '
        'origin.'
    ),
    'malicious_traffic': (
        'Protection mode. Passive logs would-be blocks without disrupting traffic '
        '— use it while you tune. Active enforces — switch after you have clean '
        'logs.'
    ),
    'use_https': (
        'Create an HTTPS listener on port 443. End users connect here; WaaS '
        'terminates TLS.'
    ),
    'use_http': (
        'Create an HTTP listener on port 80. Even for HTTPS-only sites, the '
        'HTTP listener catches legacy links and lets the WAF redirect them '
        'cleanly.'
    ),
    'redirect_http': (
        'When the HTTP listener receives a request, respond with 301 to the '
        'HTTPS equivalent instead of forwarding cleartext to the origin.'
    ),
}
