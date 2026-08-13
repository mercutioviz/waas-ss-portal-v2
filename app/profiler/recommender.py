"""Turn a SiteProfile into ApplicationCreateForm defaults + advisory list.

Pure function of the profile — no I/O, trivial to unit test. The output
shape mirrors the field names of `app.forms.ApplicationCreateForm` so the
results template can pre-fill the form directly.

Each form-field entry now carries three pieces of information:
- `value`       what to prefill
- `description` what the WaaS setting DOES (static, from descriptions.py)
- `rationale`   why we chose THIS value for THIS site (dynamic per-probe)
"""

from urllib.parse import urlparse

from app.profiler.descriptions import FIELD_DESCRIPTIONS
from app.profiler.schemas import SiteProfile

# Allowlist guards against silent typos — if we ever emit a field name the
# form doesn't have, the pre-fill would drop it without error. Kept in sync
# with app.forms.ApplicationCreateForm (app/forms.py:304).
ALLOWED_FORM_FIELDS = frozenset({
    'application_name',
    'hostname',
    'backend_ip',
    'backend_port',
    'backend_type',
    'malicious_traffic',
    'use_https',
    'use_http',
    'redirect_http',
})

# Header names that indicate a WAF/edge vendor is already fronting the site.
# Distinct from the tech-detection path because the ADVICE is different:
# "there's already a WAF here, plan the WaaS deployment carefully" vs.
# "the origin runs nginx".
WAF_HEADER_MARKERS: list[tuple[str, str]] = [
    ('cf-ray', 'Cloudflare'),
    ('cf-cache-status', 'Cloudflare'),
    ('x-akamai-request-id', 'Akamai'),
    ('x-akamai-transformed', 'Akamai'),
    ('x-cache', 'Akamai (or generic reverse cache)'),
    ('x-iinfo', 'Imperva'),
    ('x-sucuri-id', 'Sucuri'),
    ('x-served-by', 'Fastly'),
    ('x-fastly-request-id', 'Fastly'),
    ('x-amz-cf-id', 'CloudFront'),
]


def _slugify_hostname(hostname: str) -> str:
    """`www.acme-corp.example.com` → `acme-corp`. Falls back to the raw
    hostname stripped of dots."""
    if not hostname:
        return 'new-app'
    parts = [p for p in hostname.split('.') if p]
    parts = [p for p in parts if p not in ('www',)]
    if not parts:
        return hostname.replace('.', '-')
    return parts[0] if len(parts) < 3 else parts[0]


def _detects_https_redirect(profile: SiteProfile) -> bool:
    http = profile.http_root
    if not http or not http.status:
        return False
    if http.status not in (301, 302, 307, 308):
        return False
    target = (http.redirect_target or '').lower()
    return target.startswith('https://')


def _looks_session_shaped(name: str) -> bool:
    """Best-effort heuristic — cookies whose name matches this list of
    common session shapes really ought to have HttpOnly."""
    lower = name.lower()
    return any(marker in lower for marker in (
        'session', 'sess', 'sid', 'auth', 'token', 'csrf', 'xsrf', 'login',
    ))


def _field(key: str, value, rationale: str) -> dict:
    return {
        'value': value,
        'description': FIELD_DESCRIPTIONS.get(key, ''),
        'rationale': rationale,
    }


def recommend(profile: SiteProfile) -> dict:
    """Return `{form_fields: {...}, advisories: [...]}` for the results page."""
    hostname = urlparse(profile.target_url).hostname or ''
    tls_ok = profile.tls.handshake_ok
    https_ok = (profile.https_root.status or 0) < 400 and not profile.https_root.error
    redirects_to_https = _detects_https_redirect(profile)
    is_https = urlparse(profile.target_url).scheme == 'https'

    form_fields: dict = {
        'application_name': _field(
            'application_name',
            _slugify_hostname(hostname),
            f'Derived from the hostname {hostname}. Rename to whatever your team calls this service.',
        ),
        'hostname': _field(
            'hostname',
            hostname,
            'The public hostname you probed. This is what end users type.',
        ),
        'backend_ip': _field(
            'backend_ip',
            '',
            'You must supply the origin server address (the backend the WAF forwards to). '
            'This cannot be probed from the public URL.',
        ),
        'backend_port': _field(
            'backend_port',
            443 if tls_ok else 80,
            'Detected HTTPS on port 443 — pointing the WAF at the same port keeps behavior consistent.'
            if tls_ok else
            'TLS was not reachable on 443 — falling back to plain HTTP on 80. Consider hardening the origin.',
        ),
        'backend_type': _field(
            'backend_type',
            'HTTPS' if tls_ok else 'HTTP',
            f'TLS {profile.tls.tls_version or ""} handshake succeeded with a valid certificate.'
            if tls_ok else
            'TLS was not reachable; falling back to HTTP for the backend protocol.',
        ),
        'malicious_traffic': _field(
            'malicious_traffic',
            'Passive',
            'Start in Passive so the WAF monitors without blocking. Review the log for false positives, '
            'then switch to Active after ~1–2 weeks of clean traffic.',
        ),
        'use_https': _field(
            'use_https',
            bool(tls_ok or https_ok),
            'TLS is working on your site, so end users should keep hitting HTTPS through the WAF.'
            if tls_ok else
            'Recommended even if the origin is HTTP-only — the WAF can terminate TLS for you.',
        ),
        'use_http': _field(
            'use_http',
            True,
            'Keep an HTTP endpoint so legacy links redirect cleanly to HTTPS via the WAF.',
        ),
        'redirect_http': _field(
            'redirect_http',
            True,
            'Your site already redirects HTTP → HTTPS; replicating that on the WAF endpoint keeps behavior identical.'
            if redirects_to_https else
            'Recommended by default — the WAF should redirect any HTTP request to HTTPS.',
        ),
    }

    _validate_field_names(form_fields)

    advisories: list[dict] = []

    # ── TLS ────────────────────────────────────────────────────────────
    if not tls_ok:
        advisories.append({
            'severity': 'warning',
            'title': 'TLS handshake failed',
            'body': (
                'We could not complete a TLS handshake with the origin. '
                f'Reason: {profile.tls.error or "unknown"}. '
                'Fix the origin cert before switching the WAF to Active mode.'
            ),
        })

    if profile.tls.tls_version and profile.tls.tls_version.startswith('TLSv1.') and profile.tls.tls_version < 'TLSv1.2':
        advisories.append({
            'severity': 'warning',
            'title': 'Legacy TLS version',
            'body': (
                f'Origin negotiated {profile.tls.tls_version}. Apply the "Harden TLS 1.2+" feature '
                'to the created app to force modern TLS on the WAF endpoint.'
            ),
        })

    # ── CDN / WAF fronting ─────────────────────────────────────────────
    if profile.cdn:
        advisories.append({
            'severity': 'warning',
            'title': f'Public IP resolves to {profile.cdn}',
            'body': (
                f'The hostname {hostname} resolves to a {profile.cdn} edge IP. '
                'The origin behind that CDN is what you must enter as the backend — '
                'do not use the resolved public IP.'
            ),
        })

    lower_headers = {k.lower(): v for k, v in (profile.https_root.headers or {}).items()}
    fronting_seen: set[str] = set()
    for marker, vendor in WAF_HEADER_MARKERS:
        if marker in lower_headers and vendor not in fronting_seen:
            fronting_seen.add(vendor)
            advisories.append({
                'severity': 'info',
                'title': f'Existing edge/WAF detected: {vendor}',
                'body': (
                    f'The response includes {marker!r} — traffic is currently going through '
                    f'{vendor}. If you deploy WaaS in front of the origin as well, plan the '
                    f'cutover so end users hit exactly one WAF layer.'
                ),
            })

    # ── Security headers ───────────────────────────────────────────────
    sec = profile.security_headers
    if is_https and sec.hsts is None:
        advisories.append({
            'severity': 'warning',
            'title': 'HSTS missing',
            'body': (
                'The origin does not send `Strict-Transport-Security`. HSTS locks browsers '
                'to HTTPS for future visits and prevents SSL-stripping downgrades.'
            ),
        })
    if sec.csp is None:
        advisories.append({
            'severity': 'info',
            'title': 'No Content-Security-Policy',
            'body': (
                'A CSP header restricts what the browser will execute — a strong defense-in-depth '
                'against XSS. Even a permissive baseline (`default-src * ''unsafe-inline''`) beats none.'
            ),
        })
    elif sec.csp and (sec.csp.get('has_unsafe_inline') or sec.csp.get('has_unsafe_eval')):
        flags = []
        if sec.csp.get('has_unsafe_inline'):
            flags.append("'unsafe-inline'")
        if sec.csp.get('has_unsafe_eval'):
            flags.append("'unsafe-eval'")
        advisories.append({
            'severity': 'info',
            'title': 'CSP allows ' + ' + '.join(flags),
            'body': (
                'The existing CSP permits behaviors XSS exploits typically need. Tightening these '
                'is meaningful hardening once you can confirm your app doesn\'t depend on them.'
            ),
        })
    if sec.x_frame_options is None:
        advisories.append({
            'severity': 'info',
            'title': 'X-Frame-Options missing',
            'body': 'Clickjacking mitigation. Set to DENY or SAMEORIGIN on the origin, or apply the '
                    '"Enable Clickjacking Protection" feature to the WaaS app after creation.',
        })
    if sec.x_content_type_options is None:
        advisories.append({
            'severity': 'info',
            'title': 'X-Content-Type-Options missing',
            'body': 'Setting this to `nosniff` stops browsers from second-guessing Content-Type.',
        })
    if sec.referrer_policy is None:
        advisories.append({
            'severity': 'info',
            'title': 'Referrer-Policy missing',
            'body': 'Without an explicit policy, browsers leak the full referring URL to third '
                    'parties. `strict-origin-when-cross-origin` is a safe default.',
        })

    # ── Cookies ────────────────────────────────────────────────────────
    if is_https and profile.cookies:
        insecure = [c for c in profile.cookies if not c.secure]
        if insecure:
            advisories.append({
                'severity': 'warning',
                'title': f'{len(insecure)} cookie(s) missing Secure on HTTPS',
                'body': (
                    'Cookies without the `Secure` flag can leak on a downgraded connection. '
                    'Names: ' + ', '.join(c.name for c in insecure[:5]) + '.'
                ),
            })
    session_no_httponly = [
        c for c in profile.cookies
        if _looks_session_shaped(c.name) and not c.http_only
    ]
    if session_no_httponly:
        advisories.append({
            'severity': 'warning',
            'title': f'{len(session_no_httponly)} session-shaped cookie(s) missing HttpOnly',
            'body': (
                'These cookies look like session/auth tokens but are readable by JavaScript. '
                'That turns any XSS into an account-takeover. Names: '
                + ', '.join(c.name for c in session_no_httponly[:5]) + '.'
            ),
        })
    missing_samesite = [c for c in profile.cookies if c.same_site is None]
    if missing_samesite and len(missing_samesite) == len(profile.cookies) and profile.cookies:
        advisories.append({
            'severity': 'info',
            'title': 'No cookies declare SameSite',
            'body': (
                'Modern browsers assume `Lax` when absent, but declaring it explicitly makes intent '
                'clear and future-proofs against changes.'
            ),
        })

    # ── Subresource / traffic profile ──────────────────────────────────
    sub = profile.subresources
    if len(sub.by_third_party_host) > 20:
        advisories.append({
            'severity': 'info',
            'title': f'{len(sub.by_third_party_host)} distinct third-party hosts',
            'body': (
                'The landing page pulls resources from many external hosts. Each is a trust '
                'boundary — worth surfacing to your security team.'
            ),
        })
    if sub.total_bytes_estimate > 2 * 1024 * 1024:
        mb = sub.total_bytes_estimate / (1024 * 1024)
        advisories.append({
            'severity': 'info',
            'title': f'Landing page is heavy (~{mb:.1f} MB estimated)',
            'body': (
                'Large landing pages amplify origin load under DDoS. Consider enabling caching '
                'and image compression at the WAF layer after go-live.'
            ),
        })

    # ── DNS security posture ───────────────────────────────────────────
    dns_sec = profile.dns_security
    if dns_sec.mx_present and not dns_sec.spf:
        advisories.append({
            'severity': 'info',
            'title': 'No SPF record',
            'body': (
                'Email is configured for this domain (MX present) but there is no SPF record — '
                'attackers can more easily spoof mail as your domain.'
            ),
        })
    if dns_sec.mx_present and not dns_sec.dmarc:
        advisories.append({
            'severity': 'info',
            'title': 'No DMARC record',
            'body': (
                'DMARC tells receiving mail servers what to do with unauthenticated mail claiming '
                'your domain. Absent → attackers get a free pass.'
            ),
        })
    if not dns_sec.caa:
        advisories.append({
            'severity': 'info',
            'title': 'No CAA record',
            'body': (
                'A CAA record restricts which CAs can issue certificates for this domain. '
                'Reduces risk of mis-issuance.'
            ),
        })

    # ── Bot management ─────────────────────────────────────────────────
    for vendor in profile.bot_management:
        advisories.append({
            'severity': 'info',
            'title': f'Bot management vendor detected: {vendor.name}',
            'body': (
                f'The site loads {vendor.name} (via {vendor.evidence}). If you are moving traffic '
                'behind WaaS, confirm the vendor still functions correctly through the WAF, or '
                'replace it with WaaS\'s built-in bot rules.'
            ),
        })

    # ── Auth-walled / low confidence ───────────────────────────────────
    if profile.confidence == 'low':
        advisories.append({
            'severity': 'info',
            'title': 'Low-confidence result',
            'body': (
                'The site returned an auth challenge or the TLS handshake failed, so we '
                'could not fingerprint as deeply as usual. Review the pre-filled values carefully.'
            ),
        })

    # ── Tech-specific tuning nudges ────────────────────────────────────
    if 'WordPress' in profile.tech_names:
        advisories.append({
            'severity': 'info',
            'title': 'WordPress detected',
            'body': (
                'After creating the app, consider applying a WordPress-tuned template '
                '(request-limits + common false-positive exceptions) instead of the defaults.'
            ),
            'action': {'label': 'Browse templates', 'url': '/templates/'},
        })
    if 'Drupal' in profile.tech_names:
        advisories.append({
            'severity': 'info',
            'title': 'Drupal detected',
            'body': 'Drupal has known FP patterns around admin paths — plan for tuning after go-live.',
        })

    return {'form_fields': form_fields, 'advisories': advisories}


def _validate_field_names(form_fields: dict) -> None:
    unknown = set(form_fields) - ALLOWED_FORM_FIELDS
    if unknown:
        raise ValueError(
            f'recommender emitted unknown form field(s): {sorted(unknown)}. '
            f'Sync with ApplicationCreateForm in app/forms.py.'
        )
