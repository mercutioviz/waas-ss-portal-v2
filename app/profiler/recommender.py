"""Turn a SiteProfile into ApplicationCreateForm defaults + advisory list.

Pure function of the profile — no I/O, trivial to unit test. The output
shape mirrors the field names of `app.forms.ApplicationCreateForm` so the
results template can pre-fill the form directly.
"""

from urllib.parse import urlparse

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


def _slugify_hostname(hostname: str) -> str:
    """`www.acme-corp.example.com` → `acme-corp`. Falls back to the raw
    hostname stripped of dots."""
    if not hostname:
        return 'new-app'
    parts = [p for p in hostname.split('.') if p]
    parts = [p for p in parts if p not in ('www',)]
    if not parts:
        return hostname.replace('.', '-')
    # Prefer the second-level label if it exists (acme-corp from acme-corp.example.com)
    return parts[0] if len(parts) < 3 else parts[0]


def _detects_https_redirect(profile: SiteProfile) -> bool:
    http = profile.http_root
    if not http or not http.status:
        return False
    if http.status not in (301, 302, 307, 308):
        return False
    target = (http.redirect_target or '').lower()
    return target.startswith('https://')


def recommend(profile: SiteProfile) -> dict:
    """Return `{form_fields: {...}, advisories: [...]}` for the results page."""
    hostname = urlparse(profile.target_url).hostname or ''
    tls_ok = profile.tls.handshake_ok
    https_ok = (profile.https_root.status or 0) < 400 and not profile.https_root.error
    redirects_to_https = _detects_https_redirect(profile)

    form_fields: dict = {
        'application_name': {
            'value': _slugify_hostname(hostname),
            'rationale': f'Derived from the hostname {hostname}. Rename to whatever your team calls this service.',
        },
        'hostname': {
            'value': hostname,
            'rationale': 'The public hostname you probed. This is what end users type.',
        },
        'backend_ip': {
            'value': '',
            'rationale': (
                'You must supply the origin server address (the backend the WAF forwards to). '
                'This cannot be probed from the public URL.'
            ),
        },
        'backend_port': {
            'value': 443 if tls_ok else 80,
            'rationale': (
                'Detected HTTPS on port 443 — pointing the WAF at the same port keeps behavior consistent.'
                if tls_ok else
                'TLS was not reachable on 443 — falling back to plain HTTP on 80. Consider hardening the origin.'
            ),
        },
        'backend_type': {
            'value': 'HTTPS' if tls_ok else 'HTTP',
            'rationale': (
                f'TLS {profile.tls.tls_version or ""} handshake succeeded with a valid certificate.'
                if tls_ok else
                'TLS was not reachable; falling back to HTTP for the backend protocol.'
            ),
        },
        'malicious_traffic': {
            'value': 'Passive',
            'rationale': (
                'Start in Passive so the WAF monitors without blocking. Review the log for false positives, '
                'then switch to Active after ~1–2 weeks of clean traffic.'
            ),
        },
        'use_https': {
            'value': bool(tls_ok or https_ok),
            'rationale': (
                'TLS is working on your site, so end users should keep hitting HTTPS through the WAF.'
                if tls_ok else
                'Recommended even if the origin is HTTP-only — the WAF can terminate TLS for you.'
            ),
        },
        'use_http': {
            'value': True,
            'rationale': (
                'Keep an HTTP endpoint so legacy links redirect cleanly to HTTPS via the WAF.'
            ),
        },
        'redirect_http': {
            'value': True,
            'rationale': (
                'Your site already redirects HTTP → HTTPS; replicating that on the WAF endpoint keeps behavior identical.'
                if redirects_to_https else
                'Recommended by default — the WAF should redirect any HTTP request to HTTPS.'
            ),
        },
    }

    _validate_field_names(form_fields)

    advisories: list[dict] = []

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

    if profile.confidence == 'low':
        advisories.append({
            'severity': 'info',
            'title': 'Low-confidence result',
            'body': (
                'The site returned an auth challenge or the TLS handshake failed, so we '
                'could not fingerprint as deeply as usual. Review the pre-filled values carefully.'
            ),
        })

    if 'WordPress' in profile.tech_stack:
        advisories.append({
            'severity': 'info',
            'title': 'WordPress detected',
            'body': (
                'After creating the app, consider applying a WordPress-tuned template '
                '(request-limits + common false-positive exceptions) instead of the defaults.'
            ),
            'action': {'label': 'Browse templates', 'url': '/templates/'},
        })

    if 'Drupal' in profile.tech_stack:
        advisories.append({
            'severity': 'info',
            'title': 'Drupal detected',
            'body': 'Drupal has known FP patterns around admin paths — plan for tuning after go-live.',
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

    return {'form_fields': form_fields, 'advisories': advisories}


def _validate_field_names(form_fields: dict) -> None:
    unknown = set(form_fields) - ALLOWED_FORM_FIELDS
    if unknown:
        raise ValueError(
            f'recommender emitted unknown form field(s): {sorted(unknown)}. '
            f'Sync with ApplicationCreateForm in app/forms.py.'
        )
