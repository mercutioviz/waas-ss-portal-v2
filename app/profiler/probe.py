"""HTTP/TLS probe pipeline for the Web App Profiler.

Public entry point: run_probe(target_url, emit=None) -> SiteProfile.

The `emit(step_key, phase, data=None)` callback is dependency-injected — the
background greenlet passes a SocketIO-emitting version; tests pass a mock.
Keeping the probe itself I/O-agnostic keeps it fully offline-testable.

Guardrails:
- Hard 25s global budget; per-request timeout 8s.
- SSRF gate rejects loopback, link-local, RFC-1918, and reserved ranges
  AFTER DNS resolution — string checks on the hostname are defeatable via
  DNS rebinding.
- Honest User-Agent identifies outbound requests.
- `verify=True` on TLS; cert failures are recorded, not silenced.
"""

import ipaddress
import logging
import socket
import ssl
import time
from typing import Callable, Optional
from urllib.parse import urlparse

import requests

from app.profiler import (
    apex_www,
    bot_mgmt,
    cookie_analysis,
    dns_security,
    fingerprints,
    security_headers,
    subresources as subresources_mod,
)
from app.profiler.schemas import (
    DnsResult,
    HttpResult,
    ProbeStep,
    SiteProfile,
    TlsResult,
)

logger = logging.getLogger(__name__)

USER_AGENT = 'WaaS-Portal-Probe/2.0 (+https://v2.ssportal.waaslab.com/profiler)'
GLOBAL_BUDGET_SECONDS = 25
REQUEST_TIMEOUT_SECONDS = 8
MAX_BODY_BYTES = 200_000

# Step ordering surfaced to the UI. `key` values are also the event step_key.
PROBE_STEPS: list[ProbeStep] = [
    ProbeStep('dns', 'Resolving DNS'),
    ProbeStep('ssrf', 'Safety check'),
    ProbeStep('tls', 'TLS handshake'),
    ProbeStep('http_redirect', 'Checking HTTP → HTTPS redirect'),
    ProbeStep('apex_www', 'Checking apex/www redirect setup'),
    ProbeStep('https_root', 'Fetching landing page'),
    ProbeStep('security_headers', 'Auditing security headers'),
    ProbeStep('cookies', 'Analyzing cookies'),
    ProbeStep('subresources', 'Discovering subresources'),
    ProbeStep('tech', 'Fingerprinting stack'),
    ProbeStep('dns_security', 'Checking DNS security records'),
    ProbeStep('bot_mgmt', 'Detecting bot management'),
    ProbeStep('robots', 'Reading robots.txt'),
    ProbeStep('auth_surface', 'Inspecting auth surface'),
    ProbeStep('cdn', 'Checking CDN fronting'),
]

EmitCallback = Callable[[str, str, Optional[dict]], None]


def _noop_emit(step_key: str, phase: str, data: Optional[dict] = None) -> None:
    pass


class ProbeBudgetExceeded(Exception):
    """Raised when the global time budget is used up mid-probe."""


class SsrfRejected(Exception):
    """Raised when the target resolves to a disallowed IP range."""


def _budget_remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _check_budget(deadline: float) -> None:
    if _budget_remaining(deadline) <= 0:
        raise ProbeBudgetExceeded()


def _is_public_ip(ip_string: str) -> bool:
    """True if the address is a routable public IP.

    Rejects: loopback (127/8, ::1), link-local (169.254/16, fe80::/10),
    private (10/8, 172.16/12, 192.168/16, fc00::/7), unspecified, multicast,
    reserved, site-local.
    """
    try:
        addr = ipaddress.ip_address(ip_string)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_private:
        return False
    if addr.is_unspecified or addr.is_multicast or addr.is_reserved:
        return False
    return True


def _resolve(hostname: str) -> list[str]:
    """Return every A/AAAA address for `hostname`. Raises OSError on failure."""
    infos = socket.getaddrinfo(hostname, None)
    addrs: list[str] = []
    for family, _stype, _proto, _canon, sockaddr in infos:
        if family in (socket.AF_INET, socket.AF_INET6):
            ip = sockaddr[0]
            if ip not in addrs:
                addrs.append(ip)
    return addrs


def _do_tls_handshake(hostname: str, port: int, timeout: float) -> TlsResult:
    """Standalone TLS handshake to capture negotiated version, cipher, and cert."""
    result = TlsResult()
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                result.handshake_ok = True
                result.tls_version = tls.version()
                cipher_info = tls.cipher()
                if cipher_info:
                    result.cipher = cipher_info[0]
                cert = tls.getpeercert() or {}
                result.cert_subject = _flatten_name(cert.get('subject'))
                result.cert_issuer = _flatten_name(cert.get('issuer'))
                result.cert_not_after = cert.get('notAfter')
                sans = cert.get('subjectAltName', ()) or ()
                result.cert_sans = [v for k, v in sans if k == 'DNS']
    except (socket.timeout, TimeoutError) as e:
        result.error = f'TLS handshake timed out: {e}'
    except ssl.SSLError as e:
        result.error = f'TLS error: {e}'
    except OSError as e:
        result.error = f'Connect failed: {e}'
    return result


def _flatten_name(name_tuples) -> Optional[str]:
    """`getpeercert` returns tuples of ((key, value), …); flatten to `key=value, …`."""
    if not name_tuples:
        return None
    parts = []
    for rdn in name_tuples:
        for k, v in rdn:
            parts.append(f'{k}={v}')
    return ', '.join(parts)


def _http_get(url: str, timeout: float, allow_redirects: bool = False) -> HttpResult:
    """One HTTP round-trip. Returns HttpResult; never raises."""
    parsed = urlparse(url)
    result = HttpResult(scheme=parsed.scheme, url=url)
    started = time.monotonic()
    try:
        r = requests.get(
            url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            headers={'User-Agent': USER_AGENT},
            stream=True,
        )
        result.status = r.status_code
        result.headers = dict(r.headers)
        result.cookies = {c.name: c.value for c in r.cookies}
        # `r.headers` collapses duplicate Set-Cookie into one comma-joined
        # string; urllib3's underlying HTTPHeaderDict keeps them separate.
        try:
            result.set_cookie_headers = list(r.raw.headers.getlist('Set-Cookie'))
        except AttributeError:  # pragma: no cover — non-urllib3 responses
            raw = r.headers.get('Set-Cookie')
            result.set_cookie_headers = [raw] if raw else []
        if 'Location' in r.headers:
            result.redirect_target = r.headers['Location']
        content = r.raw.read(MAX_BODY_BYTES, decode_content=True) or b''
        try:
            result.body_snippet = content.decode(r.encoding or 'utf-8', errors='replace')
        except (LookupError, UnicodeDecodeError):
            result.body_snippet = content.decode('utf-8', errors='replace')
        r.close()
    except requests.exceptions.SSLError as e:
        result.error = f'TLS error: {e}'
    except requests.exceptions.ConnectTimeout:
        result.error = 'Connect timed out'
    except requests.exceptions.ReadTimeout:
        result.error = 'Read timed out'
    except requests.exceptions.ConnectionError as e:
        result.error = f'Connection failed: {e}'
    except requests.exceptions.RequestException as e:
        result.error = f'Request failed: {e}'
    result.elapsed_ms = int((time.monotonic() - started) * 1000)
    return result


def _looks_like_login(body: str) -> bool:
    """Cheap heuristic: presence of a password input suggests a login form."""
    if not body:
        return False
    lower = body.lower()
    return 'type="password"' in lower or "type='password'" in lower


def run_probe(target_url: str, emit: Optional[EmitCallback] = None) -> SiteProfile:
    """Probe `target_url` and return a SiteProfile.

    `emit(step_key, phase, data)` is called with phase in
    {'start', 'ok', 'error', 'skip'}. When phase is 'ok' or 'error', `data`
    carries step-specific fields the UI can render (e.g., tls_version).
    """
    emit = emit or _noop_emit
    deadline = time.monotonic() + GLOBAL_BUDGET_SECONDS

    parsed = urlparse(target_url if '://' in target_url else f'https://{target_url}')
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError(f'Unsupported target URL: {target_url!r}')

    normalized = f'{parsed.scheme}://{parsed.hostname}{":" + str(parsed.port) if parsed.port else ""}/'
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    profile = SiteProfile(target_url=normalized, dns=DnsResult(hostname=hostname))

    # 1. DNS
    emit('dns', 'start')
    try:
        addrs = _resolve(hostname)
        profile.dns.addresses = addrs
        emit('dns', 'ok', {'addresses': addrs})
    except OSError as e:
        profile.dns.error = str(e)
        emit('dns', 'error', {'error': str(e)})
        profile.confidence = 'low'
        return profile

    # 2. SSRF gate — after DNS to block hostname-based bypasses
    emit('ssrf', 'start')
    disallowed = [ip for ip in profile.dns.addresses if not _is_public_ip(ip)]
    if disallowed:
        profile.ssrf_blocked = True
        profile.ssrf_reason = f'Target resolves to non-public address(es): {", ".join(disallowed)}'
        emit('ssrf', 'error', {'error': profile.ssrf_reason})
        raise SsrfRejected(profile.ssrf_reason)
    emit('ssrf', 'ok')

    # 3. TLS handshake
    emit('tls', 'start')
    try:
        _check_budget(deadline)
        profile.tls = _do_tls_handshake(hostname, 443, min(REQUEST_TIMEOUT_SECONDS, _budget_remaining(deadline)))
        if profile.tls.handshake_ok:
            emit('tls', 'ok', {
                'version': profile.tls.tls_version,
                'cipher': profile.tls.cipher,
                'cert_subject': profile.tls.cert_subject,
                'cert_not_after': profile.tls.cert_not_after,
            })
        else:
            emit('tls', 'error', {'error': profile.tls.error or 'TLS failed'})
            profile.confidence = 'low'
    except ProbeBudgetExceeded:
        emit('tls', 'skip', {'error': 'time budget exceeded'})
        return _finalize(profile)

    # 4. HTTP redirect probe (no follow) — do we see a 301/302 to HTTPS?
    emit('http_redirect', 'start')
    try:
        _check_budget(deadline)
        profile.http_root = _http_get(
            f'http://{hostname}/', min(REQUEST_TIMEOUT_SECONDS, _budget_remaining(deadline))
        )
        emit('http_redirect', 'ok', {
            'status': profile.http_root.status,
            'redirect_target': profile.http_root.redirect_target,
            'error': profile.http_root.error,
        })
    except ProbeBudgetExceeded:
        emit('http_redirect', 'skip', {'error': 'time budget exceeded'})
        return _finalize(profile)

    # 4b. Apex ⇄ www redirect direction — WaaS only supports apex → www.
    emit('apex_www', 'start')
    if _budget_remaining(deadline) > 3.0:
        profile.apex_www = apex_www.analyze(
            hostname, resolve=_resolve, is_public_ip=_is_public_ip,
            timeout=min(REQUEST_TIMEOUT_SECONDS, _budget_remaining(deadline)),
        )
        emit('apex_www', 'ok', {
            'verdict': profile.apex_www.verdict,
            'message': profile.apex_www.message,
        })
    else:
        emit('apex_www', 'skip', {'error': 'time budget exceeded'})

    # 5. HTTPS landing page
    emit('https_root', 'start')
    try:
        _check_budget(deadline)
        profile.https_root = _http_get(
            f'https://{hostname}/', min(REQUEST_TIMEOUT_SECONDS, _budget_remaining(deadline)),
            allow_redirects=True,
        )
        emit('https_root', 'ok', {
            'status': profile.https_root.status,
            'content_type': profile.https_root.headers.get('Content-Type'),
        })
    except ProbeBudgetExceeded:
        emit('https_root', 'skip', {'error': 'time budget exceeded'})
        return _finalize(profile)

    # 6. Security headers (parse from step-5 response)
    emit('security_headers', 'start')
    profile.security_headers = security_headers.analyze(profile.https_root.headers)
    emit('security_headers', 'ok', {
        'hsts': bool(profile.security_headers.hsts),
        'csp': bool(profile.security_headers.csp),
        'xfo': bool(profile.security_headers.x_frame_options),
    })

    # 7. Cookies (parse Set-Cookie flags)
    emit('cookies', 'start')
    primary_ext = subresources_mod._extractor(hostname)
    primary_domain = f'{primary_ext.domain}.{primary_ext.suffix}' if primary_ext.suffix else hostname
    profile.cookies = cookie_analysis.analyze(
        profile.https_root.set_cookie_headers,
        is_https=parsed.scheme == 'https',
        primary_domain=primary_domain,
    )
    emit('cookies', 'ok', {
        'count': len(profile.cookies),
        'insecure_on_https': sum(
            1 for c in profile.cookies if not c.secure and parsed.scheme == 'https'
        ),
    })

    # 8. Subresources — discover from HTML, HEAD-fetch under a wall-clock cap
    emit('subresources', 'start')
    if _budget_remaining(deadline) > 3.0:
        discovered = subresources_mod.discover(
            profile.https_root.body_snippet or '', target_url,
        )
        sub_budget = min(
            subresources_mod.SUBRESOURCE_BUDGET_SECONDS,
            _budget_remaining(deadline) - 2.0,   # leave room for later steps
        )
        profile.subresources = subresources_mod.fetch_all(
            discovered, hostname, budget_seconds=sub_budget,
        )
        emit('subresources', 'ok', {
            'discovered': profile.subresources.discovered_count,
            'analyzed': profile.subresources.analyzed_count,
            'total_bytes': profile.subresources.total_bytes_estimate,
            'third_party_hosts': len(profile.subresources.by_third_party_host),
        })
    else:
        emit('subresources', 'skip', {'error': 'time budget exceeded'})

    # 9. Tech fingerprint (headers + cookies + body + subresource URLs)
    emit('tech', 'start')
    subresource_urls = [hit.url for hit in profile.subresources.hits]
    profile.tech_stack = fingerprints.identify_tech(
        profile.https_root.headers,
        profile.https_root.cookies,
        profile.https_root.body_snippet or '',
        subresource_urls=subresource_urls,
    )
    emit('tech', 'ok', {'tech_stack': [t.name for t in profile.tech_stack]})

    # 10. DNS security records
    emit('dns_security', 'start')
    if _budget_remaining(deadline) > 3.5:
        profile.dns_security = dns_security.analyze(hostname)
        emit('dns_security', 'ok', {
            'spf': bool(profile.dns_security.spf),
            'dmarc': bool(profile.dns_security.dmarc),
            'caa': len(profile.dns_security.caa),
        })
    else:
        emit('dns_security', 'skip', {'error': 'time budget exceeded'})

    # 11. Bot management vendors (from subresource hosts)
    emit('bot_mgmt', 'start')
    profile.bot_management = bot_mgmt.classify(
        [(hit.host, hit.url) for hit in profile.subresources.hits],
    )
    emit('bot_mgmt', 'ok', {
        'vendors': [b.name for b in profile.bot_management],
    })

    # 12. robots.txt (soft-fail)
    emit('robots', 'start')
    if _budget_remaining(deadline) > 1.0:
        robots = _http_get(
            f'https://{hostname}/robots.txt',
            min(REQUEST_TIMEOUT_SECONDS, _budget_remaining(deadline)),
        )
        if robots.status == 200 and robots.body_snippet:
            profile.robots_txt = robots.body_snippet[:4096]
            emit('robots', 'ok', {'has_robots': True})
        else:
            emit('robots', 'ok', {'has_robots': False})
    else:
        emit('robots', 'skip', {'error': 'time budget exceeded'})

    # 13. Auth surface
    emit('auth_surface', 'start')
    status = profile.https_root.status or 0
    if status in (401, 403):
        profile.auth_surface.append('landing returns 401/403 — site is auth-walled')
        profile.confidence = 'low'
    elif _looks_like_login(profile.https_root.body_snippet or ''):
        profile.auth_surface.append('password field detected on landing page')
    emit('auth_surface', 'ok', {'signals': profile.auth_surface})

    # 14. CDN detection (from resolved IPs)
    emit('cdn', 'start')
    for ip in profile.dns.addresses:
        cdn = fingerprints.is_cdn_ip(ip)
        if cdn:
            profile.cdn = cdn
            if not any(t.name == cdn for t in profile.tech_stack):
                from app.profiler.schemas import TechDetection
                profile.tech_stack.append(
                    TechDetection(name=cdn, category='CDN', source='ip'),
                )
            break
    emit('cdn', 'ok', {'cdn': profile.cdn})

    return _finalize(profile)


def _finalize(profile: SiteProfile) -> SiteProfile:
    return profile
