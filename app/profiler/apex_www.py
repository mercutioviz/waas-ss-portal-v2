"""Apex ⇄ www redirect-direction check.

WaaS cannot front a site whose FQDN (`www.<apex>`) redirects to the apex
(`<apex>`) — the supported pattern is the reverse: apex → www. This module
probes both hosts directly (no smart following) so the bad pattern is
caught whether the user profiled the apex or the `www` FQDN.

`resolve`/`is_public_ip` are injected rather than imported from
`app.profiler.probe` — that avoids a circular import (probe.py imports
this module) and lets callers/tests reuse the exact same DNS/SSRF seam
`probe.py` already uses.
"""

from typing import Callable, Optional
from urllib.parse import urlparse

import requests
import tldextract

from app.profiler.schemas import ApexWwwCheck

USER_AGENT = 'WaaS-Portal-Probe/2.0 (+https://v2.ssportal.waaslab.com/profiler)'

ResolveFn = Callable[[str], list[str]]
IsPublicIpFn = Callable[[str], bool]

_extractor = tldextract.TLDExtract(suffix_list_urls=None, cache_dir=None, fallback_to_snapshot=True)
_extractor('example.com')  # prime the bundled PSL at import time


def _resolve_addrs(hostname: str, resolve: ResolveFn) -> list[str]:
    """`resolve(hostname)`, swallowing DNS failures to an empty list."""
    try:
        return resolve(hostname)
    except OSError:
        return []


def _safe_to_fetch(addrs: list[str], is_public_ip: IsPublicIpFn) -> bool:
    """True if every resolved address is a public IP — same SSRF gate
    `probe.py` applies to the main target, applied here to the counterpart
    host before we issue any request to it."""
    return bool(addrs) and all(is_public_ip(ip) for ip in addrs)


def _no_follow_status_and_location(url: str, timeout: float) -> tuple[Optional[int], Optional[str]]:
    """One no-follow HTTPS GET. Never raises — returns (None, None) on any failure."""
    try:
        r = requests.get(
            url, timeout=timeout, allow_redirects=False,
            headers={'User-Agent': USER_AGENT}, stream=True,
        )
        location = r.headers.get('Location')
        r.close()
        return r.status_code, location
    except requests.exceptions.RequestException:
        return None, None


def _redirect_target_hostname(location: Optional[str], source_host: str) -> Optional[str]:
    """Resolve a Location header to a hostname. Relative locations stay on
    the host that issued them, so they never count as a cross-host redirect."""
    if not location:
        return None
    parsed = urlparse(location)
    return (parsed.hostname or source_host).rstrip('.').lower()


def analyze(
    hostname: str,
    resolve: ResolveFn,
    is_public_ip: IsPublicIpFn,
    timeout: float = 8.0,
) -> ApexWwwCheck:
    """Probe the apex/www pair for `hostname`. Returns an `ApexWwwCheck`
    with `applicable=False` if `hostname` isn't apex/www shaped (bare IP,
    single-label host, or a subdomain that isn't `www`)."""
    ext = tldextract.extract(hostname)
    if not ext.domain or not ext.suffix or ext.subdomain not in ('', 'www'):
        return ApexWwwCheck(applicable=False)

    apex = f'{ext.domain}.{ext.suffix}'
    www_host = f'www.{apex}'

    check = ApexWwwCheck(apex=apex, www_host=www_host, applicable=True)

    apex_addrs = _resolve_addrs(apex, resolve)
    www_addrs = _resolve_addrs(www_host, resolve)
    check.apex_dns_found = len(apex_addrs) > 0
    check.www_dns_found = len(www_addrs) > 0

    if _safe_to_fetch(apex_addrs, is_public_ip):
        check.apex_status, check.apex_redirect_target = _no_follow_status_and_location(
            f'https://{apex}/', timeout,
        )
    if _safe_to_fetch(www_addrs, is_public_ip):
        check.www_status, check.www_redirect_target = _no_follow_status_and_location(
            f'https://{www_host}/', timeout,
        )

    if check.apex_status in (301, 302, 307, 308):
        target = _redirect_target_hostname(check.apex_redirect_target, apex)
        check.apex_redirects_to_www = target == www_host.lower()

    if check.www_status in (301, 302, 307, 308):
        target = _redirect_target_hostname(check.www_redirect_target, www_host)
        check.www_redirects_to_apex = target == apex.lower()

    if check.www_redirects_to_apex:
        check.verdict = 'warning'
        check.message = 'WARNING - must be changed'
    elif check.apex_redirects_to_www:
        check.verdict = 'good'
        check.message = 'Redirect is good'
    else:
        check.verdict = 'none'
        check.message = None

    return check
