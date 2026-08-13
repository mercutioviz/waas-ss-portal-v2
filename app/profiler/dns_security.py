"""Cheap DNS records adjacent to WAF posture: SPF, DMARC, CAA, MX.

Each query is dispatched on its own greenlet under a shared budget so no
one lookup can starve the others. Failures are silent — an absent record
is a legitimate finding, not an error.
"""

import gevent
import gevent.pool

import dns.exception
import dns.resolver
import dns.rdatatype

from app.profiler.schemas import DnsSecurityReport

DNS_BUDGET_SECONDS = 3


def _query(hostname: str, rdtype) -> list[str]:
    """Resolve records and return the string representations. Empty on failure."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_BUDGET_SECONDS
        resolver.timeout = DNS_BUDGET_SECONDS
        answers = resolver.resolve(hostname, rdtype)
        return [r.to_text() for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout,
            dns.resolver.NoNameservers, dns.exception.DNSException):
        return []


def _find_spf(txt_records: list[str]) -> str | None:
    for raw in txt_records:
        # TXT records come back as quoted strings; strip quotes / join fragments.
        cleaned = raw.replace('" "', '').strip('"')
        if cleaned.lower().startswith('v=spf1'):
            return cleaned
    return None


def _find_dmarc(txt_records: list[str]) -> str | None:
    for raw in txt_records:
        cleaned = raw.replace('" "', '').strip('"')
        if cleaned.lower().startswith('v=dmarc1'):
            return cleaned
    return None


def analyze(hostname: str) -> DnsSecurityReport:
    """Fan out the four record types concurrently under DNS_BUDGET_SECONDS."""
    if not hostname:
        return DnsSecurityReport()

    pool = gevent.pool.Pool(4)
    txt_g = pool.spawn(_query, hostname, dns.rdatatype.TXT)
    dmarc_g = pool.spawn(_query, f'_dmarc.{hostname}', dns.rdatatype.TXT)
    caa_g = pool.spawn(_query, hostname, dns.rdatatype.CAA)
    mx_g = pool.spawn(_query, hostname, dns.rdatatype.MX)
    gevent.wait([txt_g, dmarc_g, caa_g, mx_g], timeout=DNS_BUDGET_SECONDS)

    txt_records = txt_g.value if txt_g.ready() else []
    dmarc_records = dmarc_g.value if dmarc_g.ready() else []
    caa_records = caa_g.value if caa_g.ready() else []
    mx_records = mx_g.value if mx_g.ready() else []

    return DnsSecurityReport(
        spf=_find_spf(txt_records),
        dmarc=_find_dmarc(dmarc_records),
        caa=[r.strip() for r in caa_records],
        mx_present=bool(mx_records),
    )
