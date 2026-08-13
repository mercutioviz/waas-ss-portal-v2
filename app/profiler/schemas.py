"""Dataclasses for probe results. All are JSON-serializable via asdict()."""

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class DnsResult:
    hostname: str
    addresses: list[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class TlsResult:
    handshake_ok: bool = False
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_sans: list[str] = field(default_factory=list)
    cert_not_after: Optional[str] = None
    error: Optional[str] = None


@dataclass
class HttpResult:
    """Single HTTP round-trip result (no follow)."""
    scheme: str = ''
    url: str = ''
    status: Optional[int] = None
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)              # jar name→value (for fingerprint matching)
    set_cookie_headers: list[str] = field(default_factory=list)  # raw values for flag analysis
    body_snippet: Optional[str] = None       # first ~200KB
    redirect_target: Optional[str] = None    # if Location header present
    elapsed_ms: Optional[int] = None
    error: Optional[str] = None


@dataclass
class SecurityHeadersReport:
    """Presence + parsed values for the standard security response headers.

    Each field is either None (header absent) or a small dict of parsed
    attributes. Kept flat and self-describing so the results-page template
    can render it without extra normalization.
    """
    hsts: Optional[dict] = None                # {max_age, include_subdomains, preload}
    csp: Optional[dict] = None                 # {directive_count, has_unsafe_inline, has_unsafe_eval, raw}
    x_frame_options: Optional[str] = None      # 'DENY' | 'SAMEORIGIN' | 'ALLOW-FROM …'
    x_content_type_options: Optional[str] = None  # typically 'nosniff'
    referrer_policy: Optional[str] = None
    permissions_policy: Optional[str] = None
    coop: Optional[str] = None
    coep: Optional[str] = None
    corp: Optional[str] = None


@dataclass
class CookieAnalysis:
    """One Set-Cookie response header, parsed."""
    name: str
    value_preview: str                          # first 12 chars, for reference only
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None             # 'Strict' | 'Lax' | 'None' | None
    domain: Optional[str] = None
    path: Optional[str] = None
    max_age: Optional[int] = None
    expires: Optional[str] = None
    is_session: bool = True                     # persistent iff Max-Age or Expires present
    third_party: bool = False                   # explicit Domain= to a different registrable domain


@dataclass
class SubresourceHit:
    """One resource linked from the landing HTML that we successfully probed."""
    url: str
    host: str
    kind: str                                   # 'script' | 'style' | 'image' | 'iframe' | 'font' | 'other'
    status: Optional[int] = None
    bytes_estimate: Optional[int] = None         # from Content-Length; None if server didn't send one
    elapsed_ms: Optional[int] = None
    third_party: bool = False
    error: Optional[str] = None


@dataclass
class SubresourceReport:
    """Aggregate view of what loading the landing page pulled in."""
    discovered_count: int = 0                    # total URLs found in HTML (before cap)
    analyzed_count: int = 0                      # how many we actually fetched (<= cap)
    total_bytes_estimate: int = 0                # sum of bytes_estimate across analyzed hits
    hits: list[SubresourceHit] = field(default_factory=list)
    first_party_count: int = 0
    third_party_count: int = 0
    by_third_party_host: dict = field(default_factory=dict)  # host -> {count, bytes}
    truncated: bool = False                      # discovered_count > cap
    budget_exceeded: bool = False                # wall-clock cap hit; some hits missing


@dataclass
class TechDetection:
    """One tech-stack match with a bit of provenance for the UI."""
    name: str
    category: str = ''
    source: str = ''                             # 'header' | 'cookie' | 'body' | 'subresource'
    version: Optional[str] = None


@dataclass
class DnsSecurityReport:
    """Records adjacent to WAF posture that are cheap to fetch."""
    spf: Optional[str] = None                    # SPF record from TXT root (if any)
    dmarc: Optional[str] = None                  # TXT at _dmarc.<host>
    caa: list[str] = field(default_factory=list) # CAA records for the apex
    mx_present: bool = False


@dataclass
class BotVendor:
    """One bot-management / CAPTCHA vendor detected via subresource host."""
    name: str
    evidence: str                                # host that triggered the classification


@dataclass
class SiteProfile:
    """Everything the probe learned about the target site."""
    target_url: str
    dns: DnsResult
    ssrf_blocked: bool = False
    ssrf_reason: Optional[str] = None
    tls: TlsResult = field(default_factory=TlsResult)
    http_root: HttpResult = field(default_factory=HttpResult)      # http://host/
    https_root: HttpResult = field(default_factory=HttpResult)     # https://host/
    robots_txt: Optional[str] = None
    tech_stack: list[TechDetection] = field(default_factory=list)  # richer than plain strings
    cdn: Optional[str] = None                                       # e.g., 'Cloudflare'
    auth_surface: list[str] = field(default_factory=list)          # signals we noticed
    confidence: str = 'high'                                        # 'high' | 'low' — low when auth-walled or TLS broken

    # New in Phase 2.5
    security_headers: SecurityHeadersReport = field(default_factory=SecurityHeadersReport)
    cookies: list[CookieAnalysis] = field(default_factory=list)
    subresources: SubresourceReport = field(default_factory=SubresourceReport)
    dns_security: DnsSecurityReport = field(default_factory=DnsSecurityReport)
    bot_management: list[BotVendor] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def tech_names(self) -> list[str]:
        """Just the names, de-duplicated and preserving detection order.
        Used by the recommender for backwards-compatible checks (`"WordPress"
        in profile.tech_names`)."""
        seen: list[str] = []
        for t in self.tech_stack:
            if t.name not in seen:
                seen.append(t.name)
        return seen


@dataclass
class ProbeStep:
    """Descriptor for a single probe step — used for event emission."""
    key: str          # machine name, e.g. 'tls'
    label: str        # user-visible, e.g. 'TLS handshake'
