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
    cookies: dict = field(default_factory=dict)
    body_snippet: Optional[str] = None       # first ~200KB
    redirect_target: Optional[str] = None    # if Location header present
    elapsed_ms: Optional[int] = None
    error: Optional[str] = None


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
    tech_stack: list[str] = field(default_factory=list)            # e.g., ['nginx', 'WordPress']
    cdn: Optional[str] = None                                       # e.g., 'Cloudflare'
    auth_surface: list[str] = field(default_factory=list)          # signals we noticed
    confidence: str = 'high'                                        # 'high' | 'low' — low when auth-walled or TLS broken

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProbeStep:
    """Descriptor for a single probe step — used for event emission."""
    key: str          # machine name, e.g. 'tls'
    label: str        # user-visible, e.g. 'TLS handshake'
