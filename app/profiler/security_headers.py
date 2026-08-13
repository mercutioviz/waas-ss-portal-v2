"""Analyze the standard security response headers into a SecurityHeadersReport.

Pure function of the header dict — no I/O. The recommender turns absence
into advisories; this module only observes and parses.
"""

import re
from typing import Optional

from app.profiler.schemas import SecurityHeadersReport


def _get(headers: dict, name: str) -> Optional[str]:
    """Case-insensitive header lookup returning the raw value (or None)."""
    if not headers:
        return None
    name_lc = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lc:
            return v
    return None


def _parse_hsts(value: Optional[str]) -> Optional[dict]:
    if not value:
        return None
    parsed = {
        'max_age': None,
        'include_subdomains': False,
        'preload': False,
    }
    for part in [p.strip() for p in value.split(';')]:
        if not part:
            continue
        low = part.lower()
        if low.startswith('max-age='):
            try:
                parsed['max_age'] = int(part.split('=', 1)[1].strip().strip('"'))
            except (ValueError, IndexError):
                pass
        elif low == 'includesubdomains':
            parsed['include_subdomains'] = True
        elif low == 'preload':
            parsed['preload'] = True
    return parsed


_UNSAFE_INLINE_PAT = re.compile(r"'unsafe-inline'", re.IGNORECASE)
_UNSAFE_EVAL_PAT = re.compile(r"'unsafe-eval'", re.IGNORECASE)


def _parse_csp(value: Optional[str]) -> Optional[dict]:
    if not value:
        return None
    # Directives are semicolon-separated. Count non-empty ones.
    directives = [d.strip() for d in value.split(';') if d.strip()]
    return {
        'directive_count': len(directives),
        'has_unsafe_inline': bool(_UNSAFE_INLINE_PAT.search(value)),
        'has_unsafe_eval': bool(_UNSAFE_EVAL_PAT.search(value)),
        'raw': value[:4096],   # truncate — some CSPs are absurdly long
    }


def analyze(headers: dict) -> SecurityHeadersReport:
    """Return a SecurityHeadersReport for the given response headers."""
    return SecurityHeadersReport(
        hsts=_parse_hsts(_get(headers, 'Strict-Transport-Security')),
        csp=_parse_csp(_get(headers, 'Content-Security-Policy')),
        x_frame_options=_get(headers, 'X-Frame-Options'),
        x_content_type_options=_get(headers, 'X-Content-Type-Options'),
        referrer_policy=_get(headers, 'Referrer-Policy'),
        permissions_policy=_get(headers, 'Permissions-Policy'),
        coop=_get(headers, 'Cross-Origin-Opener-Policy'),
        coep=_get(headers, 'Cross-Origin-Embedder-Policy'),
        corp=_get(headers, 'Cross-Origin-Resource-Policy'),
    )
