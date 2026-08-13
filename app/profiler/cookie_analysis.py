"""Parse Set-Cookie response headers into per-cookie CookieAnalysis records.

Notes on flag semantics:
- `Secure`: cookie only sent over HTTPS
- `HttpOnly`: not accessible to document.cookie in JS (mitigates XSS token theft)
- `SameSite`: 'Strict' / 'Lax' / 'None' — cross-site request behavior
- Persistent iff `Max-Age` or `Expires` is present; otherwise session cookie.
- Third-party: explicit `Domain=` attribute that doesn't match the primary
  registrable domain of the response (we take the primary_domain in from
  the caller because it's already been extracted via tldextract).

We work on raw string values rather than `http.cookies.SimpleCookie` because
SimpleCookie mangles duplicate names and is picky about Max-Age. Splitting
on `;` is fine — the value part can't contain a literal `;` per RFC.
"""

from typing import Optional

from app.profiler.schemas import CookieAnalysis


def _parse_one(raw: str, is_https: bool, primary_domain: Optional[str]) -> Optional[CookieAnalysis]:
    if not raw or '=' not in raw.split(';', 1)[0]:
        return None
    nv, *attrs = [p.strip() for p in raw.split(';')]
    name, _, value = nv.partition('=')
    name = name.strip()
    if not name:
        return None

    result = CookieAnalysis(
        name=name,
        value_preview=(value.strip('"')[:12] if value else ''),
    )
    for attr in attrs:
        low = attr.lower()
        if low == 'secure':
            result.secure = True
        elif low == 'httponly':
            result.http_only = True
        elif low.startswith('samesite='):
            v = attr.split('=', 1)[1].strip().strip('"')
            result.same_site = v.capitalize() if v.lower() in ('strict', 'lax', 'none') else v
        elif low.startswith('domain='):
            result.domain = attr.split('=', 1)[1].strip().lstrip('.')
        elif low.startswith('path='):
            result.path = attr.split('=', 1)[1].strip()
        elif low.startswith('max-age='):
            try:
                result.max_age = int(attr.split('=', 1)[1].strip())
            except ValueError:
                pass
        elif low.startswith('expires='):
            result.expires = attr.split('=', 1)[1].strip()

    result.is_session = result.max_age is None and result.expires is None

    if result.domain and primary_domain:
        # Cheap suffix compare — same registrable domain → first-party
        cookie_domain = result.domain.lower().lstrip('.')
        primary = primary_domain.lower()
        result.third_party = not (
            cookie_domain == primary or cookie_domain.endswith('.' + primary)
        )

    return result


def analyze(
    set_cookie_headers: list[str] | str | None,
    is_https: bool,
    primary_domain: Optional[str] = None,
) -> list[CookieAnalysis]:
    """Parse Set-Cookie header value(s) into CookieAnalysis records.

    Accepts either the multi-value list (as urllib3 exposes it), a single
    concatenated string (as `requests` sometimes returns), or None.
    """
    if not set_cookie_headers:
        return []
    if isinstance(set_cookie_headers, str):
        # `requests` collapses duplicate Set-Cookie into one comma-joined
        # string. That's ambiguous because Expires= also contains commas.
        # A pragmatic split: `,` followed by ` `, followed by a token that
        # ends with `=` before the first `;` — i.e., a new cookie starts.
        # For our purposes the caller should pass a list; fall back to a
        # simple split otherwise.
        raw_list = [set_cookie_headers]
    else:
        raw_list = list(set_cookie_headers)

    parsed: list[CookieAnalysis] = []
    for raw in raw_list:
        one = _parse_one(raw, is_https, primary_domain)
        if one is not None:
            parsed.append(one)
    return parsed
