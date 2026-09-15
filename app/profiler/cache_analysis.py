"""Parse HTTP cache-policy signals (Cache-Control, validators, edge-hit) from
response headers already captured by the probe.

Pure functions of the header dict / subresource list — no I/O. Mirrors the
shape of security_headers.py. The recommender turns these observations into
advisories; this module only observes and parses.
"""

from typing import Optional

from app.profiler.schemas import AssetCacheSummary, CachePageReport, SubresourceHit

STATIC_ASSET_KINDS = frozenset({'script', 'style', 'image', 'font'})
LONG_LIVED_SECONDS = 86400
MAX_EXAMPLES = 5

_EDGE_HIT_HEADERS = ('x-cache', 'cf-cache-status', 'x-cache-hits')


def _get(headers: dict, name: str) -> Optional[str]:
    """Case-insensitive header lookup returning the raw value (or None)."""
    if not headers:
        return None
    name_lc = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lc:
            return v
    return None


def parse_cache_control(value: Optional[str]) -> Optional[dict]:
    """Parse a Cache-Control header value into its directives.

    Unknown/malformed tokens are ignored rather than raising — real-world
    servers send all manner of junk here.
    """
    if not value:
        return None
    parsed = {
        'no_store': False,
        'no_cache': False,
        'private': False,
        'public': False,
        'max_age': None,
        's_maxage': None,
        'must_revalidate': False,
        'proxy_revalidate': False,
        'immutable': False,
        'stale_while_revalidate': None,
        'raw': value[:1024],
    }
    for part in [p.strip() for p in value.split(',')]:
        if not part:
            continue
        low = part.lower()
        if low == 'no-store':
            parsed['no_store'] = True
        elif low == 'no-cache':
            parsed['no_cache'] = True
        elif low == 'private':
            parsed['private'] = True
        elif low == 'public':
            parsed['public'] = True
        elif low == 'must-revalidate':
            parsed['must_revalidate'] = True
        elif low == 'proxy-revalidate':
            parsed['proxy_revalidate'] = True
        elif low == 'immutable':
            parsed['immutable'] = True
        elif low.startswith('max-age='):
            parsed['max_age'] = _parse_int(part.split('=', 1)[1])
        elif low.startswith('s-maxage='):
            parsed['s_maxage'] = _parse_int(part.split('=', 1)[1])
        elif low.startswith('stale-while-revalidate='):
            parsed['stale_while_revalidate'] = _parse_int(part.split('=', 1)[1])
    return parsed


def _parse_int(raw: str) -> Optional[int]:
    try:
        return int(raw.strip().strip('"'))
    except (ValueError, IndexError):
        return None


def _is_edge_hit(headers: dict) -> bool:
    for name in _EDGE_HIT_HEADERS:
        value = _get(headers, name)
        if value and 'hit' in value.lower():
            return True
    return False


def analyze(headers: dict) -> CachePageReport:
    """Return a CachePageReport for the given (landing-page) response headers."""
    age_raw = _get(headers, 'Age')
    return CachePageReport(
        cache_control=parse_cache_control(_get(headers, 'Cache-Control')),
        etag=_get(headers, 'ETag') is not None,
        last_modified=_get(headers, 'Last-Modified') is not None,
        vary=_get(headers, 'Vary'),
        age=_parse_int(age_raw) if age_raw else None,
        edge_hit=_is_edge_hit(headers),
    )


def _is_cacheable(cc: Optional[dict]) -> bool:
    if not cc:
        return False
    return bool(cc['public']) or (cc['max_age'] or 0) > 0


def summarize_assets(hits: list[SubresourceHit]) -> AssetCacheSummary:
    """Aggregate cache-policy signals across analyzed static-asset hits.

    Each hit lands in exactly one bucket: no_store takes priority (the
    server explicitly opted out), then an explicit lifetime (cacheable),
    then a bare validator with no lifetime (revalidate_only — the browser
    must round-trip on every load to check freshness), then nothing at all
    (missing_validators).
    """
    summary = AssetCacheSummary()
    for hit in hits:
        if hit.kind not in STATIC_ASSET_KINDS or hit.error:
            continue
        summary.analyzed += 1
        cc = parse_cache_control(hit.cache_control)
        if cc and cc['no_store']:
            summary.no_store += 1
            if len(summary.examples) < MAX_EXAMPLES:
                summary.examples.append(hit.url)
        elif _is_cacheable(cc):
            summary.cacheable += 1
            if (cc['max_age'] or 0) >= LONG_LIVED_SECONDS:
                summary.long_lived += 1
        elif hit.etag:
            summary.revalidate_only += 1
            if len(summary.revalidate_examples) < MAX_EXAMPLES:
                summary.revalidate_examples.append(hit.url)
        else:
            summary.missing_validators += 1
            if len(summary.examples) < MAX_EXAMPLES:
                summary.examples.append(hit.url)
    return summary
