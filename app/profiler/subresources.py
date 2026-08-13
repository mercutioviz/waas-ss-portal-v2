"""Discover and fetch the resources linked from the landing HTML.

`discover(html, base_url)` runs bs4/lxml over the HTML and returns a
deduplicated list of absolute URLs — cover for `<script src>`, `<link
href>`, `<img src>` (+ `srcset`), `<iframe src>`, `<video src>`, `data-src`
lazy-load, `<link rel=preload/preconnect>`, and CSS `url()` inside inline
`<style>` blocks.

`fetch_all(urls, primary_domain, budget_seconds)` fans out HEAD requests
concurrently in a `gevent.pool.Pool(8)` under a wall-clock budget. HEAD
first, fall back to a streaming GET (≤1KB) if the server rejects HEAD.
The wall-clock cap is graceful — any greenlet still running at deadline
gets its result dropped and `budget_exceeded` set on the report.

Third-party classification uses `tldextract` so cases like `co.uk` are
correct. `tldextract` reads a bundled PSL on first call; we prime it at
import time to keep the first probe fast.
"""

import logging
import re
import time
from typing import Iterable, Optional
from urllib.parse import urljoin, urlparse

import gevent
import gevent.pool
import requests
import tldextract
from bs4 import BeautifulSoup

from app.profiler.schemas import SubresourceHit, SubresourceReport

logger = logging.getLogger(__name__)

SUBRESOURCE_CAP = 30
SUBRESOURCE_BUDGET_SECONDS = 12
POOL_SIZE = 8
PER_REQUEST_TIMEOUT = 5

USER_AGENT = 'WaaS-Portal-Probe/2.0 (+https://v2.ssportal.waaslab.com/profiler)'

_extractor = tldextract.TLDExtract(suffix_list_urls=None, cache_dir=None, fallback_to_snapshot=True)
# Prime the parser (loads the bundled PSL) once at import.
_extractor('example.com')


_CSS_URL_PAT = re.compile(r'''url\(\s*['"]?([^)'"]+)['"]?\s*\)''', re.IGNORECASE)


def _kind_for(tag_name: str, attr: str, url_lc: str) -> str:
    if tag_name == 'script':
        return 'script'
    if tag_name == 'link':
        return 'style' if 'stylesheet' in attr.lower() else 'other'
    if tag_name == 'img':
        return 'image'
    if tag_name == 'iframe':
        return 'iframe'
    if tag_name in ('video', 'audio', 'source'):
        return 'media'
    if url_lc.endswith(('.woff', '.woff2', '.ttf', '.otf', '.eot')):
        return 'font'
    return 'other'


def _absolutize(base_url: str, url: str) -> Optional[str]:
    if not url:
        return None
    url = url.strip()
    if url.startswith(('data:', 'javascript:', 'blob:', 'about:', '#')):
        return None
    return urljoin(base_url, url)


def _add(discovered: dict, base_url: str, tag_name: str, attr: str, raw: str, is_srcset: bool = False) -> None:
    chunks = _split_srcset(raw) if is_srcset else [raw]
    for chunk in chunks:
        abs_url = _absolutize(base_url, chunk)
        if abs_url and abs_url not in discovered:
            discovered[abs_url] = _kind_for(tag_name, attr, abs_url.lower())


def _split_srcset(raw: str) -> list[str]:
    """`img srcset` = comma-separated `url [1x|100w]` pairs.

    Only invoke this on srcset-like attributes; on plain src it would
    mis-split URIs that legitimately contain commas (e.g., `data:` URIs).
    """
    if ',' not in raw:
        return [raw]
    return [p.strip().split()[0] for p in raw.split(',') if p.strip()]


def discover(html: str, base_url: str) -> list[tuple[str, str]]:
    """Return [(absolute_url, kind), …] for every subresource referenced.

    Deduplicated in discovery order. Kind is best-effort — used only for
    the results-page table so a wrong-but-plausible label is fine.
    """
    if not html:
        return []
    try:
        soup = BeautifulSoup(html, 'lxml')
    except Exception:  # pragma: no cover — lxml failures fall back
        soup = BeautifulSoup(html, 'html.parser')

    discovered: dict[str, str] = {}
    for tag in soup.find_all(['script', 'link', 'img', 'iframe', 'video', 'audio', 'source']):
        name = tag.name
        for attr in ('src', 'href', 'data-src', 'data-lazy-src', 'srcset'):
            val = tag.get(attr)
            if val:
                rel_class = tag.get('rel') or ''
                if isinstance(rel_class, list):
                    rel_class = ' '.join(rel_class)
                _add(
                    discovered, base_url, name, rel_class or attr, val,
                    is_srcset=(attr == 'srcset'),
                )

    # CSS url(...) inside inline <style>
    for style in soup.find_all('style'):
        text = style.get_text() or ''
        for m in _CSS_URL_PAT.finditer(text):
            _add(discovered, base_url, 'link', 'stylesheet', m.group(1))

    return list(discovered.items())


def _fetch_one(url: str, kind: str, primary_domain_key: tuple[str, str]) -> SubresourceHit:
    """HEAD-first probe of a single subresource, HTTP timing captured."""
    parsed = urlparse(url)
    host = parsed.hostname or ''
    hit = SubresourceHit(url=url, host=host, kind=kind)

    ext = _extractor(host)
    third_party = (ext.domain, ext.suffix) != primary_domain_key
    hit.third_party = third_party

    started = time.monotonic()
    try:
        r = requests.head(
            url,
            timeout=PER_REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={'User-Agent': USER_AGENT},
        )
        if r.status_code in (405, 501):
            r = requests.get(
                url,
                timeout=PER_REQUEST_TIMEOUT,
                allow_redirects=True,
                headers={'User-Agent': USER_AGENT},
                stream=True,
            )
            r.close()
        hit.status = r.status_code
        clen = r.headers.get('Content-Length')
        if clen:
            try:
                hit.bytes_estimate = int(clen)
            except ValueError:
                pass
    except requests.exceptions.RequestException as e:
        hit.error = str(e)[:200]
    hit.elapsed_ms = int((time.monotonic() - started) * 1000)
    return hit


def fetch_all(
    urls_with_kind: Iterable[tuple[str, str]],
    primary_host: str,
    budget_seconds: float = SUBRESOURCE_BUDGET_SECONDS,
) -> SubresourceReport:
    """Fan out HEAD probes across the URLs, honoring a hard wall-clock cap."""
    all_urls = list(urls_with_kind)
    report = SubresourceReport(discovered_count=len(all_urls))
    if not all_urls:
        return report

    fetch_list = all_urls[:SUBRESOURCE_CAP]
    report.truncated = len(all_urls) > SUBRESOURCE_CAP

    primary = _extractor(primary_host)
    primary_key = (primary.domain, primary.suffix)

    pool = gevent.pool.Pool(POOL_SIZE)
    greenlets = [pool.spawn(_fetch_one, url, kind, primary_key) for url, kind in fetch_list]
    finished = gevent.wait(greenlets, timeout=budget_seconds)
    report.budget_exceeded = len(finished) < len(greenlets)

    for g in greenlets:
        if not g.ready():
            g.kill(block=False)
            continue
        hit = g.value
        if hit is None:
            continue
        report.hits.append(hit)
        if hit.third_party:
            report.third_party_count += 1
            bucket = report.by_third_party_host.setdefault(hit.host, {'count': 0, 'bytes': 0})
            bucket['count'] += 1
            if hit.bytes_estimate:
                bucket['bytes'] += hit.bytes_estimate
        else:
            report.first_party_count += 1
        if hit.bytes_estimate:
            report.total_bytes_estimate += hit.bytes_estimate

    report.analyzed_count = len(report.hits)
    return report
