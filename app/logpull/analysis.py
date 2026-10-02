"""Cache analysis over a completed pull.

`app/traffic_insights.py` aggregates a single 1000-row page and measures the
**edge** cache (`CacheHit`), latency and error rates. This module reuses that
module's field handling and finding shape but answers questions a single page
cannot:

1. **Revalidation ratio** — `304 / (200 + 304)` per extension. `CacheHit` is
   the WaaS edge cache; this is *browser* behaviour, and the two are
   unrelated. On the production corpus this feature was built from, JS sat at
   0.53%: effectively every script fetch was a full-body transfer.

2. **Repeat fetch** — the same `(ClientIP, URL)` inside one five-minute
   bucket. This is the headline metric, not the 200:304 split, because a
   correctly cached asset produces *no request at all*. A 304 is already a
   failure mode (a full round-trip for nothing); a 200 is total failure. It
   needs a cross-row, cross-page view, which is why it only becomes
   computable once a pull exists.

3. **Per-host breakdown** — a wildcard application spans many hosts and the
   finding usually lives in the split rather than the total. On that same
   corpus one host was 5.5% of requests and 41% of egress.

Three things this module is deliberately careful about:

- **`EpochTime` is a JSON string of milliseconds.** An `isinstance(x, int)`
  guard silently drops every row and the repeat metric reports zero.
- **404s are excluded from the asset rankings** and reported separately. A
  heavily-404ing path outranks every real asset and sends the header audit
  off to probe URLs that do not exist.
- **Memory is bounded.** A full 30-day pull is tens of millions of rows;
  holding every `(bucket, ip, url)` key would not fit. Rows arrive in
  chronological order, so completed five-minute buckets are folded into the
  totals and dropped as the stream advances.

`BytesSent` includes response headers, so egress figures here are wire bytes
rather than body bytes. That is the number that matters for a bandwidth
conversation, but it means a bare 301 is not free.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
from collections import Counter, defaultdict
from datetime import datetime

from app.traffic_insights import (
    STATIC_EXTENSIONS,
    _extension,
    _finding,
    _int,
    _pct,
    _rate,
    _text,
    _unset,
)

logger = logging.getLogger(__name__)

#: Browsers coalesce within a few minutes; five is the bucket the production
#: analysis used and the one the published figures are comparable against.
REPEAT_BUCKET_MS = 300_000

#: Buckets kept open behind the newest one. The drain emits chronologically,
#: so this only absorbs jitter at window boundaries.
RETAIN_BUCKETS = 2

# Memory ceilings. Each is reported as a flag when hit, never silently.
MAX_KEYS_PER_BUCKET = 500_000
MAX_TRACKED_URLS = 200_000
MAX_TRACKED_HOSTS = 5_000
MAX_TRACKED_EXTENSIONS = 200

#: Yield to the gevent hub every N rows. The portal runs a single worker, so
#: parsing millions of rows without yielding freezes it for every other user.
YIELD_EVERY_ROWS = 25_000

TOP_N = 10
TOP_ASSETS_PER_HOST = 6
MAX_AUDIT_HOSTS = 8

# Finding thresholds
MIN_ROWS_FOR_FINDINGS = 1_000
MIN_EXT_SAMPLE = 200
REVALIDATION_FLOOR = 0.05
MIN_STATIC_ROWS = 500
REPEAT_SHARE_FLOOR = 0.05
MIN_HOST_REQUESTS = 500
HOST_EGRESS_SKEW = 2.5
NOT_FOUND_SHARE_FLOOR = 0.02

#: A host must carry at least this many requests before the live audit will
#: probe it. `Host` is client-supplied, so a single injected header must not
#: be able to steer an outbound request.
MIN_AUDIT_HOST_REQUESTS = 50

_HOSTNAME_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
                          r'(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$')

CATEGORY_WAAS = 'waas_config'
CATEGORY_ORIGIN = 'origin'
CATEGORY_ROBOTS = 'robots'


def _yield_to_hub():
    try:
        import gevent
        gevent.sleep(0)
    except ImportError:  # pragma: no cover — gevent absent under plain pytest
        pass


def _epoch_ms(value):
    """Milliseconds from `EpochTime`, or None.

    The API sends this as a JSON *string*. Parsing it as anything else is the
    single most expensive mistake available here, because it fails silently:
    every row is skipped and the repeat metric reports a clean zero.
    """
    if _unset(value):
        return None
    try:
        return int(float(str(value).strip().strip('"')))
    except (TypeError, ValueError):
        return None


def is_auditable_host(host, resolve=True):
    """True if `host` is safe to send an outbound probe to.

    The `Host` field comes off the wire, so it is attacker-controlled. Two
    gates: it has to look like a public DNS name, and it has to resolve to a
    globally routable address. Without the second, a request with
    `Host: metadata.internal` in the log corpus would turn the header audit
    into an outbound probe of the portal's own network.
    """
    name = (host or '').strip().lower().rstrip('.')
    if not name or len(name) > 253 or not _HOSTNAME_RE.match(name):
        return False
    # A dotted-quad passes the name regex. Reject IP literals at the shape
    # gate rather than relying on the resolve step, so the check still holds
    # when it is called without DNS.
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        return False
    if not resolve:
        return True
    try:
        infos = socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    addresses = {info[4][0] for info in infos}
    if not addresses:
        return False
    for raw in addresses:
        try:
            ip = ipaddress.ip_address(raw.split('%', 1)[0])
        except ValueError:
            return False
        if not ip.is_global:
            return False
    return True


class _RepeatTracker:
    """Counts redundant fetches of the same URL by the same client.

    Keyed on `(five-minute bucket, ClientIP, URL)` over static assets only.
    Redundancy is `sum(v - 1)` across keys seen more than once: the first
    fetch is legitimate, every repeat inside the bucket is traffic a working
    cache would have eliminated.

    Buckets older than the newest by more than `RETAIN_BUCKETS` are folded
    into the totals and dropped, which is what keeps this bounded over a
    multi-million-row corpus.
    """

    def __init__(self, retain=RETAIN_BUCKETS, max_keys=MAX_KEYS_PER_BUCKET):
        self.retain = retain
        self.max_keys = max_keys
        self._open = {}
        self._newest = None
        self.tracked_keys = 0
        self.repeated_keys = 0
        self.excess = 0
        self.excess_by_url = Counter()
        self.late_rows = 0
        self.undated_rows = 0
        self.capped = False

    def add(self, bucket, client_ip, url):
        if bucket is None:
            self.undated_rows += 1
            return
        if self._newest is None or bucket > self._newest:
            self._newest = bucket
            self._evict()
        if bucket < self._newest - self.retain:
            # Already folded into the totals; counting it again would
            # double-count the first fetch as a repeat.
            self.late_rows += 1
            return
        counter = self._open.get(bucket)
        if counter is None:
            counter = self._open[bucket] = Counter()
        key = (client_ip, url)
        if key not in counter and len(counter) >= self.max_keys:
            self.capped = True
            return
        counter[key] += 1

    def _evict(self):
        cutoff = self._newest - self.retain
        for bucket in [b for b in self._open if b < cutoff]:
            self._fold(self._open.pop(bucket))

    def _fold(self, counter):
        self.tracked_keys += len(counter)
        for (_ip, url), count in counter.items():
            if count <= 1:
                continue
            self.repeated_keys += 1
            self.excess += count - 1
            if url in self.excess_by_url or len(self.excess_by_url) < MAX_TRACKED_URLS:
                self.excess_by_url[url] += count - 1
            else:
                self.capped = True

    def finish(self):
        for bucket in sorted(self._open):
            self._fold(self._open[bucket])
        self._open.clear()


class CacheAggregator:
    """Streaming aggregator. `feed()` one row at a time, then `result()`."""

    def __init__(self):
        self.rows = 0
        self.bytes_total = 0
        self.status = Counter()
        self.hosts = {}
        self.ext_200 = Counter()
        self.ext_304 = Counter()
        self.ext_bytes_200 = Counter()
        self.static_200 = 0
        self.static_304 = 0
        self.edge = {'static_total': 0, 'static_hits': 0,
                     'dynamic_total': 0, 'dynamic_hits': 0}
        self.not_found = Counter()
        self.not_found_rows = 0
        self.asset_requests = Counter()
        self.asset_bytes = Counter()
        self.url_bytes_sum = Counter()
        self.url_bytes_count = Counter()
        self.repeat = _RepeatTracker()
        self.static_rows = 0
        self.hosts_capped = False
        self.extensions_capped = False
        self.assets_capped = False

    # --- ingest -----------------------------------------------------------

    def _host_bucket(self, host):
        bucket = self.hosts.get(host)
        if bucket is None:
            if len(self.hosts) >= MAX_TRACKED_HOSTS:
                self.hosts_capped = True
                return None
            bucket = self.hosts[host] = {
                'requests': 0, 'bytes': 0, 'static': 0,
                'static_200': 0, 'edge_hits': 0, 'not_found': 0,
            }
        return bucket

    def feed(self, row):
        self.rows += 1

        status = _int(row.get('HTTPStatus'))
        url = _text(row.get('URL'))
        host = _text(row.get('Host')).lower()
        sent = _int(row.get('BytesSent')) or 0
        cache_hit = _int(row.get('CacheHit')) == 1

        self.bytes_total += sent
        if status is not None:
            self.status[status] += 1

        bucket = self._host_bucket(host) if host else None
        if bucket is not None:
            bucket['requests'] += 1
            bucket['bytes'] += sent
            if cache_hit:
                bucket['edge_hits'] += 1

        ext = _extension(url)
        static = ext in STATIC_EXTENSIONS
        if static:
            self.static_rows += 1
            if bucket is not None:
                bucket['static'] += 1

        # Revalidation is a 200-vs-304 question; nothing else participates.
        if status in (200, 304):
            if ext in self.ext_200 or ext in self.ext_304 \
                    or len(self.ext_200) + len(self.ext_304) < MAX_TRACKED_EXTENSIONS:
                if status == 200:
                    self.ext_200[ext] += 1
                    self.ext_bytes_200[ext] += sent
                else:
                    self.ext_304[ext] += 1
            else:
                self.extensions_capped = True
            if static:
                if status == 200:
                    self.static_200 += 1
                else:
                    self.static_304 += 1

        if status == 200:
            kind = 'static' if static else 'dynamic'
            self.edge[f'{kind}_total'] += 1
            if cache_hit:
                self.edge[f'{kind}_hits'] += 1
            if static and url:
                key = (host, url)
                if key in self.asset_requests or len(self.asset_requests) < MAX_TRACKED_URLS:
                    self.asset_requests[key] += 1
                    self.asset_bytes[key] += sent
                else:
                    self.assets_capped = True
                if url in self.url_bytes_count or len(self.url_bytes_count) < MAX_TRACKED_URLS:
                    self.url_bytes_sum[url] += sent
                    self.url_bytes_count[url] += 1

        if status == 404:
            self.not_found_rows += 1
            if bucket is not None:
                bucket['not_found'] += 1
            if url and (url in self.not_found or len(self.not_found) < MAX_TRACKED_URLS):
                self.not_found[url] += 1

        # Repeat fetch: static assets only, and 304s count. A conditional
        # round-trip that returns "unchanged" is still a request the browser
        # did not need to make.
        if static and url and status in (200, 304):
            client_ip = _text(row.get('ClientIP'))
            if client_ip:
                ms = _epoch_ms(row.get('EpochTime'))
                self.repeat.add(ms // REPEAT_BUCKET_MS if ms is not None else None,
                                client_ip, url)

    # --- output -----------------------------------------------------------

    def _avg_bytes(self, url):
        count = self.url_bytes_count.get(url, 0)
        if not count:
            return 0
        return self.url_bytes_sum.get(url, 0) / count

    def _revalidation(self):
        rows = []
        for ext in set(self.ext_200) | set(self.ext_304):
            ok = self.ext_200[ext]
            revalidated = self.ext_304[ext]
            total = ok + revalidated
            if not total:
                continue
            rows.append({
                'extension': ext or '(none)',
                'static': ext in STATIC_EXTENSIONS,
                'full': ok,
                'revalidated': revalidated,
                'total': total,
                'ratio': _rate(revalidated, total),
                'bytes_full': self.ext_bytes_200[ext],
            })
        rows.sort(key=lambda r: -r['bytes_full'])
        static_total = self.static_200 + self.static_304
        return {
            'by_extension': rows[:TOP_N * 2],
            'static_full': self.static_200,
            'static_revalidated': self.static_304,
            'static_ratio': _rate(self.static_304, static_total),
            'capped': self.extensions_capped,
        }

    def _repeat_summary(self, scale):
        self.repeat.finish()
        excess = self.repeat.excess
        top = []
        for url, count in self.repeat.excess_by_url.most_common(TOP_N):
            avg = self._avg_bytes(url)
            top.append({
                'url': url,
                'excess': count,
                'bytes': int(count * avg),
                'avg_bytes': int(avg),
            })
        excess_bytes = sum(
            int(count * self._avg_bytes(url))
            for url, count in self.repeat.excess_by_url.items()
        )
        return {
            'bucket_seconds': REPEAT_BUCKET_MS // 1000,
            'static_rows': self.static_rows,
            'tracked_keys': self.repeat.tracked_keys,
            'repeated_keys': self.repeat.repeated_keys,
            'excess_requests': excess,
            'excess_share': _rate(excess, self.static_rows),
            'excess_bytes': excess_bytes,
            'extrapolated_requests': int(excess * scale),
            'extrapolated_bytes': int(excess_bytes * scale),
            'undated_rows': self.repeat.undated_rows,
            'late_rows': self.repeat.late_rows,
            'capped': self.repeat.capped,
            'top': top,
        }

    def _host_rows(self, scale):
        rows = []
        for host, bucket in self.hosts.items():
            request_share = _rate(bucket['requests'], self.rows)
            byte_share = _rate(bucket['bytes'], self.bytes_total)
            rows.append({
                'host': host,
                'requests': bucket['requests'],
                'bytes': bucket['bytes'],
                'static': bucket['static'],
                'not_found': bucket['not_found'],
                'edge_hits': bucket['edge_hits'],
                'request_share': request_share,
                'byte_share': byte_share,
                'skew': (byte_share / request_share) if request_share else None,
                'extrapolated_bytes': int(bucket['bytes'] * scale),
            })
        rows.sort(key=lambda r: -r['bytes'])
        return rows

    def audit_targets(self, check_host=is_auditable_host):
        """Busiest successful static assets per host, for the live audit.

        404s never reach this list — they are excluded upstream — because a
        path that 404s outranks real assets on a misconfigured site and would
        send the audit off to probe URLs that do not exist.
        """
        by_host = defaultdict(list)
        for (host, url), count in self.asset_requests.most_common():
            if len(by_host[host]) < TOP_ASSETS_PER_HOST:
                by_host[host].append({
                    'host': host,
                    'url': url,
                    'requests': count,
                    'bytes': self.asset_bytes[(host, url)],
                })

        ranked = sorted(
            by_host,
            key=lambda h: -sum(item['requests'] for item in by_host[h]),
        )
        targets = []
        skipped = []
        hosts_added = 0
        for host in ranked:
            if hosts_added >= MAX_AUDIT_HOSTS:
                break
            requests_here = self.hosts.get(host, {}).get('requests', 0)
            if requests_here < MIN_AUDIT_HOST_REQUESTS:
                continue
            if not check_host(host):
                skipped.append(host)
                continue
            targets.extend(by_host[host])
            hosts_added += 1
        return targets, skipped

    def result(self, *, scale=1.0, sample=None, check_host=is_auditable_host):
        scale = scale or 1.0
        revalidation = self._revalidation()
        repeat = self._repeat_summary(scale)
        hosts = self._host_rows(scale)
        targets, skipped = self.audit_targets(check_host)

        edge = dict(self.edge)
        edge['static_hit_rate'] = _rate(edge['static_hits'], edge['static_total'])
        edge['dynamic_hit_rate'] = _rate(edge['dynamic_hits'], edge['dynamic_total'])

        not_found = {
            'rows': self.not_found_rows,
            'share': _rate(self.not_found_rows, self.rows),
            'top': [{'url': url, 'count': count}
                    for url, count in self.not_found.most_common(TOP_N)],
        }

        data = {
            'generated_at': datetime.utcnow().isoformat(),
            'sample': dict(sample or {}, rows=self.rows, scale=scale,
                           bytes=self.bytes_total,
                           extrapolated_bytes=int(self.bytes_total * scale)),
            'revalidation': revalidation,
            'repeat_fetch': repeat,
            'hosts': hosts[:TOP_N * 2],
            'host_count': len(self.hosts),
            'edge_cache': edge,
            'not_found': not_found,
            'status_classes': _status_classes(self.status),
            'audit_targets': targets,
            'audit_skipped_hosts': skipped,
            'caps': {
                'hosts': self.hosts_capped,
                'extensions': self.extensions_capped,
                'assets': self.assets_capped,
                'repeat': self.repeat.capped,
            },
        }
        data['findings'] = build_findings(data)
        return data


def _status_classes(counter):
    classes = Counter()
    for status, count in counter.items():
        classes[f'{status // 100}xx'] += count
    return dict(sorted(classes.items()))


# --- findings --------------------------------------------------------------


def _cache_finding(code, severity, category, title, detail, evidence):
    finding = _finding(code, severity, title, detail, evidence)
    finding['category'] = category
    return finding


def build_findings(data):
    """Turn the aggregates into recommendations, tagged by who can act.

    The category matters as much as the finding: a customer needs to know
    whether the fix is a portal setting, a change on their own origin, or a
    file only they can deploy.
    """
    findings = []
    rows = data['sample'].get('rows') or 0
    if rows < MIN_ROWS_FOR_FINDINGS:
        return findings

    findings.extend(_edge_findings(data))
    findings.extend(_revalidation_findings(data))
    findings.extend(_repeat_findings(data))
    findings.extend(_host_findings(data))
    findings.extend(_not_found_findings(data))

    rank = {'warning': 0, 'info': 1}
    findings.sort(key=lambda f: rank.get(f['severity'], 2))
    return findings


def _edge_findings(data):
    edge = data['edge_cache']
    total = edge['static_total']
    if total < MIN_STATIC_ROWS:
        return []
    if edge['static_hits']:
        return []
    return [_cache_finding(
        'edge_cache_inactive', 'warning', CATEGORY_WAAS,
        'The WaaS edge cache served none of the static assets',
        f'Not one of {total:,} successful static-asset requests was served from the '
        'edge cache. That is the signature of caching being switched off for the '
        'application rather than of a poor hit rate — a cache that is enabled but '
        'badly tuned still hits sometimes. Check the application\'s CDN/caching '
        'settings before changing anything at the origin.',
        {'static_total': total, 'static_hits': 0},
    )]


def _revalidation_findings(data):
    reval = data['revalidation']
    offenders = [
        row for row in reval['by_extension']
        if row['static'] and row['total'] >= MIN_EXT_SAMPLE
        and (row['ratio'] or 0) < REVALIDATION_FLOOR
    ]
    if not offenders:
        return []
    offenders.sort(key=lambda r: -r['bytes_full'])
    worst = offenders[0]
    names = ', '.join(f'.{row["extension"]}' for row in offenders[:5])
    return [_cache_finding(
        'browser_revalidation_low', 'warning', CATEGORY_ORIGIN,
        'Browsers are re-downloading static assets instead of revalidating',
        f'Across {names}, only {_pct(worst["ratio"] or 0)} of responses on the worst '
        f'extension (.{worst["extension"]}) were 304s — the rest shipped the full body '
        'again. This is browser caching, not the WaaS edge cache, so it is governed by '
        'the Cache-Control and validator headers the origin sends. Assets with no '
        'freshness lifetime force a round-trip on every page load; assets whose '
        'validators the origin will not accept force a full transfer on every load.',
        {'extensions': offenders[:5],
         'static_ratio': reval['static_ratio'],
         'static_full': reval['static_full'],
         'static_revalidated': reval['static_revalidated']},
    )]


def _repeat_findings(data):
    repeat = data['repeat_fetch']
    if repeat['static_rows'] < MIN_STATIC_ROWS:
        return []
    share = repeat['excess_share'] or 0
    if share < REPEAT_SHARE_FLOOR:
        return []
    extrapolated = repeat['extrapolated_requests']
    scale = data['sample'].get('scale') or 1.0
    projected = (f' Extrapolated across the full window that is about '
                 f'{extrapolated:,} requests and '
                 f'{repeat["extrapolated_bytes"] / 1e9:.2f} GB.') if scale > 1.01 else ''
    return [_cache_finding(
        'repeat_fetch', 'warning', CATEGORY_ORIGIN,
        'The same clients refetch the same assets within minutes',
        f'{repeat["excess_requests"]:,} static-asset requests ({_pct(share)} of all '
        f'static traffic sampled) were the same client asking for the same URL again '
        f'inside a {repeat["bucket_seconds"] // 60}-minute window.{projected} '
        'This is the clearest measure of cache failure available, because a correctly '
        'cached asset generates no request at all — a 304 already costs a full '
        'round-trip, and a 200 costs the whole body. Fixing the freshness lifetime on '
        'these URLs removes the requests rather than making them cheaper.',
        {'excess_requests': repeat['excess_requests'],
         'excess_share': share,
         'excess_bytes': repeat['excess_bytes'],
         'extrapolated_requests': extrapolated,
         'extrapolated_bytes': repeat['extrapolated_bytes'],
         'top': repeat['top']},
    )]


def _host_findings(data):
    hosts = data['hosts']
    if len(hosts) < 2:
        return []
    skewed = [
        row for row in hosts
        if row['requests'] >= MIN_HOST_REQUESTS and (row['skew'] or 0) >= HOST_EGRESS_SKEW
    ]
    if not skewed:
        return []
    worst = skewed[0]
    return [_cache_finding(
        'host_egress_skew', 'info', CATEGORY_ORIGIN,
        'One host accounts for far more bandwidth than traffic',
        f'{worst["host"]} is {_pct(worst["request_share"] or 0)} of requests but '
        f'{_pct(worst["byte_share"] or 0)} of bytes sent. On an application covering '
        'several hostnames the useful work is usually concentrated like this, and a '
        'change scoped to that host moves the bandwidth bill further than a change '
        'applied evenly across all of them.',
        {'hosts': skewed[:5], 'host_count': data['host_count']},
    )]


def _not_found_findings(data):
    not_found = data['not_found']
    share = not_found['share'] or 0
    if share < NOT_FOUND_SHARE_FLOOR or not not_found['top']:
        return []
    return [_cache_finding(
        'not_found_volume', 'info', CATEGORY_ORIGIN,
        'A measurable share of requests are 404s',
        f'{not_found["rows"]:,} requests ({_pct(share)}) returned 404. These are '
        'excluded from the asset rankings above, because a path that 404s in a loop '
        'outranks every real asset and tells you nothing about caching. They are '
        'listed here instead: a 404 served repeatedly is usually a stale reference in '
        'a page or a crawler walking URLs that were never real.',
        {'rows': not_found['rows'], 'share': share, 'top': not_found['top']},
    )]


# --- entry point -----------------------------------------------------------


def analyze_pull(store, summary=None, *, dates=None, scale=None,
                 on_progress=None, should_cancel=None,
                 yield_every=YIELD_EVERY_ROWS, check_host=is_auditable_host,
                 ranges_dir=None, crawler_verifier=None, ranges_meta=None):
    """Stream a pull's rows off disk and aggregate them.

    store: `PullStore` for the pull.
    summary: the collection summary the runner produced, used for the
        measured scale factor and the truncation flags.
    scale: override the measured factor (tests, re-analysis of a partial).
    ranges_dir: where published crawler prefix lists are cached. Given one,
        the lists are refreshed before the pass so crawler UAs can be checked
        against them; without one, crawlers are still classified and counted
        but every claim is reported as unverifiable.

    Both aggregators are fed from a single pass. The corpus is the expensive
    thing to read, and crawler classification needs the same rows the cache
    metrics do.

    Yields to the gevent hub every `yield_every` rows. Without that, parsing
    a multi-million-row corpus blocks the single worker and the portal stops
    answering requests for everyone until it finishes.
    """
    from app.logpull.crawlers import CrawlerAggregator, RangeVerifier, load_ranges

    summary = summary or {}
    if scale is None:
        scale = summary.get('scale') or 1.0

    if crawler_verifier is None:
        if ranges_dir:
            networks, ranges_meta = load_ranges(ranges_dir)
            crawler_verifier = RangeVerifier(networks)
        else:
            crawler_verifier = RangeVerifier()

    aggregator = CacheAggregator()
    crawlers = CrawlerAggregator(verifier=crawler_verifier)
    for index, row in enumerate(store.iter_rows(dates=dates), start=1):
        aggregator.feed(row)
        crawlers.feed(row)
        if index % yield_every == 0:
            _yield_to_hub()
            if should_cancel is not None and should_cancel():
                from app.logpull.windows import Cancelled
                raise Cancelled()
            if on_progress is not None:
                on_progress(index)

    if on_progress is not None:
        on_progress(aggregator.rows)

    sample = {
        'mode': summary.get('mode'),
        'rows_collected': summary.get('rows_sampled'),
        'rows_total_exact': summary.get('rows_total_exact'),
        'days_collected': summary.get('days_collected'),
        'truncated_windows': summary.get('truncated_windows', 0),
        'raw_deleted': False,
    }
    result = aggregator.result(scale=scale, sample=sample, check_host=check_host)
    result['crawlers'] = crawlers.result(scale=scale, ranges_meta=ranges_meta)

    # One recommendation list, not two. The reader cares about what to change,
    # not about which pass noticed it.
    merged = (result.get('findings') or []) + (result['crawlers'].get('findings') or [])
    merged.sort(key=lambda f: 0 if f['severity'] == 'warning' else 1)
    result['findings'] = merged
    return result
