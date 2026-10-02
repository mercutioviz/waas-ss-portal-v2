"""Performance + traffic-health aggregation over access (LogType=TR) log entries.

Pure functions only — no network calls, no ORM. Mirrors the shape of
app/security_dashboard.py: the caller fetches and filters the logs, this
module only aggregates and draws conclusions.

Three things this module is deliberately careful about, because each one
produces a confidently-wrong finding if handled naively:

1. **Cache hit rate must be split by asset kind and filtered to HTTP 200.**
   Measured over a whole population the rate is meaningless — dynamic
   responses are *supposed* to miss the edge cache, and on a dynamic-heavy
   site they drown out the static assets entirely. On a real 229k-row
   sample the overall hit rate was 0.6% (alarming) while static assets
   alone sat at 63.2% (healthy). Only the static bucket is actionable.

2. **`TimeTaken - ServerTime` goes negative.** The two timestamps come from
   different clocks; a small fraction of rows land below zero. Clamp.

3. **Absent fields arrive as the literal 3-character string `"-"`** (quote,
   dash, quote), not None or ''. `len()` on one of those yields 3.

Percentiles are nearest-rank — no numpy, no new dependency.
"""
from collections import Counter, defaultdict
from math import ceil

# Below this many rows, report the sample size and emit no findings at all.
MIN_SAMPLE = 50
# Per-URL groups smaller than this are too noisy to rank by percentile.
MIN_URL_GROUP = 20
# Static 200s below this count can't support a cache-hit-rate conclusion.
MIN_STATIC_SAMPLE = 20

TOP_N = 5

STATIC_EXTENSIONS = frozenset({
    'js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico',
    'woff', 'woff2', 'ttf', 'otf', 'eot', 'mp4', 'pdf',
})

# Finding thresholds
STATIC_HIT_RATE_FLOOR = 0.5
ORIGIN_SHARE_FLOOR = 0.7
ORIGIN_BOUND_MIN_P50_MS = 500
WAF_OVERHEAD_MIN_P95_MS = 250
WAF_OVERHEAD_SHARE_FLOOR = 0.3
SLOW_URL_P95_MS = 2000
CLIENT_ERROR_RATE_FLOOR = 0.05
SERVER_ERROR_RATE_FLOOR = 0.01


def _unset(value):
    """True if a log field is absent.

    The API renders empty fields as the literal string `"-"` — including the
    surrounding double quotes — so a plain falsiness check isn't enough.
    """
    if value is None:
        return True
    text = str(value).strip().strip('"').strip()
    return text in ('', '-')


def _text(value):
    """The field's real text, or '' when the field is unset."""
    return '' if _unset(value) else str(value)


def _int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip().strip('"'))
    except (TypeError, ValueError):
        return None


def _percentile(values, fraction):
    """Nearest-rank percentile of an unsorted list. None when empty.

    Textbook definition: the smallest value at or below which `fraction` of
    the data falls, i.e. index ceil(fraction * n) - 1.
    """
    if not values:
        return None
    ordered = sorted(values)
    idx = max(ceil(fraction * len(ordered)) - 1, 0)
    return ordered[idx]


def _extension(url):
    """Lowercased file extension of a URL path, or '' if it has none.

    The TR log's `URL` field holds the path only — the query lives in a
    separate `QueryString` field — so there's nothing to strip here.
    """
    segment = _text(url).rsplit('/', 1)[-1]
    if '.' not in segment:
        return ''
    return segment.rsplit('.', 1)[-1].lower()


def _is_static(url):
    return _extension(url) in STATIC_EXTENSIONS


def _top_n(counter):
    return [{'url': url, 'count': count} for url, count in counter.most_common(TOP_N)]


def _rate(numerator, denominator):
    if numerator is None or not denominator:
        return None
    return numerator / denominator


def _summarize_cache(logs):
    """Edge-cache behaviour, split static vs dynamic over HTTP 200 only.

    Non-200 responses are excluded on purpose: a 304 is a successful browser
    revalidation rather than a cache miss to fix, and a 404 was never
    cacheable in the first place. Counting either as a miss inflates the
    rate and produces a finding with no remedy.
    """
    buckets = {
        'static': {'total': 0, 'hits': 0},
        'dynamic': {'total': 0, 'hits': 0},
    }
    uncached_static = Counter()

    for entry in logs:
        if _int(entry.get('HTTPStatus')) != 200:
            continue
        url = _text(entry.get('URL'))
        kind = 'static' if _is_static(url) else 'dynamic'
        buckets[kind]['total'] += 1
        if _int(entry.get('CacheHit')) == 1:
            buckets[kind]['hits'] += 1
        elif kind == 'static' and url:
            uncached_static[url] += 1

    return {
        'static_total': buckets['static']['total'],
        'static_hits': buckets['static']['hits'],
        'static_hit_rate': _rate(buckets['static']['hits'], buckets['static']['total']),
        'dynamic_total': buckets['dynamic']['total'],
        'dynamic_hits': buckets['dynamic']['hits'],
        'dynamic_hit_rate': _rate(buckets['dynamic']['hits'], buckets['dynamic']['total']),
        'top_uncached_static': _top_n(uncached_static),
    }


def _summarize_latency(logs):
    """Total vs origin time, and the WAF overhead between them."""
    totals = []
    origins = []
    overheads = []
    per_url = defaultdict(list)

    for entry in logs:
        total = _int(entry.get('TimeTaken'))
        origin = _int(entry.get('ServerTime'))
        if total is None:
            continue
        totals.append(total)
        url = _text(entry.get('URL'))
        if url:
            per_url[url].append(total)
        if origin is None:
            continue
        origins.append(origin)
        # Total and origin are stamped by different clocks; a small share of
        # rows come back with origin > total. Clamp rather than discard, so
        # the overhead percentiles keep the same denominator as the others.
        overheads.append(max(total - origin, 0))

    total_p50 = _percentile(totals, 0.5)
    origin_p50 = _percentile(origins, 0.5)

    slowest = []
    for url, values in per_url.items():
        if len(values) < MIN_URL_GROUP:
            continue
        slowest.append({'url': url, 'count': len(values), 'p95_ms': _percentile(values, 0.95)})
    slowest.sort(key=lambda row: row['p95_ms'], reverse=True)

    return {
        'sample': len(totals),
        'total_p50_ms': total_p50,
        'total_p95_ms': _percentile(totals, 0.95),
        'total_p99_ms': _percentile(totals, 0.99),
        'origin_p50_ms': origin_p50,
        'origin_p95_ms': _percentile(origins, 0.95),
        'origin_p99_ms': _percentile(origins, 0.99),
        'overhead_p50_ms': _percentile(overheads, 0.5),
        'overhead_p95_ms': _percentile(overheads, 0.95),
        'origin_share_p50': _rate(origin_p50, total_p50),
        'slowest_urls': slowest[:TOP_N],
    }


def _summarize_errors(logs):
    by_class = Counter()
    not_found = Counter()
    server_errors = Counter()
    classified = 0

    for entry in logs:
        status = _int(entry.get('HTTPStatus'))
        if status is None or not 100 <= status <= 599:
            continue
        classified += 1
        bucket = f'{status // 100}xx'
        by_class[bucket] += 1
        url = _text(entry.get('URL'))
        if not url:
            continue
        if status == 404:
            not_found[url] += 1
        elif 500 <= status <= 599:
            server_errors[url] += 1

    return {
        'classified': classified,
        'by_class': {bucket: by_class.get(bucket, 0) for bucket in ('1xx', '2xx', '3xx', '4xx', '5xx')},
        'client_error_rate': _rate(by_class.get('4xx', 0), classified),
        'server_error_rate': _rate(by_class.get('5xx', 0), classified),
        'top_404': _top_n(not_found),
        'top_5xx': _top_n(server_errors),
    }


def _finding(code, severity, title, detail, evidence):
    return {
        'code': code,
        'severity': severity,
        'title': title,
        'detail': detail,
        'evidence': evidence,
    }


def _pct(value):
    return f'{value * 100:.1f}%'


def _cache_findings(cache):
    static_total = cache['static_total']
    hit_rate = cache['static_hit_rate']
    if static_total < MIN_STATIC_SAMPLE or hit_rate is None:
        return []
    if hit_rate >= STATIC_HIT_RATE_FLOOR:
        return []
    return [_finding(
        'cache_static_miss', 'warning',
        'Static assets are mostly missing the edge cache',
        f'Only {cache["static_hits"]} of {static_total} successful static-asset requests '
        f'({_pct(hit_rate)}) were served from the WaaS edge cache — the rest went to the '
        'origin. Check the origin\'s Cache-Control headers on these assets; the edge will '
        'not cache what the origin marks private or no-store.',
        {
            'static_total': static_total,
            'static_hits': cache['static_hits'],
            'static_hit_rate': hit_rate,
            'top_uncached_static': cache['top_uncached_static'],
        },
    )]


def _latency_findings(latency):
    findings = []
    total_p50 = latency['total_p50_ms']
    origin_share = latency['origin_share_p50']

    if (origin_share is not None and total_p50 is not None
            and origin_share >= ORIGIN_SHARE_FLOOR and total_p50 >= ORIGIN_BOUND_MIN_P50_MS):
        findings.append(_finding(
            'latency_origin_bound', 'warning',
            'Response time is dominated by the origin, not the WAF',
            f'Median total response time is {total_p50} ms, of which {latency["origin_p50_ms"]} ms '
            f'({_pct(origin_share)}) is the origin server. The WAF adds a median of '
            f'{latency["overhead_p50_ms"]} ms. Tuning WaaS will not move this number — the '
            'work belongs at the origin, or in caching more of these responses at the edge.',
            {
                'total_p50_ms': total_p50,
                'origin_p50_ms': latency['origin_p50_ms'],
                'overhead_p50_ms': latency['overhead_p50_ms'],
                'origin_share_p50': origin_share,
                'sample': latency['sample'],
            },
        ))

    overhead_p95 = latency['overhead_p95_ms']
    total_p95 = latency['total_p95_ms']
    if (overhead_p95 is not None and total_p95
            and overhead_p95 >= WAF_OVERHEAD_MIN_P95_MS
            and overhead_p95 / total_p95 >= WAF_OVERHEAD_SHARE_FLOOR):
        findings.append(_finding(
            'latency_waf_overhead', 'info',
            'WAF processing is a large share of tail latency',
            f'At the 95th percentile the WAF adds {overhead_p95} ms of the {total_p95} ms total '
            f'({_pct(overhead_p95 / total_p95)}). This is unusual — large request or response '
            'bodies, or an expensive rewrite rule, are the usual causes.',
            {
                'overhead_p95_ms': overhead_p95,
                'total_p95_ms': total_p95,
                'sample': latency['sample'],
            },
        ))

    slow = [row for row in latency['slowest_urls'] if (row['p95_ms'] or 0) >= SLOW_URL_P95_MS]
    if slow:
        findings.append(_finding(
            'latency_slow_urls', 'info',
            'Some URLs are consistently slow',
            f'{len(slow)} URL(s) with at least {MIN_URL_GROUP} requests have a 95th-percentile '
            f'response time of {SLOW_URL_P95_MS} ms or worse. The slowest is '
            f'{slow[0]["url"]} at {slow[0]["p95_ms"]} ms.',
            {'slow_urls': slow},
        ))

    return findings


def _error_findings(errors):
    findings = []
    classified = errors['classified']

    client_rate = errors['client_error_rate']
    if client_rate is not None and client_rate >= CLIENT_ERROR_RATE_FLOOR:
        findings.append(_finding(
            'errors_client', 'warning',
            'High rate of client errors (4xx)',
            f'{errors["by_class"]["4xx"]} of {classified} requests ({_pct(client_rate)}) returned '
            'a 4xx status. Concentrated 404s usually mean a broken rewrite rule, a stale link, '
            'or a bot probing paths that do not exist — the first two are worth fixing, the '
            'third may be worth blocking.',
            {
                'count': errors['by_class']['4xx'],
                'classified': classified,
                'rate': client_rate,
                'top_404': errors['top_404'],
            },
        ))

    server_rate = errors['server_error_rate']
    if server_rate is not None and server_rate >= SERVER_ERROR_RATE_FLOOR:
        findings.append(_finding(
            'errors_server', 'warning',
            'Origin is returning server errors (5xx)',
            f'{errors["by_class"]["5xx"]} of {classified} requests ({_pct(server_rate)}) returned '
            'a 5xx status. These come from the origin, not the WAF — check origin health and '
            'whether the errors cluster on particular URLs.',
            {
                'count': errors['by_class']['5xx'],
                'classified': classified,
                'rate': server_rate,
                'top_5xx': errors['top_5xx'],
            },
        ))

    return findings


def analyze(access_logs, total_from_api=None):
    """Aggregate access-log entries into a performance + traffic-health report.

    access_logs: list of TR (access) log entries as returned by
        WaasClient.get_logs(). Caller filters to LogType=TR.
    total_from_api: the API's reported total for the window, when known. The
        route fetches a single page, so on a busy application this is a
        sample rather than a census and the UI needs to say so.

    Returns a dict with `sample`, `cache`, `latency`, `errors` and `findings`.
    Findings are suppressed entirely below MIN_SAMPLE rows — a handful of
    requests cannot support a percentile or a rate.
    """
    logs = access_logs or []
    rows = len(logs)
    total = total_from_api if total_from_api is not None else rows

    cache = _summarize_cache(logs)
    latency = _summarize_latency(logs)
    errors = _summarize_errors(logs)

    insufficient = rows < MIN_SAMPLE
    findings = []
    if not insufficient:
        findings = _cache_findings(cache) + _latency_findings(latency) + _error_findings(errors)

    severity_rank = {'warning': 0, 'info': 1}
    findings.sort(key=lambda f: severity_rank.get(f['severity'], 2))

    return {
        'sample': {
            'rows': rows,
            'total_from_api': total,
            'truncated': bool(total_from_api) and total_from_api > rows,
            'insufficient': insufficient,
            'min_sample': MIN_SAMPLE,
        },
        'cache': cache,
        'latency': latency,
        'errors': errors,
        'findings': findings,
    }
