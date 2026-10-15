"""Per-IP abuse profiling over a completed pull.

This module answers "which addresses are behaving badly", **without caring
what they are asking for**. That framing is deliberate. The obvious approach —
find the login endpoint, count failures — does not work on this data at all:

    LoginID          empty in 100% of rows
    SessionID        empty in 100% of rows
    ClientFP         empty in 100% of rows
    CredStuffState   CRED_STUFF_CHECK_NOT_DONE in 100% of rows
    AuthenticatedUser  the Authorization *scheme*, truncated to 10 characters

There is no username in an access-log row and no response body, so a failed
login is indistinguishable from a successful one. Worse, scoping to auth URLs
looks past the actual attacks: on the corpus this module was built from, the
single worst offender sent 182,000 requests — 75% of all traffic to the app —
and never touched an auth endpoint once.

What *is* observable is shape. A browser fetches a page and then its CSS, its
JS and its images; it sends a `Referer` and a `Cookie`; it arrives at human,
ragged intervals. A script does none of those things, whatever it is pointed
at. Every signal here is built from that difference.

Three things this module is careful about:

- **Verified crawlers trip every signal.** A crawler is a non-browser by
  definition: no assets, no cookies, no referer, machine-regular timing. Left
  alone, the ranking fills with Googlebot and Meta. They get their own lane —
  not dropped, because a crawler hammering the origin is still worth seeing.

- **The crawler gate is registry membership, not verification.** Most
  operators publish no prefix list, so `verify()` can only ever return `None`
  for them. Gating the lane on `verify() is True` would route all of Meta
  straight into the threat list, which is exactly the case that motivates
  having a lane.

- **Memory is bounded by a candidate pass.** A 30-day pull has ~92,000
  distinct addresses, of which ~3% account for 80% of the rows. Pass one
  counts; pass two keeps detail for the few that matter.

`BytesSent` includes response headers, so egress here is wire bytes.
"""
from __future__ import annotations

import ipaddress
import logging
import math
from collections import Counter
from datetime import datetime

from app.logpull.crawlers import (
    VERIFY_NO_LIST,
    VERIFY_PUBLISHED,
    VERIFY_UNAVAILABLE,
    RangeVerifier,
    _trim,
    classify_ua,
    crawler_product,
    looks_like_crawler,
)
from app.logpull.windows import MODE_SAMPLE
from app.traffic_insights import (
    STATIC_EXTENSIONS,
    _extension,
    _finding,
    _int,
    _rate,
    _text,
    _unset,
)

logger = logging.getLogger(__name__)

#: Below this many requests an address cannot be profiled — a rate computed
#: from four requests is noise, not evidence. Candidates only.
MIN_REQUESTS = 30

#: Yield to the gevent hub every N rows. The portal runs a single worker, so
#: a multi-minute pass without yielding freezes it for every other user.
YIELD_EVERY_ROWS = 25_000

# Memory ceilings. Each is reported as a flag when hit, never silently.
MAX_CANDIDATES = 20_000
MAX_URLS_PER_IP = 400
MAX_UAS_PER_IP = 60
MAX_SUBNETS = 20_000
MAX_COHORTS = 10_000
#: Timestamps retained per candidate for the interval statistics. A sorted
#: sample is enough for a coefficient of variation; the full series on a
#: 180k-request attacker is not worth 1.4 MB.
MAX_TIMESTAMPS_PER_IP = 20_000

#: Profiles kept in the stored result. Measured at ~490 bytes of JSON each,
#: so this is ~240 KB in the report blob.
TOP_PROFILES = 500
TOP_ROLLUPS = 50
TOP_N = 5

MIN_ROWS_FOR_FINDINGS = 1_000

# --- scoring ---------------------------------------------------------------

#: Ceilings each raw ratio is scaled against before weighting.
RATE_CEILING = 300.0          # requests/minute
ERR_CEILING = 0.30            # share of 4xx
UA_CHURN_CEILING = 10.0       # distinct UAs beyond the first
WAF_CEILING = 0.30            # share of WFMatched=INVALID

ASSET_FLOOR = 0.05            # below this share of assets, "not a browser"
MIN_PAGES_FOR_ASSET_SIGNAL = 50
METRONOME_CV = 0.35           # gap CV below this is machine-regular
MIN_ROWS_FOR_METRONOME = 60
REPEAT_FLOOR = 0.30           # top-URL share above this is hammering
ENTROPY_FLOOR = 2.0
MIN_ROWS_FOR_ENTROPY = 100

WEIGHTS = {
    'impostor': 2.5,
    'err4xx': 2.0,
    'ua_churn': 2.0,
    'no_assets': 1.5,
    'metronome': 1.5,
    'repeat': 1.5,
    'waf': 1.5,
    'rate': 1.0,
    'no_referer': 1.0,
    'no_cookie': 1.0,
    'low_entropy': 1.0,
}

#: Score at or above which an address is worth a human looking at it. Tuned so
#: the Rapid7 scan on the reference corpus lands well clear of the crawlers.
BAND_HIGH = 0.45
BAND_MEDIUM = 0.30

#: Findings must carry one of `report.SECTIONS`' three keys or they land in a
#: bucket nothing renders. The remedy for an abusive address is a WaaS
#: rate-limit or ACL, so this is the honest owner.
CATEGORY = 'waas_config'


def _yield_to_hub():
    try:
        import gevent
        gevent.sleep(0)
    except ImportError:  # pragma: no cover — gevent absent under plain pytest
        pass


def _epoch_ms(value):
    """Milliseconds from `EpochTime`, which arrives as a JSON *string*.

    An `isinstance(value, int)` guard here drops every row and every interval
    metric silently reports zero.
    """
    if _unset(value):
        return None
    try:
        return int(float(str(value).strip().strip('"')))
    except (TypeError, ValueError):
        return None


def _subnet(ip):
    """The /24 (or /48 for v6) an address sits in, or None."""
    try:
        address = ipaddress.ip_address(ip.split('%', 1)[0])
    except ValueError:
        return None
    prefix = 24 if address.version == 4 else 48
    return str(ipaddress.ip_network(f'{ip.split("%", 1)[0]}/{prefix}',
                                    strict=False))


def _entropy(counter):
    """Shannon entropy of a distribution, in bits."""
    total = sum(counter.values())
    if not total:
        return 0.0
    return -sum((c / total) * math.log2(c / total)
                for c in counter.values() if c)


def _cv(values):
    """Coefficient of variation of the gaps between sorted timestamps.

    Returns None when there are too few points to say anything. The series is
    sorted first: within a day the drain's order is not strictly monotonic,
    and unsorted gaps go negative and produce a meaningless statistic.
    """
    if len(values) < 3:
        return None
    ordered = sorted(values)
    gaps = [b - a for a, b in zip(ordered, ordered[1:])]
    if not gaps:
        return None
    mean = sum(gaps) / len(gaps)
    if mean <= 0:
        return None
    variance = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    return math.sqrt(variance) / mean


class _Profile:
    """Mutable per-address state. Scalars plus two bounded collections."""

    __slots__ = ('requests', 'urls', 'uas', 'statuses', 'methods', 'assets',
                 'pages', 'referers', 'cookies', 'bytes_sent', 'countries',
                 'timestamps', 'waf_invalid', 'hosts', 'timestamps_capped',
                 'first_seen', 'last_seen')

    def __init__(self):
        self.requests = 0
        self.urls = Counter()
        self.uas = Counter()
        self.statuses = Counter()
        self.methods = Counter()
        self.assets = 0
        self.pages = 0
        self.referers = 0
        self.cookies = 0
        self.bytes_sent = 0
        self.countries = set()
        # The retained sample, for the regularity statistic only.
        self.timestamps = []
        self.timestamps_capped = False
        # True extremes, tracked as scalars so they survive the cap. The rate
        # divides the FULL request count, so taking the span from the capped
        # sample would divide by a truncated window — on the reference corpus
        # that inflated the headline rate 3.5x and reported a `last_seen` an
        # hour and a half before the attack actually stopped.
        self.first_seen = None
        self.last_seen = None
        self.waf_invalid = 0
        self.hosts = Counter()

    def feed(self, row):
        self.requests += 1

        url = _text(row.get('URL'))
        if url:
            self.urls[url[:200]] += 1
            if _extension(url) in STATIC_EXTENSIONS:
                self.assets += 1
            else:
                self.pages += 1
        else:
            self.pages += 1

        user_agent = _text(row.get('UserAgent'))
        if user_agent:
            self.uas[user_agent] += 1

        status = _int(row.get('HTTPStatus'))
        if status is not None:
            self.statuses[status] += 1

        method = _text(row.get('Method'))
        if method:
            self.methods[method] += 1

        # `_unset` is load-bearing: the sentinel arrives as the three-character
        # string `"-"` *with* its quotes, so it is truthy and a bare check
        # counts every empty field as a present header — inverting both
        # signals rather than merely weakening them.
        if not _unset(row.get('Referer')):
            self.referers += 1
        if not _unset(row.get('Cookie')):
            self.cookies += 1

        self.bytes_sent += _int(row.get('BytesSent')) or 0

        country = _text(row.get('ClientIP_country_code'))
        if country:
            self.countries.add(country)

        host = _text(row.get('Host'))
        if host:
            self.hosts[host[:120]] += 1

        if _text(row.get('WFMatched')).upper() == 'INVALID':
            self.waf_invalid += 1

        stamp = _epoch_ms(row.get('EpochTime'))
        if stamp is not None:
            seconds = stamp / 1000.0
            if self.first_seen is None or seconds < self.first_seen:
                self.first_seen = seconds
            if self.last_seen is None or seconds > self.last_seen:
                self.last_seen = seconds
            if len(self.timestamps) < MAX_TIMESTAMPS_PER_IP:
                self.timestamps.append(seconds)
            else:
                self.timestamps_capped = True

        if len(self.urls) > MAX_URLS_PER_IP * 2:
            _trim(self.urls, MAX_URLS_PER_IP, lambda v: v, {}, 'urls')
        if len(self.uas) > MAX_UAS_PER_IP * 2:
            _trim(self.uas, MAX_UAS_PER_IP, lambda v: v, {}, 'uas')


class AbuseAggregator:
    """Second-pass aggregator: detail for candidate addresses only.

    `candidates` is the set produced by the counting pass. Rows from anything
    else are counted toward the totals and otherwise skipped, which is what
    keeps a 30-day corpus inside a few tens of megabytes.
    """

    #: Signals computed from inter-arrival timing. A sampled pull collects a
    #: 300s slice every 7200s, so these measure the sampling plan rather than
    #: the client: on the reference 30-day sample, 39% of candidates appeared
    #: inside a single window, where every gap is small by construction and
    #: the regularity test fires on everything. Suppressed rather than merely
    #: warned about — a warning does not stop 835 confident false positives.
    TIMING_SIGNALS = ('metronome', 'rate')

    def __init__(self, candidates, verifier=None, sampled=False):
        self.candidates = candidates
        self.verifier = verifier if verifier is not None else RangeVerifier()
        self.sampled = sampled
        self.profiles = {}
        self.rows = 0
        self.skipped_rows = 0
        self.undated_rows = 0
        self.subnets = Counter()
        self.subnet_ips = {}
        self.cohorts = Counter()
        self.cohort_ips = {}
        self.caps = {}

    def feed(self, row):
        self.rows += 1
        client_ip = _text(row.get('ClientIP'))
        if not client_ip:
            self.undated_rows += 1
            return
        if client_ip not in self.candidates:
            self.skipped_rows += 1
            return

        profile = self.profiles.get(client_ip)
        if profile is None:
            if len(self.profiles) >= MAX_CANDIDATES:
                self.caps['candidates'] = True
                self.skipped_rows += 1
                return
            profile = self.profiles[client_ip] = _Profile()
        profile.feed(row)

        subnet = _subnet(client_ip)
        if subnet:
            self.subnets[subnet] += 1
            seen = self.subnet_ips.get(subnet)
            if seen is None:
                seen = self.subnet_ips[subnet] = set()
            seen.add(client_ip)

        user_agent = _text(row.get('UserAgent'))
        if user_agent:
            cohort = user_agent[:120]
            self.cohorts[cohort] += 1
            seen = self.cohort_ips.get(cohort)
            if seen is None:
                seen = self.cohort_ips[cohort] = set()
            seen.add(client_ip)

        if len(self.subnets) > MAX_SUBNETS * 2:
            _trim(self.subnets, MAX_SUBNETS, lambda v: v, self.caps, 'subnets')
            self.subnet_ips = {k: v for k, v in self.subnet_ips.items()
                               if k in self.subnets}
        if len(self.cohorts) > MAX_COHORTS * 2:
            _trim(self.cohorts, MAX_COHORTS, lambda v: v, self.caps, 'cohorts')
            self.cohort_ips = {k: v for k, v in self.cohort_ips.items()
                               if k in self.cohorts}

    # --- classification ---------------------------------------------------

    def _crawler_view(self, ip, profile):
        """How this address's dominant UA classifies.

        Returns `(label, category, verification, verdict)`. `verdict` is the
        tri-state from `RangeVerifier.verify`, kept distinct from
        `verification` because "no list published" and "outside the published
        list" are opposite conclusions.
        """
        if not profile.uas:
            return None, None, None, None
        dominant = profile.uas.most_common(1)[0][0]

        # Match against the FULL UA string. The crawler token usually sits at
        # the *end* ("...; +http://www.google.com/bot.html) Googlebot/2.1"),
        # so matching a truncated prefix silently reclassifies crawlers as
        # suspicious — it under-counted them by a factor of three in testing.
        known = classify_ua(dominant)
        if known is None:
            if looks_like_crawler(dominant):
                return crawler_product(dominant), 'unknown', VERIFY_NO_LIST, None
            return None, None, None, None

        _token, label, category, sources = known
        if not sources:
            return label, category, VERIFY_NO_LIST, None
        if not self.verifier.available(sources):
            return label, category, VERIFY_UNAVAILABLE, None
        return label, category, VERIFY_PUBLISHED, self.verifier.verify(sources, ip)

    # --- scoring ----------------------------------------------------------

    def _score(self, ip, profile, impostor):
        n = profile.requests
        signals = {}

        # True span, not the span of the retained sample — see `_Profile`.
        seconds = 0.0
        if profile.first_seen is not None and profile.last_seen is not None:
            seconds = profile.last_seen - profile.first_seen
        per_minute = (n / (seconds / 60.0)) if seconds > 0 else 0.0
        signals['rate'] = min(1.0, per_minute / RATE_CEILING)

        cv = _cv(profile.timestamps)
        signals['metronome'] = (
            1.0 if (cv is not None and cv < METRONOME_CV
                    and n >= MIN_ROWS_FOR_METRONOME) else 0.0
        )

        asset_share = _rate(profile.assets, n) or 0.0
        signals['no_assets'] = (
            1.0 if (asset_share < ASSET_FLOOR
                    and profile.pages > MIN_PAGES_FOR_ASSET_SIGNAL) else 0.0
        )

        signals['no_referer'] = 1.0 - (_rate(profile.referers, n) or 0.0)
        signals['no_cookie'] = 1.0 - (_rate(profile.cookies, n) or 0.0)

        err4xx = sum(v for s, v in profile.statuses.items() if 400 <= s < 500)
        err_share = _rate(err4xx, n) or 0.0
        signals['err4xx'] = min(1.0, err_share / ERR_CEILING)

        signals['ua_churn'] = min(1.0, max(0, len(profile.uas) - 1)
                                  / UA_CHURN_CEILING)

        top_share = (profile.urls.most_common(1)[0][1] / n) if profile.urls else 0.0
        signals['repeat'] = top_share if top_share > REPEAT_FLOOR else 0.0

        entropy = _entropy(profile.urls)
        signals['low_entropy'] = (
            1.0 if (entropy < ENTROPY_FLOOR and n >= MIN_ROWS_FOR_ENTROPY)
            else 0.0
        )

        waf_share = _rate(profile.waf_invalid, n) or 0.0
        signals['waf'] = min(1.0, waf_share / WAF_CEILING)

        signals['impostor'] = 1.0 if impostor else 0.0

        # On a sampled pull the timing signals describe the sampling plan, not
        # the client. Drop them from both the numerator and the denominator so
        # the remaining signals still span 0..1 rather than being scaled down.
        weights = WEIGHTS
        if self.sampled:
            for key in self.TIMING_SIGNALS:
                signals.pop(key, None)
            weights = {k: v for k, v in WEIGHTS.items()
                       if k not in self.TIMING_SIGNALS}

        score = (sum(signals[k] * weights[k] for k in signals)
                 / sum(weights.values()))
        return score, signals, per_minute, cv, err_share, asset_share, entropy, top_share

    def _profile_row(self, ip, profile):
        label, category, verification, verdict = self._crawler_view(ip, profile)

        # Only a published list can convict. Accusing on a `None` verdict
        # would libel every address of every operator that publishes nothing.
        impostor = bool(label and verification == VERIFY_PUBLISHED
                        and verdict is False)
        verified = bool(label and verification == VERIFY_PUBLISHED
                        and verdict is True)

        (score, signals, per_minute, cv, err_share, asset_share, entropy,
         top_share) = self._score(ip, profile, impostor)

        contributing = sorted(
            (k for k, v in signals.items() if v >= 0.3),
            key=lambda k: -signals[k] * WEIGHTS[k],
        )

        return {
            'ip': ip,
            'requests': profile.requests,
            'score': round(score, 3),
            'band': ('high' if score >= BAND_HIGH
                     else 'medium' if score >= BAND_MEDIUM else 'low'),
            'signals': contributing[:4],
            # Null rather than wrong on a sampled pull: a rate measured across
            # sampling gaps is not this client's rate.
            'rate_per_min': None if self.sampled else round(per_minute, 1),
            'gap_cv': None if self.sampled
            else (round(cv, 2) if cv is not None else None),
            'timing_suppressed': self.sampled,
            'asset_share': round(asset_share, 3),
            'referer_share': round(_rate(profile.referers, profile.requests) or 0.0, 3),
            'cookie_share': round(_rate(profile.cookies, profile.requests) or 0.0, 3),
            'err4xx_share': round(err_share, 3),
            'waf_invalid_share': round(
                _rate(profile.waf_invalid, profile.requests) or 0.0, 3),
            'distinct_urls': len(profile.urls),
            'url_entropy': round(entropy, 2),
            'top_url_share': round(top_share, 3),
            'distinct_uas': len(profile.uas),
            'bytes': profile.bytes_sent,
            'countries': sorted(profile.countries),
            'first_seen': int(profile.first_seen) if profile.first_seen else None,
            'last_seen': int(profile.last_seen) if profile.last_seen else None,
            'crawler': label,
            'crawler_category': category,
            'verification': verification,
            'verified': verified,
            'impostor': impostor,
            'timestamps_capped': profile.timestamps_capped,
            'top_urls': [{'url': u, 'requests': c}
                         for u, c in profile.urls.most_common(TOP_N)],
            'top_uas': [{'user_agent': u[:180], 'requests': c}
                        for u, c in profile.uas.most_common(3)],
            'top_hosts': [{'host': h, 'requests': c}
                          for h, c in profile.hosts.most_common(3)],
            'methods': dict(profile.methods.most_common(6)),
            'status_classes': _status_classes(profile.statuses),
        }

    def result(self, *, scale=1.0, sample=None, ranges_meta=None):
        rows = [self._profile_row(ip, p) for ip, p in self.profiles.items()]

        # Registry membership routes into the lane — NOT `verified`. Most
        # operators publish nothing (all of Meta, Yandex, Baidu, ClaudeBot),
        # so a `verified`-only gate drops them into the threat list, which is
        # the exact failure the lane exists to prevent.
        crawler_rows = [r for r in rows if r['crawler'] and not r['impostor']]
        suspect_rows = [r for r in rows if not r['crawler'] or r['impostor']]

        crawler_rows.sort(key=lambda r: -r['requests'])
        suspect_rows.sort(key=lambda r: (-r['score'], -r['requests']))

        crawler_ips = {r['ip'] for r in crawler_rows}
        data = {
            'generated_at': datetime.utcnow().isoformat(timespec='seconds') + 'Z',
            'rows': self.rows,
            'scale': scale,
            'profiled_ips': len(self.profiles),
            'candidate_ips': len(self.candidates),
            'min_requests': MIN_REQUESTS,
            'skipped_rows': self.skipped_rows,
            'rows_without_ip': self.undated_rows,
            'suspects': suspect_rows[:TOP_PROFILES],
            'suspects_total': len(suspect_rows),
            'flagged_high': sum(1 for r in suspect_rows if r['band'] == 'high'),
            'flagged_medium': sum(1 for r in suspect_rows if r['band'] == 'medium'),
            'crawlers': crawler_rows[:TOP_ROLLUPS],
            'crawlers_total': len(crawler_rows),
            'impostors': [r for r in suspect_rows if r['impostor']][:TOP_ROLLUPS],
            'subnets': self._rollup(self.subnets, self.subnet_ips, crawler_ips),
            'cohorts': self._rollup(self.cohorts, self.cohort_ips, crawler_ips,
                                    truncate=120),
            'caps': dict(self.caps),
            'ranges': ranges_meta or {},
            'sample': sample or {},
        }
        data['findings'] = build_findings(data)
        return data

    def _rollup(self, counter, members, crawler_ips, truncate=None):
        """Group view, with crawler-only groups dropped.

        Without that filter this is just a list of Google, Bing and Meta
        ranges — which is what the unfiltered prototype produced.
        """
        out = []
        for key, requests in counter.most_common(TOP_ROLLUPS * 4):
            ips = members.get(key) or set()
            if len(ips) < 2:
                continue
            if ips <= crawler_ips:
                continue
            scored = [self.profiles[i] for i in ips if i in self.profiles]
            if not scored:
                continue
            out.append({
                'key': key[:truncate] if truncate else key,
                'requests': requests,
                'distinct_ips': len(ips),
                'requests_per_ip': round(requests / len(ips), 1),
                'non_crawler_ips': len(ips - crawler_ips),
            })
            if len(out) >= TOP_ROLLUPS:
                break
        return out


def _status_classes(counter):
    classes = Counter()
    for status, count in counter.items():
        if 100 <= status < 600:
            classes[f'{status // 100}xx'] += count
    return dict(sorted(classes.items()))


# --- findings --------------------------------------------------------------


def _abuse_finding(code, severity, title, detail, evidence, impact=None):
    finding = _finding(code, severity, title, detail, evidence, impact=impact)
    finding['category'] = CATEGORY
    return finding


def build_findings(data):
    if data['rows'] < MIN_ROWS_FOR_FINDINGS:
        return []

    findings = []
    suspects = data['suspects']
    rows = data['rows'] or 1

    # `suspects` is truncated to TOP_PROFILES for storage; the counts are not.
    # Counting the list would silently report the cap instead of the total —
    # "500 addresses" on a corpus that actually had 835.
    high = [r for r in suspects if r['band'] == 'high']
    high_total = data.get('flagged_high', len(high))
    if high:
        worst = high[0]
        share = worst['requests'] / rows
        findings.append(_abuse_finding(
            'abuse_high_confidence',
            'warning',
            f'{high_total:,} address(es) behaving like automated abuse',
            'These addresses do not behave like browsers: the mix of missing '
            'static-asset fetches, absent cookies or referers, error rates and '
            'request timing is characteristic of scripted clients rather than '
            'of people. Worst offender is '
            f'{worst["ip"]} at {worst["requests"]:,} requests '
            f'({share * 100:.1f}% of all traffic in this pull), '
            + (f'{worst["rate_per_min"]:,.0f}/min, '
               if worst.get('rate_per_min') is not None else '')
            + f'{worst["err4xx_share"] * 100:.0f}% 4xx, '
            f'{worst["distinct_uas"]} distinct User-Agents.\n'
            'Consider a rate limit or an ACL on the WaaS application.',
            {'addresses': high_total, 'worst_ip': worst['ip'],
             'worst_requests': worst['requests'],
             'worst_signals': worst['signals']},
            impact=f'{sum(r["requests"] for r in high):,} requests from the '
                   f'{len(high):,} shown' if high_total > len(high)
                   else f'{sum(r["requests"] for r in high):,} requests from '
                        f'{high_total:,} address(es)',
        ))

    impostors = data['impostors']
    if impostors:
        findings.append(_abuse_finding(
            'abuse_crawler_impostor',
            'warning',
            f'{len(impostors)} address(es) impersonating a verified crawler',
            'The User-Agent claims a crawler whose operator publishes its IP '
            'ranges, and these addresses are outside those ranges. Only '
            'operators that publish a list are checked, so this is a positive '
            'mismatch rather than an absence of evidence.',
            {'addresses': len(impostors),
             'examples': [r['ip'] for r in impostors[:5]]},
            impact=f'{sum(r["requests"] for r in impostors):,} requests',
        ))

    spread = [s for s in data['subnets']
              if s['distinct_ips'] >= 5 and s['requests_per_ip'] >= 20]
    if spread:
        worst = spread[0]
        findings.append(_abuse_finding(
            'abuse_subnet_spread',
            'info',
            'Coordinated activity across a single network range',
            f'{worst["key"]} accounts for {worst["requests"]:,} requests '
            f'spread over {worst["distinct_ips"]} addresses '
            f'({worst["requests_per_ip"]:,.0f} each). Per-address rate limits '
            'do not see this pattern; a range-level rule does.',
            {'subnet': worst['key'], 'requests': worst['requests'],
             'distinct_ips': worst['distinct_ips']},
        ))

    if data['sample'].get('mode') == 'sample':
        findings.append(_abuse_finding(
            'abuse_sampled_pull',
            'info',
            'These figures come from a sampled pull',
            'This pull collected a slice of each time window rather than every '
            'row, so request rate and timing regularity cannot be measured — '
            'a burst can fall entirely inside a gap, and an address seen in '
            'only one window has uniformly small gaps whatever it was doing. '
            'Those two signals have been left out of the scores below rather '
            'than scored wrongly. The rest — missing asset fetches, absent '
            'cookies, error rates, User-Agent churn — survive sampling. '
            'Re-run as a full pull to get the timing signals back.',
            {'mode': 'sample', 'suppressed': list(AbuseAggregator.TIMING_SIGNALS)},
        ))

    findings.sort(key=lambda f: 0 if f['severity'] == 'warning' else 1)
    return findings


# --- entry point -----------------------------------------------------------


def count_candidates(store, *, dates=None, min_requests=MIN_REQUESTS,
                     on_progress=None, yield_every=YIELD_EVERY_ROWS):
    """Pass one: how many requests each address made.

    Counting is all this pass does, which is what makes it affordable —
    ~39,000 rows/s at 23 MB for a 30-day corpus. The result narrows pass two
    to roughly 3% of addresses, which between them sent ~80% of the rows.
    """
    counts = Counter()
    rows = 0
    for index, row in enumerate(store.iter_rows(dates=dates), start=1):
        rows = index
        client_ip = _text(row.get('ClientIP'))
        if client_ip:
            counts[client_ip] += 1
        if index % yield_every == 0:
            _yield_to_hub()
            if on_progress is not None:
                on_progress(index)
    candidates = {ip for ip, n in counts.items() if n >= min_requests}
    return candidates, rows, len(counts)


def analyze_pull(store, summary=None, *, dates=None, scale=None,
                 on_progress=None, should_cancel=None,
                 yield_every=YIELD_EVERY_ROWS, verifier=None,
                 ranges_dir=None, ranges_meta=None,
                 min_requests=MIN_REQUESTS):
    """Profile every candidate address in a pull.

    Two passes over the corpus: one to find the addresses worth profiling,
    one to profile them. Twice the read for a bounded working set — the read
    is sequential and gzip-bound, the memory is not.
    """
    summary = summary or {}
    if scale is None:
        scale = summary.get('scale') or 1.0

    if verifier is None:
        if ranges_dir:
            from app.logpull.crawlers import load_ranges
            networks, ranges_meta = load_ranges(ranges_dir)
            verifier = RangeVerifier(networks)
        else:
            verifier = RangeVerifier()

    candidates, total_rows, distinct_ips = count_candidates(
        store, dates=dates, min_requests=min_requests,
        on_progress=on_progress, yield_every=yield_every,
    )

    if should_cancel is not None and should_cancel():
        from app.logpull.windows import Cancelled
        raise Cancelled()

    aggregator = AbuseAggregator(candidates, verifier=verifier,
                                 sampled=summary.get('mode') == MODE_SAMPLE)
    for index, row in enumerate(store.iter_rows(dates=dates), start=1):
        aggregator.feed(row)
        if index % yield_every == 0:
            _yield_to_hub()
            if should_cancel is not None and should_cancel():
                from app.logpull.windows import Cancelled
                raise Cancelled()
            if on_progress is not None:
                on_progress(total_rows + index)

    if on_progress is not None:
        on_progress(total_rows * 2)

    sample = {
        'mode': summary.get('mode'),
        'rows_collected': summary.get('rows_sampled'),
        'rows_total_exact': summary.get('rows_total_exact'),
        'days_collected': summary.get('days_collected'),
        'truncated_windows': summary.get('truncated_windows', 0),
    }
    result = aggregator.result(scale=scale, sample=sample,
                               ranges_meta=ranges_meta)
    result['distinct_ips'] = distinct_ips
    return result
