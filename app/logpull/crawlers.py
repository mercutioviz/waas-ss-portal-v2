"""Crawler classification and IP verification over a completed pull.

A User-Agent string is a claim, not an identity. Anyone can send
`Googlebot/2.1`, and on a real corpus plenty of clients do. So every per-bot
number this module produces is split three ways rather than two:

    verified      ClientIP falls inside a prefix the operator publishes
    impostor      the UA claims a crawler whose ranges are published, and the
                  IP is not in any of them — the claim is false
    unverifiable  the operator publishes no machine-readable range list

The third state is the one that matters. Collapsing it into "impostor" turns
every unlisted crawler into a fake, and collapsing it into "verified" hands
a spoofer a free pass. ClaudeBot, PetalBot, Bytespider, AhrefsBot and most
of the rest publish nothing, so they are counted and reported as claims.

**Containment, never substring matching.** `'34.64.' in '27.34.64.9'` is
true, and that kind of test is why this module uses `ipaddress` networks.

Classification is deliberately conservative about what it calls a crawler:

- Known tokens are matched longest-first, so `Applebot-Extended` is not
  silently folded into `Applebot` — they are different crawlers with
  different opt-outs.
- Anything else carrying a bot-ish marker is counted as "other self-declared
  crawler" with its UA string shown, rather than being classified by guess.
  That bucket is a lower bound by construction, and showing the strings lets
  the reader judge what landed there.

Crawler traffic is also cross-tabulated against the URL space, because
"crawlers are 38% of requests" is not actionable on its own. What makes it
actionable is which path prefixes and which query parameters they spend that
budget on — which is exactly the input the robots.txt proposal engine needs.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime

from app.traffic_insights import _finding, _int, _pct, _rate, _text

logger = logging.getLogger(__name__)

CATEGORY_WAAS = 'waas_config'
CATEGORY_ROBOTS = 'robots'

# --- published range lists -------------------------------------------------

#: Only these four operators publish a machine-readable prefix list. Google's
#: three files cover different crawler families and are not interchangeable:
#: Googlebot is in common-crawlers, AdsBot and the inspection tool are in
#: special-crawlers, and the fetchers users trigger by hand are separate
#: again. Verifying against the wrong file reports a real crawler as a fake.
SOURCE_URLS = {
    'google-common': 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',
    'google-special': 'https://developers.google.com/static/crawling/ipranges/special-crawlers.json',
    'google-fetch': 'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json',
    'bing': 'https://www.bing.com/toolbox/bingbot.json',
    'apple': 'https://search.developer.apple.com/applebot.json',
    'openai-gptbot': 'https://openai.com/gptbot.json',
    'openai-search': 'https://openai.com/searchbot.json',
    'openai-user': 'https://openai.com/chatgpt-user.json',
}

CACHE_DIR_NAME = 'crawler_ranges'

#: Operators republish these when their fleets move. A week is well inside
#: the rate at which prefixes actually change and keeps the analysis from
#: making eight outbound requests every time someone re-runs it.
RANGE_MAX_AGE_SECONDS = 7 * 86400
RANGE_FETCH_TIMEOUT = 15.0

# --- crawler registry ------------------------------------------------------

CAT_SEARCH = 'search'
CAT_AI = 'ai'
CAT_SEO = 'seo'
CAT_SOCIAL = 'social'
CAT_ARCHIVE = 'archive'
CAT_MONITOR = 'monitoring'

CATEGORY_LABELS = {
    CAT_SEARCH: 'Search engine',
    CAT_AI: 'AI / LLM',
    CAT_SEO: 'SEO / marketing',
    CAT_SOCIAL: 'Social preview',
    CAT_ARCHIVE: 'Archive',
    CAT_MONITOR: 'Monitoring',
}

#: (match token, display label, category, verification sources).
#: Tokens are matched case-insensitively against the UA, longest first.
CRAWLERS = (
    # Search
    ('googlebot', 'Googlebot', CAT_SEARCH, ('google-common',)),
    ('googleother', 'GoogleOther', CAT_SEARCH, ('google-common', 'google-special')),
    ('google-inspectiontool', 'Google-InspectionTool', CAT_SEARCH, ('google-special',)),
    ('storebot-google', 'Storebot-Google', CAT_SEARCH, ('google-special',)),
    ('adsbot-google', 'AdsBot-Google', CAT_SEARCH, ('google-special',)),
    ('apis-google', 'APIs-Google', CAT_SEARCH, ('google-special',)),
    ('feedfetcher-google', 'FeedFetcher-Google', CAT_SEARCH, ('google-fetch',)),
    ('google-safety', 'Google-Safety', CAT_SEARCH, ('google-special',)),
    ('bingbot', 'bingbot', CAT_SEARCH, ('bing',)),
    ('bingpreview', 'BingPreview', CAT_SEARCH, ('bing',)),
    ('applebot-extended', 'Applebot-Extended', CAT_AI, ('apple',)),
    ('applebot', 'Applebot', CAT_SEARCH, ('apple',)),
    ('duckduckbot', 'DuckDuckBot', CAT_SEARCH, ()),
    ('yandexbot', 'YandexBot', CAT_SEARCH, ()),
    ('baiduspider', 'Baiduspider', CAT_SEARCH, ()),
    ('seznambot', 'SeznamBot', CAT_SEARCH, ()),
    ('qwantbot', 'Qwantbot', CAT_SEARCH, ()),
    ('petalbot', 'PetalBot', CAT_SEARCH, ()),
    ('sogou', 'Sogou', CAT_SEARCH, ()),
    ('naver', 'Naver', CAT_SEARCH, ()),
    # AI / LLM
    ('gptbot', 'GPTBot', CAT_AI, ('openai-gptbot',)),
    ('oai-searchbot', 'OAI-SearchBot', CAT_AI, ('openai-search',)),
    ('chatgpt-user', 'ChatGPT-User', CAT_AI, ('openai-user',)),
    ('claude-searchbot', 'Claude-SearchBot', CAT_AI, ()),
    ('claude-user', 'Claude-User', CAT_AI, ()),
    ('claudebot', 'ClaudeBot', CAT_AI, ()),
    ('anthropic-ai', 'anthropic-ai', CAT_AI, ()),
    ('perplexity-user', 'Perplexity-User', CAT_AI, ()),
    ('perplexitybot', 'PerplexityBot', CAT_AI, ()),
    ('bytespider', 'Bytespider', CAT_AI, ()),
    ('amazonbot', 'Amazonbot', CAT_AI, ()),
    ('ccbot', 'CCBot', CAT_AI, ()),
    ('meta-externalagent', 'meta-externalagent', CAT_AI, ()),
    ('mistralai-user', 'MistralAI-User', CAT_AI, ()),
    ('cohere-ai', 'cohere-ai', CAT_AI, ()),
    ('youbot', 'YouBot', CAT_AI, ()),
    ('diffbot', 'Diffbot', CAT_AI, ()),
    # SEO / marketing
    ('ahrefsbot', 'AhrefsBot', CAT_SEO, ()),
    ('semrushbot', 'SemrushBot', CAT_SEO, ()),
    ('mj12bot', 'MJ12bot', CAT_SEO, ()),
    ('dataforseobot', 'DataForSeoBot', CAT_SEO, ()),
    ('siteauditbot', 'SiteAuditBot', CAT_SEO, ()),
    ('blexbot', 'BLEXBot', CAT_SEO, ()),
    ('barkrowler', 'Barkrowler', CAT_SEO, ()),
    ('serpstatbot', 'serpstatbot', CAT_SEO, ()),
    ('zoominfobot', 'ZoominfoBot', CAT_SEO, ()),
    ('screaming frog', 'Screaming Frog', CAT_SEO, ()),
    ('dotbot', 'DotBot', CAT_SEO, ()),
    # Social preview
    ('facebookexternalhit', 'facebookexternalhit', CAT_SOCIAL, ()),
    ('meta-externalads', 'meta-externalads', CAT_SOCIAL, ()),
    ('twitterbot', 'Twitterbot', CAT_SOCIAL, ()),
    ('linkedinbot', 'LinkedInBot', CAT_SOCIAL, ()),
    ('pinterestbot', 'Pinterestbot', CAT_SOCIAL, ()),
    ('slackbot', 'Slackbot', CAT_SOCIAL, ()),
    ('discordbot', 'Discordbot', CAT_SOCIAL, ()),
    ('telegrambot', 'TelegramBot', CAT_SOCIAL, ()),
    ('whatsapp', 'WhatsApp', CAT_SOCIAL, ()),
    ('redditbot', 'redditbot', CAT_SOCIAL, ()),
    # Archive
    ('archive.org_bot', 'archive.org_bot', CAT_ARCHIVE, ()),
    ('ia_archiver', 'ia_archiver', CAT_ARCHIVE, ()),
    # Monitoring
    ('uptimerobot', 'UptimeRobot', CAT_MONITOR, ()),
    ('pingdom', 'Pingdom', CAT_MONITOR, ()),
    ('statuscake', 'StatusCake', CAT_MONITOR, ()),
    ('site24x7', 'Site24x7', CAT_MONITOR, ()),
    ('censys', 'Censys', CAT_MONITOR, ()),
    ('internetmeasurement', 'InternetMeasurement', CAT_MONITOR, ()),
)

#: Longest first so `applebot-extended` is not swallowed by `applebot`.
_ORDERED = tuple(sorted(CRAWLERS, key=lambda c: len(c[0]), reverse=True))

#: Markers for crawlers that are not in the registry. A lower bound: this
#: only catches clients that say so in the UA.
_GENERIC_MARKERS = ('bot', 'spider', 'crawl', 'scrapy', 'fetcher')

#: Substrings that contain a marker but are not crawlers. `CUBOT` is a phone
#: brand and appears in ordinary Android UA strings.
_GENERIC_EXCLUDE = ('cubot',)

#: The optional leading word catches products written with a space in them
#: ("HubSpot Crawler", "Light Crawler"), which would otherwise all collapse
#: into a single meaningless "Crawler" bucket.
_UA_PRODUCT_RE = re.compile(
    r'(?:[A-Za-z][A-Za-z0-9._\-]* )?[A-Za-z0-9._\-]*(?:bot|crawler|spider)'
    r'[A-Za-z0-9._\-]*',
    re.IGNORECASE)

#: A match that is nothing but the marker itself tells the reader nothing.
_BARE_PRODUCTS = {'bot', 'crawler', 'spider', 'bots', 'crawlers', 'spiders'}

#: Tables are trimmed back to these sizes when they grow past twice them.
#: A hard cap would freeze the table at whatever appeared first; trimming
#: keeps the heavy hitters, which are the only rows that get reported.
PREFIX_KEEP = 20_000
QUERY_KEY_KEEP = 5_000
URLS_KEEP = 2_000
OTHER_UA_KEEP = 1_000
MAX_IPS_PER_CRAWLER = 5_000
MAX_VERIFY_CACHE = 200_000

TOP_N = 10
TOP_URLS = 8
TOP_IPS = 5

# Finding thresholds
MIN_ROWS_FOR_FINDINGS = 1_000
CRAWLER_SHARE_INFO = 0.10
CRAWLER_SHARE_WARN = 0.30
MIN_IMPOSTOR_REQUESTS = 100
IMPOSTOR_SHARE_FLOOR = 0.05
AI_SHARE_FLOOR = 0.15
SEO_SHARE_FLOOR = 0.10
MIN_CATEGORY_REQUESTS = 500
QUERY_TRAP_SHARE = 0.25
MIN_QUERY_TRAP_REQUESTS = 500

#: A parameter is worth naming when crawlers are over-represented on it
#: relative to how much of the traffic they are overall. A flat "more than
#: half" test hides the interesting ones: on a corpus that is 8.7% crawler,
#: a parameter at 46% is a five-fold enrichment and obviously a trap, but it
#: never clears 50%.
QUERY_KEY_ENRICHMENT = 2.5
QUERY_KEY_MIN_SHARE = 0.25

URL_SPACE_DOMINANCE = 0.80
#: Absolute, not a share of the corpus. A prefix can be a rounding error
#: overall and still be thousands of requests nobody wanted served.
URL_SPACE_MIN_REQUESTS = 1_000

VERIFY_PUBLISHED = 'published_list'
VERIFY_NO_LIST = 'no_published_list'
VERIFY_UNAVAILABLE = 'list_unavailable'


# --- range lists -----------------------------------------------------------


def parse_prefixes(payload):
    """`ipaddress` networks from one published list.

    Google, Bing, Apple and OpenAI all use the same `{"prefixes": [{...}]}`
    shape with `ipv4Prefix`/`ipv6Prefix` keys. A prefix that will not parse is
    skipped rather than failing the file — a single malformed entry upstream
    should not take the whole crawler's verification offline.
    """
    networks = []
    if not isinstance(payload, dict):
        return networks
    for entry in payload.get('prefixes') or []:
        if not isinstance(entry, dict):
            continue
        raw = entry.get('ipv4Prefix') or entry.get('ipv6Prefix')
        if not raw:
            continue
        try:
            networks.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            logger.debug('crawler ranges: skipping unparseable prefix %r', raw)
    return networks


def _fetch_json(url, timeout=RANGE_FETCH_TIMEOUT):
    import requests

    response = requests.get(url, timeout=timeout,
                            headers={'Accept': 'application/json'})
    response.raise_for_status()
    return response.json()


def load_ranges(cache_dir, *, max_age_seconds=RANGE_MAX_AGE_SECONDS,
                fetch=_fetch_json, now=None, sources=None):
    """Load every published prefix list, refreshing the on-disk cache.

    Returns `(networks, meta)` where `networks` maps a source key to its
    parsed networks and `meta` records, per source, how many prefixes loaded
    and whether the copy is fresh, stale or missing.

    A source that cannot be fetched and has no cached copy comes back with no
    networks, and the aggregator then reports every crawler that depends on
    it as *unverifiable* rather than as an impostor. Verification going
    offline must never manufacture accusations.
    """
    now = now if now is not None else time.time()
    sources = sources or SOURCE_URLS
    networks = {}
    meta = {}

    for key, url in sources.items():
        path = os.path.join(cache_dir, f'{key}.json')
        age = None
        payload = None
        if os.path.exists(path):
            try:
                age = now - os.path.getmtime(path)
                with open(path, 'r', encoding='utf-8') as fh:
                    payload = json.load(fh)
            except (OSError, ValueError) as e:
                logger.warning('crawler ranges: unusable cache %s: %s', path, e)
                payload, age = None, None

        error = None
        stale = False
        if payload is None or age is None or age > max_age_seconds:
            try:
                fresh = fetch(url)
                if parse_prefixes(fresh):
                    payload, age = fresh, 0
                    _write_cache(path, fresh)
                else:
                    raise ValueError('no usable prefixes in response')
            except Exception as e:  # network, JSON, HTTP — all the same here
                error = str(e)[:200]
                stale = payload is not None
                logger.warning('crawler ranges: %s unavailable (%s)', key, error)

        parsed = parse_prefixes(payload) if payload is not None else []
        networks[key] = parsed
        meta[key] = {
            'url': url,
            'prefixes': len(parsed),
            'age_seconds': int(age) if age is not None else None,
            'stale': stale,
            'error': error,
            'available': bool(parsed),
        }
    return networks, meta


def _write_cache(path, payload):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f'{path}.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh)
        os.replace(tmp, path)
    except OSError as e:
        logger.warning('crawler ranges: could not cache %s: %s', path, e)


class RangeVerifier:
    """Decides whether a claimed crawler is coming from where it should.

    `verify()` returns True, False, or None — and None is load-bearing. It
    means "this operator publishes nothing to check against", which is a
    different statement from "this IP is not theirs".
    """

    def __init__(self, networks=None):
        self._by_source = networks or {}
        self._cache = {}
        self._cache_full = False

    def available(self, sources):
        return any(self._by_source.get(s) for s in sources)

    def verify(self, sources, ip):
        if not sources or not self.available(sources):
            return None
        if not ip:
            # A missing ClientIP is a gap in the record, not a false claim.
            return None
        key = (sources, ip)
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        try:
            address = ipaddress.ip_address(ip.split('%', 1)[0])
        except ValueError:
            result = False
        else:
            result = any(address in net
                         for source in sources
                         for net in self._by_source.get(source, ())
                         if net.version == address.version)
        if not self._cache_full:
            self._cache[key] = result
            if len(self._cache) >= MAX_VERIFY_CACHE:
                self._cache_full = True
        return result


# --- classification --------------------------------------------------------


def classify_ua(user_agent):
    """`(token, label, category, sources)` for a known crawler, else None."""
    if not user_agent:
        return None
    lowered = user_agent.lower()
    for token, label, category, sources in _ORDERED:
        if token in lowered:
            return token, label, category, sources
    return None


def looks_like_crawler(user_agent):
    """True for a self-declared crawler that is not in the registry."""
    if not user_agent:
        return False
    lowered = user_agent.lower()
    for bad in _GENERIC_EXCLUDE:
        lowered = lowered.replace(bad, '')
    return any(marker in lowered for marker in _GENERIC_MARKERS)


def crawler_product(user_agent):
    """The bot-ish product token out of a UA, for grouping unknown crawlers.

    Grouping on the whole UA string splits one crawler across every version
    and platform variant it sends; grouping on the product token keeps them
    together, which is what makes the "other crawlers" table readable.

    The *first* usable candidate wins, because the product token leads the
    UA by convention and the contact URL that follows it often contains a
    longer bot-ish string: `tphotobot/0.1 (+https://crawler.example.com/bot)`
    is tphotobot, not crawler.example.com.

    Candidates that are nothing but the bare marker are skipped — plenty of
    UAs carry an unrelated `+http://…/bot.html` and grouping on that produces
    one giant "bot" row that names nothing. When a UA has no product token at
    all, it is reported as itself rather than guessed at.
    """
    for match in _UA_PRODUCT_RE.finditer(user_agent or ''):
        candidate = match.group(0).strip()
        if candidate.lower() not in _BARE_PRODUCTS:
            return candidate[:64]
    return (user_agent or '')[:64]


def _path_prefix(url, depth=2):
    path = url.split('?', 1)[0].split('#', 1)[0]
    parts = [p for p in path.split('/') if p]
    if not parts:
        return '/'
    return '/' + '/'.join(parts[:depth])


def _query_keys(query_string):
    for pair in query_string.split('&'):
        if not pair:
            continue
        key = pair.split('=', 1)[0].strip()
        if key:
            yield key[:64]


def _trim(table, keep, weight, caps, flag):
    """Drop the long tail once a table has grown to twice its budget.

    A hard cap would freeze the table at whatever happened to appear first,
    which on a chronological stream means the first hour decides the whole
    report. Trimming by weight keeps the heavy hitters — the only rows that
    are ever reported — and bounds memory just as firmly.
    """
    if len(table) <= keep * 2:
        return
    survivors = sorted(table.items(), key=lambda kv: weight(kv[1]),
                       reverse=True)[:keep]
    table.clear()
    table.update(survivors)
    caps[flag] = True


def _requests(value):
    return value[0] + value[1]


# --- aggregation -----------------------------------------------------------


class CrawlerAggregator:
    """Streaming classification and cross-tab. One row at a time, bounded."""

    def __init__(self, verifier=None):
        self.verifier = verifier or RangeVerifier()
        self.rows = 0
        self.crawler_rows = 0
        self.crawler_bytes = 0
        self.human_rows = 0
        self.human_bytes = 0
        self.other_rows = 0
        self.other_bytes = 0

        self._stats = defaultdict(lambda: {
            'requests': 0, 'bytes': 0,
            'verified': 0, 'verified_bytes': 0,
            'impostor': 0, 'impostor_bytes': 0,
            'unverifiable': 0,
            'query_rows': 0,
            'status': Counter(),
            'urls': Counter(),
            'prefixes': Counter(),
            'ips': set(),
            'impostor_ips': Counter(),
        })
        self._meta = {}
        # product -> [requests, 0, bytes]; the middle slot keeps the weight
        # function shared with the other tables.
        self._other_uas = {}
        # prefix -> [crawler requests, human requests, crawler bytes, human bytes]
        self._prefixes = {}
        # query key -> [crawler requests, human requests, crawler bytes]
        self._query_keys = {}
        self.caps = {}

    def feed(self, row):
        self.rows += 1
        user_agent = _text(row.get('UserAgent'))
        sent = _int(row.get('BytesSent')) or 0
        url = _text(row.get('URL'))
        query = _text(row.get('QueryString'))
        status = _int(row.get('HTTPStatus'))
        ip = _text(row.get('ClientIP'))

        known = classify_ua(user_agent)
        if known is not None:
            self._feed_known(known, ip, url, query, status, sent)
            is_crawler = True
        elif looks_like_crawler(user_agent):
            self.other_rows += 1
            self.other_bytes += sent
            product = crawler_product(user_agent)
            entry = self._other_uas.setdefault(product, [0, 0, 0])
            entry[0] += 1
            entry[2] += sent
            _trim(self._other_uas, OTHER_UA_KEEP, _requests, self.caps,
                  'other_crawlers_trimmed')
            is_crawler = True
        else:
            self.human_rows += 1
            self.human_bytes += sent
            is_crawler = False

        if is_crawler:
            self.crawler_rows += 1
            self.crawler_bytes += sent

        self._feed_url_space(is_crawler, url, query, sent)

    def _feed_known(self, known, ip, url, query, status, sent):
        token, label, category, sources = known
        stats = self._stats[token]
        self._meta[token] = (label, category, sources)
        stats['requests'] += 1
        stats['bytes'] += sent
        if status is not None:
            stats['status'][f'{status // 100}xx'] += 1
        if query:
            stats['query_rows'] += 1
        if url:
            stats['urls'][url[:300]] += 1
            stats['prefixes'][_path_prefix(url)] += 1
            if len(stats['urls']) > URLS_KEEP * 2:
                stats['urls'] = Counter(dict(stats['urls'].most_common(URLS_KEEP)))
                self.caps['crawler_urls_trimmed'] = True
            if len(stats['prefixes']) > URLS_KEEP * 2:
                stats['prefixes'] = Counter(
                    dict(stats['prefixes'].most_common(URLS_KEEP)))
                self.caps['crawler_prefixes_trimmed'] = True
        if ip:
            if len(stats['ips']) < MAX_IPS_PER_CRAWLER:
                stats['ips'].add(ip)
            elif ip not in stats['ips']:
                self.caps['crawler_ips'] = True

        verdict = self.verifier.verify(sources, ip)
        if verdict is None:
            stats['unverifiable'] += 1
        elif verdict:
            stats['verified'] += 1
            stats['verified_bytes'] += sent
        else:
            stats['impostor'] += 1
            stats['impostor_bytes'] += sent
            if len(stats['impostor_ips']) <= MAX_IPS_PER_CRAWLER:
                stats['impostor_ips'][ip or '(none)'] += 1

    def _feed_url_space(self, is_crawler, url, query, sent):
        if not url:
            return
        side = 0 if is_crawler else 1
        entry = self._prefixes.setdefault(_path_prefix(url), [0, 0, 0, 0])
        entry[side] += 1
        entry[2 + side] += sent
        _trim(self._prefixes, PREFIX_KEEP, _requests, self.caps,
              'url_space_trimmed')
        if not query:
            return
        for key in _query_keys(query):
            entry = self._query_keys.setdefault(key, [0, 0, 0])
            entry[side] += 1
            if is_crawler:
                entry[2] += sent
        _trim(self._query_keys, QUERY_KEY_KEEP, _requests, self.caps,
              'query_keys_trimmed')

    # -- output --

    def _crawler_rows(self):
        out = []
        for token, stats in self._stats.items():
            label, category, sources = self._meta[token]
            requests = stats['requests']
            if self.verifier.available(sources):
                verification = VERIFY_PUBLISHED
            elif sources:
                verification = VERIFY_UNAVAILABLE
            else:
                verification = VERIFY_NO_LIST
            out.append({
                'token': token,
                'label': label,
                'category': category,
                'category_label': CATEGORY_LABELS.get(category, category),
                'requests': requests,
                'bytes': stats['bytes'],
                'request_share': _rate(requests, self.rows),
                'byte_share': _rate(stats['bytes'], self.crawler_bytes + self.human_bytes),
                'verification': verification,
                'verified': stats['verified'],
                'impostor': stats['impostor'],
                'impostor_bytes': stats['impostor_bytes'],
                'impostor_share': _rate(stats['impostor'], requests),
                'unverifiable': stats['unverifiable'],
                'distinct_ips': len(stats['ips']),
                'query_share': _rate(stats['query_rows'], requests),
                'status_classes': dict(stats['status']),
                'top_urls': [{'url': u, 'requests': c}
                             for u, c in stats['urls'].most_common(TOP_URLS)],
                'top_prefixes': [{'prefix': p, 'requests': c}
                                 for p, c in stats['prefixes'].most_common(TOP_URLS)],
                'top_impostor_ips': [{'ip': i, 'requests': c}
                                     for i, c in stats['impostor_ips'].most_common(TOP_IPS)],
            })
        out.sort(key=lambda c: c['requests'], reverse=True)
        return out

    def _categories(self, crawlers):
        totals = defaultdict(lambda: {'requests': 0, 'bytes': 0, 'crawlers': 0})
        for crawler in crawlers:
            bucket = totals[crawler['category']]
            bucket['requests'] += crawler['requests']
            bucket['bytes'] += crawler['bytes']
            bucket['crawlers'] += 1
        out = [{
            'category': category,
            'label': CATEGORY_LABELS.get(category, category),
            'requests': bucket['requests'],
            'bytes': bucket['bytes'],
            'crawlers': bucket['crawlers'],
            'share_of_crawl': _rate(bucket['requests'], self.crawler_rows),
        } for category, bucket in totals.items()]
        out.sort(key=lambda c: c['requests'], reverse=True)
        return out

    def _url_space(self):
        rows = [{
            'prefix': prefix,
            'crawler_requests': crawler,
            'human_requests': human,
            'crawler_bytes': crawler_bytes,
            'human_bytes': human_bytes,
            'crawler_share': _rate(crawler, crawler + human),
            'request_share': _rate(crawler + human, self.rows),
        } for prefix, (crawler, human, crawler_bytes, human_bytes)
            in self._prefixes.items()]
        rows.sort(key=lambda r: r['crawler_requests'], reverse=True)
        return rows[:TOP_N * 2]

    def _query_key_rows(self):
        rows = [{
            'key': key,
            'crawler_requests': crawler,
            'human_requests': human,
            'crawler_bytes': crawler_bytes,
            'crawler_share': _rate(crawler, crawler + human),
        } for key, (crawler, human, crawler_bytes) in self._query_keys.items()]
        rows.sort(key=lambda r: r['crawler_requests'], reverse=True)
        return rows[:TOP_N * 2]

    def result(self, *, scale=None, ranges_meta=None):
        scale = scale or 1.0
        crawlers = self._crawler_rows()
        total_bytes = self.crawler_bytes + self.human_bytes
        data = {
            'generated_at': datetime.utcnow().isoformat(),
            'rows': self.rows,
            'scale': scale,
            'crawler_requests': self.crawler_rows,
            'crawler_bytes': self.crawler_bytes,
            'human_requests': self.human_rows,
            'human_bytes': self.human_bytes,
            'crawler_request_share': _rate(self.crawler_rows, self.rows),
            'crawler_byte_share': _rate(self.crawler_bytes, total_bytes),
            'extrapolated_crawler_requests': int(self.crawler_rows * scale),
            'extrapolated_crawler_bytes': int(self.crawler_bytes * scale),
            'crawlers': crawlers,
            'categories': self._categories(crawlers),
            'other_crawlers': {
                'requests': self.other_rows,
                'bytes': self.other_bytes,
                'top': [{'product': p, 'requests': v[0], 'bytes': v[2]}
                        for p, v in sorted(self._other_uas.items(),
                                           key=lambda kv: kv[1][0],
                                           reverse=True)[:TOP_N]],
            },
            'url_space': self._url_space(),
            'query_keys': self._query_key_rows(),
            'ranges': ranges_meta or {},
            'caps': dict(self.caps),
        }
        data['findings'] = build_findings(data)
        return data


# --- findings --------------------------------------------------------------


def _ranges_findings(data):
    meta = data.get('ranges') or {}
    broken = sorted(k for k, m in meta.items() if not m.get('available'))
    if not broken:
        return []
    return [dict(_finding(
        'crawler_ranges_unavailable', 'info',
        'Crawler verification is incomplete',
        'Could not load published IP ranges for: ' + ', '.join(broken) + '. '
        'Crawlers that depend on those lists are reported as unverifiable '
        'rather than as impostors — an unreachable list is not evidence of '
        'anything about the traffic.',
        {'sources': broken},
    ), category=CATEGORY_WAAS)]


def _volume_finding(data):
    share = data.get('crawler_request_share') or 0
    if share < CRAWLER_SHARE_INFO:
        return []
    byte_share = data.get('crawler_byte_share') or 0
    severity = 'warning' if share >= CRAWLER_SHARE_WARN else 'info'
    return [dict(_finding(
        'crawler_traffic_share', severity,
        f'Crawlers are {_pct(share)} of requests',
        f'Self-declared crawlers account for {data["crawler_requests"]:,} of '
        f'{data["rows"]:,} sampled requests ({_pct(share)}) and '
        f'{_pct(byte_share)} of egress. Extrapolated over the full window '
        f'that is roughly {data["extrapolated_crawler_requests"]:,} requests. '
        'Crawl volume is tuned with robots.txt and crawl-rate settings, not '
        'with caching.',
        {'requests': data['crawler_requests'], 'share': share,
         'byte_share': byte_share},
    ), category=CATEGORY_ROBOTS)]


def _impostor_findings(data):
    offenders = [c for c in data['crawlers']
                 if c['verification'] == VERIFY_PUBLISHED
                 and c['impostor'] >= MIN_IMPOSTOR_REQUESTS
                 and (c['impostor_share'] or 0) >= IMPOSTOR_SHARE_FLOOR]
    if not offenders:
        return []
    offenders.sort(key=lambda c: c['impostor'], reverse=True)
    lines = [
        f'  {c["label"]}: {c["impostor"]:,} of {c["requests"]:,} requests '
        f'({_pct(c["impostor_share"] or 0)}) from outside the published ranges'
        for c in offenders[:5]
    ]
    return [dict(_finding(
        'crawler_impostors', 'warning',
        'Traffic claims to be a crawler and is not',
        'These requests carry the UA of a crawler whose operator publishes '
        'its IP ranges, and arrive from addresses outside them:\n'
        + '\n'.join(lines) +
        '\nThey are not that crawler, so robots.txt will not slow them down — '
        'robots.txt is honoured voluntarily and a client lying about its '
        'identity has already opted out. These are candidates for a WaaS '
        'block or rate limit.',
        {'crawlers': [{'label': c['label'], 'impostor': c['impostor'],
                       'share': c['impostor_share'],
                       'top_ips': c['top_impostor_ips']} for c in offenders]},
    ), category=CATEGORY_WAAS)]


def _bytes_label(value):
    """Megabytes up to a point, then gigabytes.

    '6382.8 MB' is a number the reader has to divide before it means
    anything.
    """
    value = value or 0
    if value >= 1e9:
        return f'{value / 1e9:.1f} GB'
    return f'{value / 1e6:.1f} MB'


def _category_findings(data):
    out = []
    by_category = {c['category']: c for c in data['categories']}

    ai = by_category.get(CAT_AI)
    if ai and ai['requests'] >= MIN_CATEGORY_REQUESTS \
            and (ai['share_of_crawl'] or 0) >= AI_SHARE_FLOOR:
        out.append(dict(_finding(
            'ai_crawler_load', 'info',
            f'AI crawlers are {_pct(ai["share_of_crawl"] or 0)} of crawl traffic',
            f'{ai["requests"]:,} requests and {_bytes_label(ai["bytes"])} came '
            f'from {ai["crawlers"]} AI/LLM crawler(s). Most honour a robots.txt '
            'opt-out under their own token (GPTBot, ClaudeBot, Google-Extended, '
            'Applebot-Extended, CCBot, Bytespider). Whether to serve them is a '
            'business decision, not a performance one — but it should be a '
            'decision rather than a default.',
            {'requests': ai['requests'], 'bytes': ai['bytes'],
             'share_of_crawl': ai['share_of_crawl']},
        ), category=CATEGORY_ROBOTS))

    seo = by_category.get(CAT_SEO)
    if seo and seo['requests'] >= MIN_CATEGORY_REQUESTS \
            and (seo['share_of_crawl'] or 0) >= SEO_SHARE_FLOOR:
        out.append(dict(_finding(
            'seo_crawler_load', 'warning',
            f'SEO crawlers are {_pct(seo["share_of_crawl"] or 0)} of crawl traffic',
            f'{seo["requests"]:,} requests and {_bytes_label(seo["bytes"])} came '
            'from backlink and site-audit crawlers. These index the site for '
            'someone else\'s product; unless the customer is a subscriber to '
            'one of them, the traffic is pure cost. They publish no IP ranges, '
            'so the UA cannot be verified, but the well-behaved ones do honour '
            'robots.txt.',
            {'requests': seo['requests'], 'bytes': seo['bytes'],
             'share_of_crawl': seo['share_of_crawl']},
        ), category=CATEGORY_ROBOTS))
    return out


def _query_trap_findings(data):
    traps = [c for c in data['crawlers']
             if c['requests'] >= MIN_QUERY_TRAP_REQUESTS
             and (c['query_share'] or 0) >= QUERY_TRAP_SHARE]
    if not traps:
        return []
    # Enrichment against the site's own crawler share, not a flat majority.
    # On a corpus that is 9% crawler, a parameter at 46% is the trap; waiting
    # for it to cross 50% means never naming it.
    baseline = data.get('crawler_request_share') or 0
    floor = max(QUERY_KEY_MIN_SHARE, baseline * QUERY_KEY_ENRICHMENT)
    keys = [q for q in data['query_keys']
            if (q['crawler_share'] or 0) >= floor][:6]
    key_lines = [f'  ?{q["key"]}= — {q["crawler_requests"]:,} crawler requests '
                 f'({_pct(q["crawler_share"] or 0)} of all requests carrying it)'
                 for q in keys]
    detail = (
        'These crawlers spend a large share of their budget on URLs with query '
        'strings:\n'
        + '\n'.join(f'  {c["label"]}: {_pct(c["query_share"] or 0)} of '
                    f'{c["requests"]:,} requests' for c in traps[:5])
    )
    if key_lines:
        detail += ('\n\nThe parameters they are following:\n'
                   + '\n'.join(key_lines))
    detail += ('\n\nParameterised URLs are usually filters, sorts and calendar '
               'views — a combinatorial space with no end to it. Disallowing '
               'the parameters rather than the pages keeps the canonical URLs '
               'indexable.')
    return [dict(_finding(
        'crawler_query_traps', 'warning',
        'Crawlers are working through a parameterised URL space',
        detail,
        {'crawlers': [{'label': c['label'], 'query_share': c['query_share'],
                       'requests': c['requests']} for c in traps],
         'keys': keys},
    ), category=CATEGORY_ROBOTS)]


def _url_space_findings(data):
    hot = [r for r in data['url_space']
           if (r['crawler_share'] or 0) >= URL_SPACE_DOMINANCE
           and r['crawler_requests'] >= URL_SPACE_MIN_REQUESTS]
    if not hot:
        return []
    lines = [f'  {r["prefix"]} — {r["crawler_requests"]:,} crawler requests, '
             f'{r["human_requests"]:,} human, '
             f'{_bytes_label(r["crawler_bytes"])}'
             for r in hot[:6]]
    return [dict(_finding(
        'crawler_url_space', 'info',
        'Parts of the site are crawled far more than they are visited',
        'These path prefixes are almost entirely crawler traffic:\n'
        + '\n'.join(lines) +
        '\nA prefix that real users barely touch is the cheapest thing to '
        'disallow: the measured cost is real and the measured benefit is '
        'close to zero.',
        {'prefixes': hot},
    ), category=CATEGORY_ROBOTS)]


def build_findings(data):
    if data.get('rows', 0) < MIN_ROWS_FOR_FINDINGS:
        return []
    findings = []
    findings.extend(_volume_finding(data))
    findings.extend(_impostor_findings(data))
    findings.extend(_query_trap_findings(data))
    findings.extend(_category_findings(data))
    findings.extend(_url_space_findings(data))
    findings.extend(_ranges_findings(data))
    findings.sort(key=lambda f: 0 if f['severity'] == 'warning' else 1)
    return findings


def ranges_cache_dir(instance_path):
    return os.path.join(instance_path, CACHE_DIR_NAME)
