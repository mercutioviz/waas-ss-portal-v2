"""robots.txt proposal engine with a measured before/after.

Three things make this different from writing some Disallow lines and hoping:

**Google-spec matching.** `urllib.robotparser` does not implement wildcards —
CPython's `RuleLine.applies_to` is `path == "*" or
filename.startswith(self.path)`, so `Disallow: /*?*eventDisplay=` degrades to a
literal prefix and matches nothing. The stdlib will cheerfully agree that a
broken file works. The matcher here implements the spec directly: `*`, `$`,
longest-pattern-wins, Allow breaking ties at equal length, and one most-specific
user-agent group per crawler.

**Patterns are anchored at the path start.** This is not a detail. A real
customer file carried `Disallow: /tag` and `Disallow: /category` while the
traffic sat at `/news-and-events-calendar/tag/…` — 242,413 and 590,147 requests
over thirty days that the rules never touched, because an anchored pattern does
not match mid-path. Candidates here are generated from observed path prefixes,
so they are anchored where the traffic actually is.

**Nothing is claimed that was not measured.** Every number this module reports
comes from replaying the final file against the collected rows. A draft of that
same customer report asserted the proposal covered "80–100%" of five crawlers'
fetches; measured, it was 56.4–86.0%, and the measurement turned up the more
useful fact that only 9.2% of Googlebot was affected. A rule added late also
invalidated an earlier measurement, which is why `replay()` takes the rendered
file rather than the candidate list.

The ceiling is reported too. robots.txt is honoured voluntarily and only by
clients that identify themselves, so non-crawler traffic matching the same
patterns is traffic these rules cannot touch. Reporting that share stops the
proposal from being read as a total.

One WaaS-specific wrinkle: WaaS rewrites `/robots.txt` in flight, prepending its
own `User-agent: *` group with a spider-trap Disallow. That leaves two `*`
groups in the served file. Google merges same-agent groups so the origin's rules
survive, but a crawler that takes only the first matching group sees nothing but
the honeypot. `replay()` evaluates both readings and reports the gap.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime

from app.logpull.crawlers import classify_ua, looks_like_crawler
from app.traffic_insights import _int, _is_static, _pct, _rate, _text

logger = logging.getLogger(__name__)

CATEGORY_ROBOTS = 'robots'

# --- limits ----------------------------------------------------------------

MAX_HOSTS = 25
PREFIX_KEEP = 5_000
SEGMENT_KEEP = 2_000
QUERY_KEEP = 2_000
MAX_PARENTS = 64
MAX_DEPTH = 3

#: Candidate thresholds. A rule has to be both lopsided and large: lopsided so
#: that blocking it does not cost real visitors, large so that it is worth the
#: review it asks the customer for.
DOMINANCE = 0.85
MIN_CRAWLER_REQUESTS = 200
MIN_SEGMENT_PARENTS = 3
MIN_SCOPED_PARENTS = 2

#: Two tiers, because the interesting traffic is rarely dominant. On a real
#: corpus the site baseline was 16.6% crawler and the calendar space — the
#: single biggest crawl trap on the site — ran 40-50%: enriched threefold, and
#: nowhere near `DOMINANCE`. An analyst blocked it anyway, on the judgement
#: that generated list/month/tag views duplicate content reachable elsewhere.
#: That judgement is not in the logs and no threshold recovers it.
#:
#: So: rules at or above `DOMINANCE` ship active, because a space real
#: visitors barely touch costs nothing to disallow. Rules that are merely
#: enriched ship commented out, with their measured impact next to them, for
#: someone who knows the site to uncomment. Both totals are measured and
#: reported separately — the customer is never asked to take the larger number
#: on trust.
TIER_CONFIDENT = 'confident'
TIER_REVIEW = 'review'
PREFIX_ENRICHMENT = 2.5
MIN_REVIEW_REQUESTS = 1_000

#: A prefix has to be a space, not a page. Long article slugs otherwise look
#: like crawler-dominated directories three segments down, and a Disallow for
#: one URL is noise in a file somebody has to review.
MIN_PREFIX_VARIANTS = 5
MAX_VARIANTS = 8

#: Candidates stay shallow even though the tables go one level deeper. Depth 3
#: on a content site is where the article slugs live, so prefixes there
#: describe single pages; the traps worth a rule — a search endpoint, an
#: archive, a tag space — all sit at depth 1 or 2, and a deeper trap is
#: normally covered by its parent anyway. The deeper table rows are still
#: needed: `_feed_segments` reads them to find patterns that recur.
MAX_PREFIX_DEPTH = 2
QUERY_ENRICHMENT = 2.5
QUERY_MIN_SHARE = 0.25

#: Parameters that select *which content* is served rather than how it is
#: filtered, sorted or decorated. `Disallow: /*?*id=` is a site-wide rule, and
#: on a corpus where crawlers happen to dominate `?id=` it passes every
#: statistical test while quietly proposing to de-index the catalogue. No
#: measurement can tell a crawl trap from a product page; a denylist can.
CONTENT_SELECTOR_KEYS = frozenset({
    'id', 'p', 'q', 's', 'search', 'url', 'uri', 'slug', 'sku', 'node',
    'product', 'product_id', 'item', 'itemid', 'pid', 'nid', 'name',
    'lang', 'locale', 'hl', 'token', 'key', 'file', 'path',
})
MIN_HOST_CRAWLER_REQUESTS = 500
MAX_PROPOSED_RULES = 25

#: Blocking CSS/JS stops Google rendering the page and is a well-known way to
#: lose rankings while believing you are saving bandwidth. Static assets never
#: become candidates no matter how lopsided they look.
SKIP_STATIC = True

TOP_N = 12


# --- the matcher -----------------------------------------------------------


def _rx(pattern):
    """Compile a robots path pattern to a regex anchored at the path start."""
    out = []
    for i, ch in enumerate(pattern):
        if ch == '*':
            out.append('.*')
        elif ch == '$' and i == len(pattern) - 1:
            out.append('$')
        else:
            out.append(re.escape(ch))
    return re.compile('^' + ''.join(out))


def _parse_groups(text):
    """Yield `(agents, rules, directives)` per group, in file order."""
    agents, rules, directives, fresh = [], [], [], True
    for raw in (text or '').splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line or ':' not in line:
            continue
        field, _, value = line.partition(':')
        field, value = field.strip().lower(), value.strip()
        if field == 'user-agent':
            if not fresh and (agents or rules):
                yield agents, rules, directives
                agents, rules, directives = [], [], []
            agents.append(value.lower())
            fresh = True
        elif field in ('allow', 'disallow'):
            fresh = False
            # An empty Disallow means "allow everything" and carries no rule.
            if value:
                rules.append((field == 'allow', value, _rx(value)))
        elif field == 'sitemap':
            directives.append(('sitemap', value))
        elif agents:
            fresh = False
            directives.append((field, value))
    if agents or rules:
        yield agents, rules, directives


class Robots:
    """Google-spec reading: groups sharing a user-agent token are merged."""

    def __init__(self, text):
        self.text = text or ''
        self.groups = {}
        self.sitemaps = []
        self.group_count = 0
        self.duplicate_agents = 0
        seen = set()
        for agents, rules, directives in _parse_groups(self.text):
            self.group_count += 1
            for agent in agents:
                if agent in seen:
                    self.duplicate_agents += 1
                seen.add(agent)
                self.groups.setdefault(agent, []).extend(rules)
            self.sitemaps.extend(v for k, v in directives if k == 'sitemap')

    def group_for(self, agent):
        """Most specific matching group: longest UA substring match, else `*`."""
        lowered = (agent or '').lower()
        best, best_len = None, -1
        for name in self.groups:
            if name != '*' and name in lowered and len(name) > best_len:
                best, best_len = name, len(name)
        if best is not None:
            return best, self.groups[best]
        return '*', self.groups.get('*', [])

    def allowed(self, agent, path):
        """`(allowed, winning_pattern)`. `path` must include the query string."""
        _, rules = self.group_for(agent)
        return self._decide(rules, path)

    @staticmethod
    def _decide(rules, path):
        win, win_len, win_allow = None, -1, True
        for is_allow, pattern, rx in rules:
            if not rx.search(path):
                continue
            length = len(pattern)
            # Longest pattern wins; Allow beats Disallow at equal length.
            if length > win_len or (length == win_len and is_allow and not win_allow):
                win, win_len, win_allow = pattern, length, is_allow
        if win is None:
            return True, None
        return win_allow, win


class FirstGroupRobots(Robots):
    """The non-merging reading: only the first group whose agent matches.

    Not a straw man. It is how several real crawlers behave, and because WaaS
    prepends its own `User-agent: *` honeypot group ahead of the origin's,
    this reading sees a file that blocks essentially nothing.
    """

    def __init__(self, text):
        super().__init__(text)
        self.ordered = [(agents, rules)
                        for agents, rules, _ in _parse_groups(self.text)]

    def group_for(self, agent):
        lowered = (agent or '').lower()
        fallback = None
        for agents, rules in self.ordered:
            for name in agents:
                if name != '*' and name in lowered:
                    return name, rules
                if name == '*' and fallback is None:
                    fallback = ('*', rules)
        return fallback or ('*', [])


#: WaaS's injected trap: a single Disallow for a long random-looking .html
#: path, in a `*` group of its own, ahead of whatever the origin serves.
_HONEYPOT_RE = re.compile(r'^/[A-Za-z0-9+/_=-]{8,}\.html?$')


def describe_served(text, *, content_type=None):
    """What the served bytes actually are, before anyone reasons about them.

    A CAPTCHA page comes back at HTTP 200 with `Content-Type: text/html`, and
    the robots spec says to parse a 200 body as the file — which yields zero
    rules, i.e. allow-all. Reading that as "the customer has no robots.txt"
    is wrong and the kind of wrong that ends up in a report.
    """
    body = (text or '').strip()
    html = body[:200].lower().lstrip().startswith(('<!doctype', '<html', '<head'))
    if content_type and 'html' in content_type.lower():
        html = True
    parsed = Robots(text)
    honeypot = None
    for agents, rules, _ in _parse_groups(text or ''):
        if '*' in agents and len(rules) == 1 and not rules[0][0] \
                and _HONEYPOT_RE.match(rules[0][1]):
            honeypot = rules[0][1]
            break
    return {
        'bytes': len(body.encode('utf-8', 'replace')),
        'served_as_html': html,
        'rules': sum(len(r) for r in parsed.groups.values()),
        'groups': parsed.group_count,
        'merged_agents': parsed.duplicate_agents,
        'waas_honeypot': honeypot,
        'sitemaps': parsed.sitemaps[:5],
    }


# --- candidate collection (pass one) ---------------------------------------


def request_path(row):
    """Path plus query string, which is what robots patterns match against."""
    url = _text(row.get('URL'))
    if not url:
        return ''
    if not url.startswith('/'):
        url = '/' + url
    query = _text(row.get('QueryString'))
    return f'{url}?{query}' if query else url


def _segments(url):
    return [s for s in url.split('?', 1)[0].split('#', 1)[0].split('/') if s]


def _query_keys(query):
    for pair in query.split('&'):
        key = pair.split('=', 1)[0].strip()
        if key:
            yield key[:64]


def _weight(entry):
    return entry['crawler'] + entry['human']


def _trim(table, keep, caps, flag):
    if len(table) <= keep * 2:
        return
    survivors = sorted(table.items(), key=lambda kv: _weight(kv[1]),
                       reverse=True)[:keep]
    table.clear()
    table.update(survivors)
    caps[flag] = True


def _entry(table, key, sample):
    entry = table.get(key)
    if entry is None:
        entry = table[key] = {'crawler': 0, 'human': 0, 'crawler_bytes': 0,
                              'sample': sample}
    return entry


class RobotsAggregator:
    """Per-host candidate statistics, collected in one streaming pass.

    Everything here is split crawler/human, because a rule is only safe to
    propose when the traffic it would stop is overwhelmingly crawler traffic.
    A table of "busiest URLs" cannot tell you that.
    """

    def __init__(self):
        self.rows = 0
        self.hosts = {}
        self.caps = {}
        self.skipped_hosts = 0

    def _host(self, name):
        host = self.hosts.get(name)
        if host is None:
            if len(self.hosts) >= MAX_HOSTS:
                self.skipped_hosts += 1
                self.caps['hosts_trimmed'] = True
                return None
            host = self.hosts[name] = {
                'host': name,
                'requests': 0, 'crawler': 0, 'human': 0,
                'crawler_bytes': 0, 'human_bytes': 0,
                'prefixes': {}, 'segments': {}, 'query_keys': {},
            }
        return host

    def feed(self, row):
        self.rows += 1
        name = _text(row.get('Host'))
        if not name:
            return
        host = self._host(name)
        if host is None:
            return

        user_agent = _text(row.get('UserAgent'))
        is_crawler = bool(classify_ua(user_agent)) or looks_like_crawler(user_agent)
        sent = _int(row.get('BytesSent')) or 0

        host['requests'] += 1
        if is_crawler:
            host['crawler'] += 1
            host['crawler_bytes'] += sent
        else:
            host['human'] += 1
            host['human_bytes'] += sent

        url = _text(row.get('URL'))
        if not url:
            return
        if not url.startswith('/'):
            url = '/' + url
        if SKIP_STATIC and _is_static(url):
            # Still counted in the host totals above — just never a candidate.
            return

        path = request_path(row)
        parts = _segments(url)
        query = _text(row.get('QueryString'))
        self._feed_prefixes(host, parts, path, is_crawler, sent, query)
        self._feed_segments(host, parts, path, is_crawler, sent)
        if query:
            self._feed_queries(host, query, path, is_crawler, sent)

    def _feed_prefixes(self, host, parts, path, is_crawler, sent, query):
        """Prefixes of depth 1..MAX_DEPTH, with a bounded sample of what
        follows each one.

        The continuation — next path segment, or the query string when the
        prefix is the whole path — is what separates a *space* from a *page*.
        Three segments down a site with long article slugs, every prefix is an
        individual article: crawler-dominated, over the volume floor, and
        completely pointless to disallow. One real corpus proposed
        `/membership/councils-committees/membership-councils-application` on
        348 requests to a single URL. Counting distinct continuations rejects
        that while still admitting `/search_gcse`, which has no child segments
        at all but thousands of distinct query strings.
        """
        table = host['prefixes']
        for depth in range(1, min(len(parts), MAX_DEPTH) + 1):
            prefix = '/' + '/'.join(parts[:depth])
            entry = table.get(prefix)
            if entry is None:
                entry = table[prefix] = {
                    'crawler': 0, 'human': 0, 'crawler_bytes': 0,
                    'sample': path, 'variants': set()}
            entry['crawler' if is_crawler else 'human'] += 1
            if is_crawler:
                entry['crawler_bytes'] += sent
            if len(entry['variants']) < MAX_VARIANTS:
                tail = parts[depth] if len(parts) > depth else query
                entry['variants'].add((tail or '')[:64])
        _trim(table, PREFIX_KEEP, self.caps, 'prefixes_trimmed')

    def _feed_segments(self, host, parts, path, is_crawler, sent):
        """Segments appearing below the first level, e.g. the `/page/` in
        `/news/2026/page/4`, which become `/*/page/` rules.

        Each one is counted twice: once site-wide and once scoped to its top
        path segment. Site-wide `page` is usually a mix — humans paginate too
        — and fails the dominance test, while `page` under one archive
        section is overwhelmingly crawler and passes it. Without the scoped
        form the biggest single rule on a real corpus goes unproposed.
        """
        table = host['segments']
        for index in range(1, min(len(parts), MAX_DEPTH + 1)):
            name = parts[index]
            if name.isdigit():
                # A number in a path is a value, not a name: page 2, year
                # 2026, item 4718. Counting it produces one rule per page
                # number — `/*/2/`, `/*/3/`, `/*/4/` — each describing a
                # slice of the same archive, none of them a pattern. The
                # name beside it (`page`, `archive`) is the real rule.
                continue
            # The scoped form renders as `/scope/*/name/`, where `*` cannot be
            # empty — it would need a doubled slash to match. At index 1 there
            # is nothing between scope and name, so the scoped form would be a
            # rule that matches nothing. That case is already the prefix
            # `/scope/name`, counted in the prefix table.
            scopes = (None,) if index < 2 else (None, parts[0])
            for scope in scopes:
                entry = table.get((scope, name))
                if entry is None:
                    entry = table[(scope, name)] = {
                        'crawler': 0, 'human': 0, 'crawler_bytes': 0,
                        'sample': path, 'parents': set()}
                entry['crawler' if is_crawler else 'human'] += 1
                if is_crawler:
                    entry['crawler_bytes'] += sent
                if len(entry['parents']) < MAX_PARENTS:
                    entry['parents'].add('/'.join(parts[:index]))
        _trim(table, SEGMENT_KEEP, self.caps, 'segments_trimmed')

    def _feed_queries(self, host, query, path, is_crawler, sent):
        table = host['query_keys']
        for key in _query_keys(query):
            entry = _entry(table, key, path)
            entry['crawler' if is_crawler else 'human'] += 1
            if is_crawler:
                entry['crawler_bytes'] += sent
        _trim(table, QUERY_KEEP, self.caps, 'query_keys_trimmed')

    def result(self):
        hosts = [{
            'host': h['host'],
            'requests': h['requests'],
            'crawler_requests': h['crawler'],
            'human_requests': h['human'],
            'crawler_bytes': h['crawler_bytes'],
            'human_bytes': h['human_bytes'],
            'crawler_share': _rate(h['crawler'], h['requests']),
        } for h in self.hosts.values()]
        hosts.sort(key=lambda h: h['crawler_requests'], reverse=True)
        return {'rows': self.rows, 'hosts': hosts, 'caps': dict(self.caps),
                'skipped_hosts': self.skipped_hosts}

    def candidates_for(self, host_name):
        return self.hosts.get(host_name)

    def best_host(self):
        """The host worth proposing a file for: most crawler traffic.

        robots.txt is per host, so a single proposal covering several
        hostnames would be wrong however it was measured.
        """
        eligible = [h for h in self.hosts.values()
                    if h['crawler'] >= MIN_HOST_CRAWLER_REQUESTS]
        if not eligible:
            return None
        return max(eligible, key=lambda h: h['crawler'])['host']


# --- candidate generation --------------------------------------------------

KIND_PREFIX = 'prefix'
KIND_SEGMENT = 'segment'
KIND_QUERY = 'query'


def _candidate(kind, pattern, entry, reason, tier=TIER_CONFIDENT):
    crawler, human = entry['crawler'], entry['human']
    return {
        'kind': kind,
        'pattern': pattern,
        'tier': tier,
        'crawler_requests': crawler,
        'human_requests': human,
        'crawler_bytes': entry['crawler_bytes'],
        'crawler_share': _rate(crawler, crawler + human),
        'sample': entry['sample'],
        'reason': reason,
    }


def _tier(entry, share, *, dominance, baseline, min_requests):
    """Which tier a candidate qualifies for, or None if it qualifies for
    neither.

    Dominance alone is a high bar that most real crawl traps miss, because
    humans also walk the archive, the calendar and the search page. The second
    bar — enriched well past the host's own crawler share, on serious volume —
    catches those without pretending they are risk-free.
    """
    if share >= dominance:
        return TIER_CONFIDENT
    floor = (baseline or 0) * PREFIX_ENRICHMENT
    if (share >= floor and share >= QUERY_MIN_SHARE
            and entry['crawler'] >= max(min_requests, MIN_REVIEW_REQUESTS)):
        return TIER_REVIEW
    return None


def _prefix_candidates(host, *, min_requests, dominance, baseline):
    out = []
    for prefix, entry in host['prefixes'].items():
        if entry['crawler'] < min_requests:
            continue
        if prefix.count('/') < 1 or prefix == '/':
            continue
        if prefix.count('/') > MAX_PREFIX_DEPTH:
            continue
        if len(entry['variants']) < MIN_PREFIX_VARIANTS:
            # One page wearing a directory's clothes. See _feed_prefixes.
            continue
        share = _rate(entry['crawler'], entry['crawler'] + entry['human']) or 0
        tier = _tier(entry, share, dominance=dominance, baseline=baseline,
                     min_requests=min_requests)
        if tier is None:
            continue
        if tier == TIER_CONFIDENT:
            reason = f'{_pct(share)} of requests under this path are crawlers'
        else:
            reason = (f'{_pct(share)} crawler against {_pct(baseline or 0)} '
                      f'for the host — a crawl-heavy section, but real '
                      f'visitors reach it too')
        # No trailing slash. Google's prefix semantics mean `/search_gcse`
        # covers `/search_gcse`, `/search_gcse?q=…` and `/search_gcse/…`,
        # while `/search_gcse/` covers only the last of those — and on real
        # traffic the query-string form is most of it.
        out.append(_candidate(KIND_PREFIX, prefix, entry, reason, tier))
    # Shallowest first, so a dominated parent subsumes its children and the
    # file carries one rule instead of nine.
    out.sort(key=lambda c: (c['pattern'].count('/'), -c['crawler_requests']))
    return out


def _segment_candidates(host, *, min_requests, dominance, baseline):
    out = []
    for (scope, name), entry in host['segments'].items():
        if entry['crawler'] < min_requests:
            continue
        # A wildcard has to stand for something. `/membership/*/x/` where the
        # `*` only ever took one value is a rule for one URL wearing a
        # pattern's syntax — the leaf-page problem again, arriving through the
        # segment table this time. The site-wide form needs a higher bar
        # because `/*/name/` is a rule over the entire site.
        floor = MIN_SEGMENT_PARENTS if scope is None else MIN_SCOPED_PARENTS
        if len(entry['parents']) < floor:
            continue
        share = _rate(entry['crawler'], entry['crawler'] + entry['human']) or 0
        tier = _tier(entry, share, dominance=dominance, baseline=baseline,
                     min_requests=min_requests)
        if tier is None:
            continue
        pattern = f'/*/{name}/' if scope is None else f'/{scope}/*/{name}/'
        where = 'across the site' if scope is None else f'under /{scope}/'
        if scope is None:
            reason = (f'`{name}` recurs {where} under '
                      f'{len(entry["parents"])}+ different paths and is '
                      f'{_pct(share)} crawler')
        else:
            reason = f'`{name}` {where} is {_pct(share)} crawler'
        out.append(_candidate(KIND_SEGMENT, pattern, entry, reason, tier))
    out.sort(key=lambda c: -c['crawler_requests'])
    return out


def _query_candidates(host, *, min_requests, baseline):
    """Parameter rules, admitted on enrichment alone rather than dominance.

    Unlike a path rule, these ship active even when real visitors use the
    parameter heavily, and that asymmetry is deliberate: `Disallow: /*?*sort=`
    suppresses a *faceted duplicate* of a page that stays indexable at its
    canonical URL, where `Disallow: /news/` removes the content itself. The
    risk is not comparable, so the bar should not be either.

    The whole weight of that argument rests on the parameter not selecting
    content — which is what `CONTENT_SELECTOR_KEYS` exists to guarantee, and
    why a key on that list is skipped here no matter how it measures.
    """
    floor = max(QUERY_MIN_SHARE, (baseline or 0) * QUERY_ENRICHMENT)
    out = []
    for key, entry in host['query_keys'].items():
        if entry['crawler'] < min_requests:
            continue
        if key.lower().lstrip('_') in CONTENT_SELECTOR_KEYS:
            continue
        share = _rate(entry['crawler'], entry['crawler'] + entry['human']) or 0
        if share < floor:
            continue
        out.append(_candidate(
            KIND_QUERY, f'/*?*{key}=', entry,
            f'{_pct(share)} of requests carrying `{key}` are crawlers, '
            f'against {_pct(baseline or 0)} for the host overall'))
    out.sort(key=lambda c: -c['crawler_requests'])
    return out


def propose(host, *, min_requests=MIN_CRAWLER_REQUESTS, dominance=DOMINANCE,
            max_rules=MAX_PROPOSED_RULES):
    """Pick a non-overlapping set of Disallow patterns for one host.

    Candidates are admitted biggest-first and each one is tested against the
    rules already admitted: if an existing rule would already stop its sample
    path, it adds nothing but a line to review. That subsumption test uses the
    real matcher, so it accounts for wildcards rather than comparing strings.

    Confident rules are admitted before review rules regardless of size, so
    that a rule which ships active is never suppressed by one that ships
    commented out. Dropping a live rule because a line nobody uncomments
    covers it would quietly cost the customer the reduction they were
    promised.
    """
    baseline = _rate(host['crawler'], host['requests'])
    pool = (_prefix_candidates(host, min_requests=min_requests,
                               dominance=dominance, baseline=baseline)
            + _segment_candidates(host, min_requests=min_requests,
                                  dominance=dominance, baseline=baseline)
            + _query_candidates(host, min_requests=min_requests,
                                baseline=baseline))

    chosen, rules, dropped = [], [], []
    ordered = sorted(pool, key=lambda c: (c['tier'] != TIER_CONFIDENT,
                                          -c['crawler_requests']))
    for candidate in ordered:
        if len(chosen) >= max_rules:
            dropped.append({**candidate, 'dropped': 'rule budget'})
            continue
        allowed, _winner = Robots._decide(rules, candidate['sample'])
        if not allowed:
            dropped.append({**candidate, 'dropped': 'covered by another rule'})
            continue
        chosen.append(candidate)
        rules.append((False, candidate['pattern'], _rx(candidate['pattern'])))
    chosen.sort(key=lambda c: (c['tier'] != TIER_CONFIDENT, c['kind'],
                               c['pattern']))
    review = [c for c in chosen if c['tier'] == TIER_REVIEW]
    return {'host': host['host'], 'rules': chosen, 'dropped': dropped,
            'review_count': len(review), 'crawler_share': baseline}


# --- rendering -------------------------------------------------------------


def _carry_over(current):
    """The existing `*` group's rules, so a proposal never silently drops one.

    Dropping a rule the customer deliberately added is a worse failure than
    proposing nothing: it is an invisible change of policy.

    Two things are dropped anyway. Duplicates, which arrive because the
    matcher merges groups and the fetched file had the same rule in several of
    them. And the WaaS spider trap — that line is injected into the response
    in flight, so it is not the origin's rule to keep. Writing it into the
    origin's file would have WaaS add its own copy on top, and would hard-code
    today's trap token into a file that outlives it.
    """
    if current is None:
        return []
    out, seen = [], set()
    for is_allow, pattern, _rx in current.groups.get('*', []):
        if (is_allow, pattern) in seen:
            continue
        seen.add((is_allow, pattern))
        if not is_allow and _HONEYPOT_RE.match(pattern):
            continue
        if is_allow and pattern == '/':
            continue  # already emitted at the top of the group
        out.append((is_allow, pattern))
    return out


def _measured_header(host, measurement, scale_note, review_count=0):
    m = measurement or {}
    current = m.get('current') or {}
    proposed = m.get('proposed') or {}
    with_review = m.get('with_review') or {}
    net = m.get('net') or {}
    ceiling = m.get('ceiling') or {}
    lines = [
        f'# robots.txt for https://{host}/  -- SUGGESTED REVISION',
        '#',
        '# Every number below was MEASURED by replaying this exact file',
        f'# against collected WaaS access logs{scale_note}, using a',
        '# Google-spec robots matcher. They are not estimates.',
        '#',
    ]
    if m:
        lines += [
            f'#   crawler requests to {host}: {m.get("crawler_requests", 0):,} sampled',
            f'#   blocked by the CURRENT file: {current.get("requests", 0):,} '
            f'({_pct(current.get("request_share") or 0)} of crawler requests)',
            f'#   blocked by THIS file:        {proposed.get("requests", 0):,} '
            f'({_pct(proposed.get("request_share") or 0)} of requests, '
            f'{_pct(proposed.get("byte_share") or 0)} of bytes)',
            f'#   net reduction:               {net.get("requests", 0):,} requests, '
            f'{(net.get("bytes") or 0) / 1e9:.2f} GB (sampled)',
            '#',
        ]
    if review_count and with_review:
        lines += [
            f'# {review_count} further rule(s) below are COMMENTED OUT. They cover',
            '# crawl-heavy sections that real visitors also reach, so enabling',
            '# them is a judgement about what you want indexed, not something',
            '# the traffic can decide. Measured, with all of them enabled:',
            f'#   blocked:                     {with_review.get("requests", 0):,} '
            f'({_pct(with_review.get("request_share") or 0)} of requests, '
            f'{_pct(with_review.get("byte_share") or 0)} of bytes)',
            '#',
        ]
    if ceiling.get('request_share'):
        lines += [
            f'# Ceiling: a further {_pct(ceiling["request_share"])} of NON-crawler',
            '# requests match these same patterns. Those are browser-UA clients;',
            '# robots.txt does not affect them. They need caching or rate',
            '# limiting, not crawl rules.',
            '#',
        ]
    lines += [
        '# Review before deploying. These rules were derived from observed',
        '# traffic, not from knowledge of the site: a path that is crawled and',
        '# not visited may still be one you want indexed.',
        '#',
        f'# Generated {datetime.utcnow().strftime("%Y-%m-%d")} by the WaaS '
        'self-service portal.',
    ]
    return lines


def render_file(proposal, *, current=None, measurement=None, scale_note='',
                crawl_delay=None, enable_review=False):
    """The downloadable file. `measurement` may be None on a first render.

    Rendering and measuring are separate on purpose: the file is rendered,
    then replayed, then rendered again with the numbers the replay produced.
    Measuring a draft and shipping a later draft is how an earlier version of
    this analysis published a figure its own file no longer supported.

    `enable_review` renders the review-tier rules as live directives instead
    of comments. The shipped file never sets it; the replay does, so that the
    "if you also enable these" figure in the header is measured from a real
    file rather than inferred by adding rule counts together.
    """
    host = proposal['host']
    lines = _measured_header(host, measurement, scale_note,
                             proposal.get('review_count', 0))
    lines += ['', 'User-agent: *', 'Allow: /']
    if crawl_delay:
        lines.append(f'Crawl-delay: {int(crawl_delay)}')

    carried = _carry_over(current)
    if carried:
        lines += ['', '# --- existing rules, carried over unchanged ---']
        lines += [f'{"Allow" if is_allow else "Disallow"}: {pattern}'
                  for is_allow, pattern in carried]

    by_kind = {}
    for rule in proposal['rules']:
        if rule['tier'] == TIER_CONFIDENT:
            by_kind.setdefault(rule['kind'], []).append(rule)
    titles = {
        KIND_PREFIX: 'crawler-dominated paths',
        KIND_SEGMENT: 'patterns that recur across the site',
        KIND_QUERY: 'parameterised URL space',
    }
    for kind in (KIND_PREFIX, KIND_SEGMENT, KIND_QUERY):
        rules = by_kind.get(kind)
        if not rules:
            continue
        lines += ['', f'# --- proposed: {titles[kind]} ---']
        for rule in rules:
            lines.append(f'#   {rule["reason"]}'
                         f' ({rule["crawler_requests"]:,} sampled requests)')
            lines.append(f'Disallow: {rule["pattern"]}')

    review = [r for r in proposal['rules'] if r['tier'] == TIER_REVIEW]
    if review:
        lines += [
            '',
            '# --- for review: crawl-heavy, but not crawler-only -------------',
            '#',
            '# Uncomment the ones covering content you do not need indexed.',
            '# Each line states the share of its traffic that is crawlers and',
            '# how many sampled crawler requests it would stop. Everything',
            '# here is reached by real visitors as well, so these are left',
            '# inactive rather than decided on your behalf.',
        ]
        prefix = '' if enable_review else '# '
        for rule in review:
            lines.append(f'#   {rule["reason"]}'
                         f' ({rule["crawler_requests"]:,} sampled requests,'
                         f' {rule["human_requests"]:,} non-crawler)')
            lines.append(f'{prefix}Disallow: {rule["pattern"]}')

    if current is not None and current.sitemaps:
        lines += ['']
        lines += [f'Sitemap: {s}' for s in current.sitemaps]
    return '\n'.join(lines) + '\n'


# --- measurement (pass two) ------------------------------------------------


class Replay:
    """Counts what two robots files would have done to the collected rows."""

    def __init__(self, host, current_text, proposed_text, review_text=None):
        self.host = host
        self.current = Robots(current_text or '')
        self.current_first = FirstGroupRobots(current_text or '')
        self.proposed = Robots(proposed_text)
        # The same proposal with its commented-out rules live. Measured rather
        # than derived: the review rules overlap the active ones, so their
        # totals do not add.
        self.review = Robots(review_text) if review_text else None
        self.rows = self.crawler_requests = self.crawler_bytes = 0
        self.cur_req = self.cur_bytes = 0
        self.cur_first_req = 0
        self.new_req = self.new_bytes = 0
        self.rev_req = self.rev_bytes = 0
        self.gain_req = self.gain_bytes = 0
        self.human_requests = self.human_matched = self.human_bytes = 0
        self.by_crawler = {}
        self.by_rule = {}
        self.existing_rule_hits = {}

    def feed(self, row):
        if _text(row.get('Host')) != self.host:
            return
        self.rows += 1
        path = request_path(row)
        if not path:
            return
        user_agent = _text(row.get('UserAgent'))
        sent = _int(row.get('BytesSent')) or 0
        known = classify_ua(user_agent)

        if known is None and not looks_like_crawler(user_agent):
            # The ceiling: what the same patterns would catch if only these
            # clients obeyed robots.txt. They do not.
            self.human_requests += 1
            # '~unmatched' matches no explicit group, so this falls through to
            # the `*` group — the rules a crawler here would actually obey.
            if not self.proposed.allowed('~unmatched', path)[0]:
                self.human_matched += 1
                self.human_bytes += sent
            return

        label = known[1] if known else 'Other (unclassified)'
        self.crawler_requests += 1
        self.crawler_bytes += sent

        cur_ok, cur_pattern = self.current.allowed(user_agent, path)
        if not cur_ok:
            self.cur_req += 1
            self.cur_bytes += sent
            self.existing_rule_hits[cur_pattern] = \
                self.existing_rule_hits.get(cur_pattern, 0) + 1
        if not self.current_first.allowed(user_agent, path)[0]:
            self.cur_first_req += 1

        new_ok, new_pattern = self.proposed.allowed(user_agent, path)
        if not new_ok:
            self.new_req += 1
            self.new_bytes += sent
            entry = self.by_rule.setdefault(new_pattern, [0, 0])
            entry[0] += 1
            entry[1] += sent
        if self.review is not None and not self.review.allowed(user_agent, path)[0]:
            self.rev_req += 1
            self.rev_bytes += sent

        if cur_ok and not new_ok:
            self.gain_req += 1
            self.gain_bytes += sent
            gained = self.by_crawler.setdefault(label, [0, 0, 0])
            gained[0] += 1
            gained[1] += sent
        seen = self.by_crawler.setdefault(label, [0, 0, 0])
        seen[2] += 1

    def result(self, *, scale=1.0):
        scale = scale or 1.0
        crawlers = [{
            'label': label,
            'requests': value[2],
            'newly_blocked': value[0],
            'newly_blocked_bytes': value[1],
            'share_blocked': _rate(value[0], value[2]),
        } for label, value in self.by_crawler.items() if value[2]]
        crawlers.sort(key=lambda c: -c['newly_blocked'])
        rules = [{'pattern': pattern, 'requests': v[0], 'bytes': v[1]}
                 for pattern, v in self.by_rule.items()]
        rules.sort(key=lambda r: -r['requests'])
        existing = [{'pattern': p, 'requests': c}
                    for p, c in self.existing_rule_hits.items()]
        existing.sort(key=lambda r: -r['requests'])
        return {
            'host': self.host,
            'rows': self.rows,
            'crawler_requests': self.crawler_requests,
            'crawler_bytes': self.crawler_bytes,
            'current': {
                'requests': self.cur_req,
                'bytes': self.cur_bytes,
                'request_share': _rate(self.cur_req, self.crawler_requests),
                'byte_share': _rate(self.cur_bytes, self.crawler_bytes),
                'rules_hit': existing,
            },
            'proposed': {
                'requests': self.new_req,
                'bytes': self.new_bytes,
                'request_share': _rate(self.new_req, self.crawler_requests),
                'byte_share': _rate(self.new_bytes, self.crawler_bytes),
            },
            'with_review': None if self.review is None else {
                'requests': self.rev_req,
                'bytes': self.rev_bytes,
                'request_share': _rate(self.rev_req, self.crawler_requests),
                'byte_share': _rate(self.rev_bytes, self.crawler_bytes),
            },
            'net': {
                'requests': self.gain_req,
                'bytes': self.gain_bytes,
                'extrapolated_requests': int(self.gain_req * scale),
                'extrapolated_bytes': int(self.gain_bytes * scale),
            },
            'by_crawler': crawlers[:TOP_N * 2],
            'by_rule': rules[:TOP_N * 2],
            'ceiling': {
                'human_requests': self.human_requests,
                'matched': self.human_matched,
                'bytes': self.human_bytes,
                'request_share': _rate(self.human_matched, self.human_requests),
            },
            'group_gap': {
                'merged': self.cur_req,
                'first_group_only': self.cur_first_req,
                'gap': self.cur_req - self.cur_first_req,
            },
            'scale': scale,
        }


# --- findings --------------------------------------------------------------


def _finding(code, severity, title, detail, evidence, impact=None):
    return {'code': code, 'severity': severity, 'category': CATEGORY_ROBOTS,
            'title': title, 'detail': detail, 'evidence': evidence,
            'impact': impact}


MIN_FINDING_REQUESTS = 100
DEAD_RULE_SHARE = 0.01


def build_findings(report):
    """What the measurement means, stated only where it was measured."""
    out = []
    measurement = report.get('measurement') or {}
    proposal = report.get('proposal') or {}
    net = measurement.get('net') or {}
    current = measurement.get('current') or {}
    ceiling = measurement.get('ceiling') or {}
    host = report.get('host')

    if not proposal.get('rules'):
        return [_finding(
            'robots_nothing_to_propose', 'info',
            'No robots.txt rules worth proposing',
            'No path or parameter on this host carries enough crawler traffic, '
            'lopsidedly enough, to justify a rule. That is a result: it means '
            'crawl load here is spread across content real visitors also use, '
            'so robots.txt is the wrong lever and caching or rate limiting is '
            'the right one.',
            {'host': host},
            impact='no rule qualified')]

    if net.get('requests', 0) >= MIN_FINDING_REQUESTS:
        out.append(_finding(
            'robots_measured_reduction', 'info',
            f'Proposed robots.txt would stop {net["requests"]:,} sampled requests',
            f'Replayed against the collected rows for {host}, the proposed file '
            f'blocks {net["requests"]:,} crawler requests the current file '
            f'allows — {(net.get("bytes") or 0) / 1e6:,.0f} MB sampled, about '
            f'{net.get("extrapolated_requests", 0):,} requests over the full '
            f'window. robots.txt is served by the origin, so this is a change '
            f'the site team makes, not one the portal can apply.',
            {'host': host, 'net': net},
            impact=f'{net["requests"]:,} sampled requests, '
                   f'{(net.get("bytes") or 0) / 1e9:.2f} GB'))

    with_review = measurement.get('with_review') or {}
    review_rules = [r for r in proposal.get('rules', [])
                    if r.get('tier') == TIER_REVIEW]
    if review_rules and with_review.get('requests'):
        extra = with_review['requests'] - (measurement.get('proposed') or {}).get('requests', 0)
        out.append(_finding(
            'robots_review_tier', 'info',
            f'{len(review_rules)} further rule(s) need a decision only you can make',
            f'These cover sections that are crawl-heavy — well above the '
            f'{_pct(proposal.get("crawler_share") or 0)} crawler share of the '
            f'host overall — but that real visitors also reach, so disallowing '
            f'them trades crawl load against search visibility. They ship '
            f'commented out. Measured with all of them enabled, the file blocks '
            f'{with_review["requests"]:,} sampled crawler requests '
            f'({_pct(with_review.get("request_share") or 0)}) instead of '
            f'{(measurement.get("proposed") or {}).get("requests", 0):,} — '
            f'{extra:,} more. Enable the ones whose content you do not need '
            f'indexed.',
            {'host': host, 'rules': review_rules, 'with_review': with_review},
            impact=f'{extra:,} further sampled requests if all are enabled'))

    crawler_requests = measurement.get('crawler_requests') or 0
    if crawler_requests and (current.get('request_share') or 0) < DEAD_RULE_SHARE \
            and current.get('requests', 0) >= 0 and report.get('current_text'):
        out.append(_finding(
            'robots_current_ineffective', 'warning',
            'The current robots.txt blocks almost nothing',
            f'Of {crawler_requests:,} sampled crawler requests to {host}, the '
            f'file as served stopped {current.get("requests", 0):,}. The usual '
            'cause is a pattern anchored at the path start that does not match '
            'where the traffic is: `Disallow: /tag` never matches '
            '`/news/tag/foo`. Patterns match from the beginning of the path, '
            'so a rule has to name the path the crawler actually requests.',
            {'host': host, 'blocked': current.get('requests', 0),
             'rules_hit': current.get('rules_hit', [])[:8]},
            impact=f'{_pct(current.get("request_share") or 0)} of {crawler_requests:,} crawler requests'))

    gap = measurement.get('group_gap') or {}
    if gap.get('gap', 0) >= MIN_FINDING_REQUESTS:
        out.append(_finding(
            'robots_group_gap', 'warning',
            'WaaS splits the file into two groups and some crawlers see only the first',
            f'WaaS rewrites /robots.txt in flight, prepending its own '
            f'`User-agent: *` group with a spider-trap rule. That leaves two '
            f'`*` groups. Google merges them, so the origin\'s rules survive — '
            f'but a crawler that reads only the first matching group sees '
            f'nothing but the trap. Measured difference between the two '
            f'readings: {gap["gap"]:,} sampled requests the origin meant to '
            f'block that a non-merging crawler fetches anyway.',
            {'host': host, **gap},
            impact=f'{gap["gap"]:,} sampled requests read differently'))

    # `served` is present-but-None whenever nothing was fetched — which is the
    # normal path, because a pasted file short-circuits the fetch entirely.
    if (report.get('served') or {}).get('served_as_html'):
        out.append(_finding(
            'robots_served_as_html', 'warning',
            '/robots.txt came back as an HTML page',
            'The fetch returned HTML rather than a robots file. A WaaS CAPTCHA '
            'challenge is served at HTTP 200 with an HTML body, and the robots '
            'spec says to parse a 200 body as the file — which yields no rules '
            'at all, i.e. allow-all. This may only be happening to the portal\'s '
            'own IP rather than to crawlers: check `CaptchaState` in the WAF '
            'logs for `/robots.txt` before concluding the file is broken. The '
            'before/after numbers here were measured against an empty rule set '
            'and understate what the current file does.',
            {'host': host, **(report.get('served') or {})},
            impact='current-file figures understated'))

    if (ceiling.get('request_share') or 0) >= 0.05:
        out.append(_finding(
            'robots_ceiling', 'info',
            f'{_pct(ceiling["request_share"])} of non-crawler traffic matches the same patterns',
            f'{ceiling.get("matched", 0):,} requests from clients that do not '
            f'identify as crawlers match the proposed patterns. robots.txt is '
            f'honoured voluntarily and only by clients that declare themselves, '
            f'so these are untouched by any crawl rule — they are browser-UA '
            f'clients, feed readers, and crawlers that spoof a browser. Caching '
            f'and rate limiting are the levers that reach them.',
            {'host': host, **ceiling},
            impact=f'{ceiling.get("matched", 0):,} requests no crawl rule can reach'))
    return out


# --- fetching the file as served -------------------------------------------

FETCH_TIMEOUT = 15.0
MAX_ROBOTS_BYTES = 512 * 1024


def fetch_robots(host, *, session=None, timeout=FETCH_TIMEOUT,
                 check_host=None):
    """Fetch `https://<host>/robots.txt` as served.

    `Host` comes off the wire in the log rows, so it is attacker-influenced
    and is gated the same way the header audit gates its probes before any
    request leaves the portal.

    What comes back is the file *as WaaS serves it*, which is not the file the
    origin serves — see `describe_served`. It is still the right thing to
    measure, because it is what a crawler receives.
    """
    import requests

    if check_host is not None and not check_host(host):
        return {'error': 'host not resolvable to a public address',
                'text': None, 'status': None}
    getter = session.get if session is not None else requests.get
    try:
        response = getter(
            f'https://{host}/robots.txt', timeout=timeout,
            allow_redirects=True, stream=True,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; WaaS-Portal/2.0)',
                     'Accept': 'text/plain,*/*'})
        body = response.raw.read(MAX_ROBOTS_BYTES, decode_content=True) or b''
        status = response.status_code
        content_type = response.headers.get('Content-Type', '')
        response.close()
    except Exception as e:  # noqa: BLE001 — a failed fetch is a reportable state
        logger.warning('robots fetch failed for %s: %s', host, e)
        return {'error': str(e)[:200], 'text': None, 'status': None}
    if status != 200:
        return {'error': f'HTTP {status}', 'text': None, 'status': status,
                'content_type': content_type}
    return {'error': None, 'status': status, 'content_type': content_type,
            'text': body.decode('utf-8', 'replace')}


# --- orchestration ---------------------------------------------------------


def _stream(store, aggregator, *, dates, yield_every, on_progress,
            should_cancel, offset=0):
    from app.logpull.analysis import _yield_to_hub

    index = 0
    for index, row in enumerate(store.iter_rows(dates=dates), start=1):
        aggregator.feed(row)
        if index % yield_every == 0:
            _yield_to_hub()
            if should_cancel is not None and should_cancel():
                from app.logpull.windows import Cancelled
                raise Cancelled()
            if on_progress is not None:
                on_progress(offset + index)
    if on_progress is not None:
        on_progress(offset + index)
    return index


def build_report(store, summary=None, *, dates=None, scale=None, host=None,
                 current_text=None, fetcher=fetch_robots, check_host=None,
                 yield_every=25_000, on_progress=None, should_cancel=None,
                 **propose_kwargs):
    """Generate a robots.txt proposal and measure it. Two passes.

    The first pass collects candidate statistics; the second replays the
    rendered file against the same rows. They cannot be merged — you cannot
    measure a file you have not written yet — and the separation is what keeps
    the published numbers attached to the bytes that actually ship.

    `current_text` short-circuits the live fetch. Pasting the file the origin
    serves is strictly better evidence than fetching it through WaaS, which
    rewrites it; the fetch is the fallback for when nobody has it to hand.
    """
    summary = summary or {}
    if scale is None:
        scale = summary.get('scale') or 1.0

    collector = RobotsAggregator()
    rows = _stream(store, collector, dates=dates, yield_every=yield_every,
                   on_progress=on_progress, should_cancel=should_cancel)
    overview = collector.result()

    host = host or collector.best_host()
    if host is None:
        return {
            'host': None, 'rows': rows, 'hosts': overview['hosts'],
            'caps': overview['caps'],
            'findings': [_finding(
                'robots_no_host', 'info',
                'Not enough crawler traffic to propose a robots.txt',
                f'No host in this pull saw {MIN_HOST_CRAWLER_REQUESTS:,} '
                'crawler requests. A proposal measured on less than that would '
                'be describing noise.',
                {'hosts': overview['hosts'][:5]})],
        }

    candidates = collector.candidates_for(host)
    proposal = propose(candidates, **propose_kwargs)

    served = None
    fetched = None
    # Where the baseline came from decides how much the before/after figures
    # are worth, so it is recorded rather than inferred from what is present.
    text_source = 'pasted' if current_text is not None else None
    if current_text is None and fetcher is not None:
        fetched = fetcher(host, check_host=check_host)
        current_text = fetched.get('text')
        text_source = 'fetched' if current_text is not None else None
    if current_text is not None:
        served = describe_served(
            current_text,
            content_type=(fetched or {}).get('content_type'))
    current = Robots(current_text) if current_text else None

    scale_note = ''
    if (summary.get('rows_sampled') or 0) and scale and scale > 1.01:
        scale_note = (f' ({summary["rows_sampled"]:,} rows, '
                      f'{1 / scale * 100:.2f}% time-sampled)')

    # Render first, measure the rendered bytes, then render again with the
    # numbers. Measuring a draft and shipping a later one is exactly the
    # mistake this ordering exists to make impossible.
    draft = render_file(proposal, current=current, scale_note=scale_note)
    review_draft = None
    if proposal.get('review_count'):
        review_draft = render_file(proposal, current=current,
                                   scale_note=scale_note, enable_review=True)
    replay = Replay(host, current_text or '', draft, review_draft)
    _stream(store, replay, dates=dates, yield_every=yield_every,
            on_progress=on_progress, should_cancel=should_cancel, offset=rows)
    measurement = replay.result(scale=scale)
    final = render_file(proposal, current=current, measurement=measurement,
                        scale_note=scale_note)

    report = {
        'host': host,
        'rows': rows,
        'generated_at': datetime.utcnow().isoformat(),
        'hosts': overview['hosts'],
        'caps': overview['caps'],
        'proposal': proposal,
        'measurement': measurement,
        'served': served,
        'fetch_error': (fetched or {}).get('error'),
        'current_text': current_text,
        'current_text_source': text_source,
        'file': final,
        'scale': scale,
    }
    report['findings'] = build_findings(report)
    return report
