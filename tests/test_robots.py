"""Tests for the robots.txt proposal engine (app/logpull/robots.py).

The engine's output is a file a customer deploys on a judgement it makes on
their behalf, so most of what is pinned down here is the difference between a
rule that works and one that looks like it works:

- `urllib.robotparser` cannot do any of this. CPython's `RuleLine.applies_to`
  is `path == "*" or filename.startswith(self.path)`, so `/*?*eventDisplay=`
  degrades to a literal prefix and matches nothing — and the stdlib then
  cheerfully agrees that a broken file is working.
- Patterns anchor at the path start. `Disallow: /tag` never touches
  `/news-and-events-calendar/tag/...`, which is exactly why one real
  customer's existing file blocked 0.29% of its crawler traffic.
- A trailing slash changes what a rule covers. `/search_gcse/` misses
  `/search_gcse?q=x`, which on real traffic is most of the volume.
- A rule has to describe a space, not a page, and a wildcard has to stand for
  something. `/membership/*/one-article/` and `/*/2/` are both syntactically
  patterns and semantically single URLs.
- Every published number has to come from replaying the bytes that ship. A
  rule added after the measurement invalidates it.
"""
import uuid

import pytest

from app.logpull.robots import (
    CONTENT_SELECTOR_KEYS,
    MAX_PREFIX_DEPTH,
    MIN_HOST_CRAWLER_REQUESTS,
    MIN_PREFIX_VARIANTS,
    MIN_SCOPED_PARENTS,
    TIER_CONFIDENT,
    TIER_REVIEW,
    FirstGroupRobots,
    Replay,
    Robots,
    RobotsAggregator,
    _carry_over,
    _query_keys,
    _segments,
    build_findings,
    build_report,
    describe_served,
    propose,
    render_file,
    request_path,
)
from app.logpull.store import PullStore
from app.logpull.windows import MODE_SAMPLE
from app.models import LogPull, User, WaasAccount

BASE_MS = 1_767_225_600_000  # 2026-01-01T00:00:00Z in milliseconds

CHROME = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
          '(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36')
GOOGLEBOT = ('Mozilla/5.0 (compatible; Googlebot/2.1; '
             '+http://www.google.com/bot.html)')
BINGBOT = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'

HOST = 'www.example.com'


def row(**kwargs):
    """One access-log row with the API's real field names and string types."""
    defaults = {
        'Host': HOST,
        'URL': '/articles/launch',
        'QueryString': '"-"',
        'ClientIP': '198.51.100.7',
        'HTTPStatus': 200,
        'BytesSent': '1024',
        'CacheHit': '0',
        'EpochTime': str(BASE_MS),
        'UserAgent': CHROME,
    }
    defaults.update(kwargs)
    return defaults


def bulk(n, **kwargs):
    return [row(**kwargs) for _ in range(n)]


def varied(n, url, *, crawler=True, query=None, **kwargs):
    """`n` rows under `url`, each with a different continuation.

    The variants guard rejects a prefix whose traffic is really one page, so
    any fixture that expects a prefix rule has to look like a space.
    """
    out = []
    for i in range(n):
        if query is None:
            out.append(row(URL=f'{url}/item-{i % 20}',
                           UserAgent=GOOGLEBOT if crawler else CHROME, **kwargs))
        else:
            out.append(row(URL=url, QueryString=f'{query}={i % 20}',
                           UserAgent=GOOGLEBOT if crawler else CHROME, **kwargs))
    return out


def feed_all(rows):
    agg = RobotsAggregator()
    for r in rows:
        agg.feed(r)
    return agg


def patterns(proposal, tier=None):
    return [r['pattern'] for r in proposal['rules']
            if tier is None or r['tier'] == tier]


# --- the matcher -----------------------------------------------------------


class TestPatternMatching:
    """Google's spec, which is not what the standard library implements."""

    def allowed(self, rules, path, agent='Googlebot'):
        text = 'User-agent: *\n' + '\n'.join(rules)
        return Robots(text).allowed(agent, path)[0]

    def test_a_prefix_matches_every_continuation(self):
        """`Disallow: /fish` covers all five of these per the spec."""
        for path in ('/fish', '/fish.html', '/fish?id=1', '/fish/salmon',
                     '/fishheads'):
            assert not self.allowed(['Disallow: /fish'], path), path

    def test_patterns_anchor_at_the_start_of_the_path(self):
        """The defect that made a real customer's file useless: the rule was
        `/tag` and the traffic was at `/news-and-events-calendar/tag/...`."""
        assert not self.allowed(['Disallow: /tag'], '/tag/climate')
        assert self.allowed(['Disallow: /tag'], '/news-and-events-calendar/tag/x')

    def test_a_trailing_slash_excludes_the_query_string_form(self):
        """Why the generator emits bare prefixes. On one real corpus this
        distinction was 9,591 blocked requests against 5,347."""
        assert self.allowed(['Disallow: /search/'], '/search?q=boots')
        assert not self.allowed(['Disallow: /search'], '/search?q=boots')

    def test_wildcards_span_path_segments(self):
        assert not self.allowed(['Disallow: /*/page/'], '/news/2026/page/4')
        assert not self.allowed(['Disallow: /*?*sort='], '/shop/boots?x=1&sort=asc')

    def test_a_wildcard_does_not_match_an_empty_segment(self):
        """`/a/*/b/` needs something between a and b. This is why the scoped
        segment form is never emitted at depth 1 — it would match nothing."""
        assert self.allowed(['Disallow: /news/*/tag/'], '/news/tag/climate')

    def test_dollar_anchors_the_end(self):
        assert not self.allowed(['Disallow: /*.pdf$'], '/docs/manual.pdf')
        assert self.allowed(['Disallow: /*.pdf$'], '/docs/manual.pdf.html')

    def test_regex_metacharacters_in_a_pattern_are_literal(self):
        """A `.` or `+` in a path is a character, not a regex operator."""
        assert not self.allowed(['Disallow: /a.b'], '/a.b')
        assert self.allowed(['Disallow: /a.b'], '/axb')

    def test_the_longest_matching_pattern_wins(self):
        rules = ['Disallow: /shop', 'Allow: /shop/boots']
        assert self.allowed(rules, '/shop/boots/red')
        assert not self.allowed(rules, '/shop/hats')

    def test_allow_beats_disallow_at_equal_length(self):
        rules = ['Disallow: /p', 'Allow: /p']
        assert self.allowed(rules, '/page')

    def test_an_empty_file_allows_everything(self):
        assert Robots('').allowed('Googlebot', '/anything')[0]

    def test_a_comment_only_file_allows_everything(self):
        """The CAPTCHA-page failure mode in miniature: a body with no
        directives parses as permission to crawl everything."""
        assert Robots('# nothing here\n').allowed('Googlebot', '/anything')[0]

    def test_rules_outside_any_group_are_ignored(self):
        assert Robots('Disallow: /x\n').allowed('Googlebot', '/x')[0]


class TestGroupSelection:
    text = (
        'User-agent: *\n'
        'Disallow: /private\n'
        '\n'
        'User-agent: Googlebot\n'
        'Disallow: /no-google\n'
    )

    def test_a_named_group_replaces_the_star_group_entirely(self):
        """Google does not merge the `*` group into a named one — a crawler
        with its own group ignores `*` completely."""
        bots = Robots(self.text)
        assert bots.allowed(GOOGLEBOT, '/private')[0]
        assert not bots.allowed(GOOGLEBOT, '/no-google')[0]

    def test_an_unnamed_agent_falls_back_to_the_star_group(self):
        assert not Robots(self.text).allowed('SomeOtherBot', '/private')[0]

    def test_the_longest_matching_token_wins(self):
        """`Applebot-Extended` is an AI opt-out and `Applebot` is a search
        crawler. Matching the shorter token first silently conflates them."""
        text = ('User-agent: Applebot\nDisallow: /a\n\n'
                'User-agent: Applebot-Extended\nDisallow: /b\n')
        bots = Robots(text)
        assert bots.group_for('Applebot-Extended/1.0')[0] == 'applebot-extended'
        assert bots.group_for('Applebot/0.1')[0] == 'applebot'

    def test_agent_matching_is_case_insensitive(self):
        text = 'User-agent: GoogleBot\nDisallow: /x\n'
        assert not Robots(text).allowed('googlebot/2.1', '/x')[0]

    def test_same_agent_groups_merge(self):
        """Google merges repeated groups for one agent. The WaaS honeypot
        relies on this being true for Google and false for simpler crawlers."""
        text = ('User-agent: *\nDisallow: /a\n\n'
                'User-agent: *\nDisallow: /b\n')
        bots = Robots(text)
        assert not bots.allowed('AnyBot', '/a')[0]
        assert not bots.allowed('AnyBot', '/b')[0]
        assert bots.duplicate_agents


class TestFirstGroupReading:
    """Crawlers that stop at the first matching group see a different file.

    WaaS prepends its own `*` group with a spider trap when it rewrites
    /robots.txt in flight. Google merges and still honours the origin's rules;
    a non-merging crawler sees the trap and nothing else. The gap between the
    two readings is a number worth reporting, so both have to be computed.
    """
    text = ('User-agent: *\nDisallow: /trap.html\n\n'
            'User-agent: *\nDisallow: /real-rule\n')

    def test_merged_reading_honours_the_later_group(self):
        assert not Robots(self.text).allowed('AnyBot', '/real-rule')[0]

    def test_first_group_reading_does_not(self):
        assert FirstGroupRobots(self.text).allowed('AnyBot', '/real-rule')[0]

    def test_both_readings_honour_the_first_group(self):
        assert not Robots(self.text).allowed('AnyBot', '/trap.html')[0]
        assert not FirstGroupRobots(self.text).allowed('AnyBot', '/trap.html')[0]


class TestDescribeServed:
    def test_an_html_body_is_flagged_rather_than_parsed_as_rules(self):
        """WaaS answers some requests for /robots.txt with a CAPTCHA page at
        HTTP 200. The spec says parse a 200 body as the file, which yields
        zero rules — allow everything. The only safe response is to say so."""
        served = describe_served('<html><body>Please verify</body></html>',
                                 content_type='text/html; charset=utf-8')
        assert served['served_as_html'] is True
        assert served['rules'] == 0

    def test_a_plain_file_is_not_flagged(self):
        served = describe_served('User-agent: *\nDisallow: /x\n',
                                 content_type='text/plain')
        assert served['served_as_html'] is False
        assert served['rules'] == 1

    def test_the_waas_honeypot_is_recognised(self):
        """Reported as the matched pattern rather than a flag, because the
        token rotates and the one in play is worth seeing."""
        served = describe_served(
            'User-agent: *\n'
            'Disallow: /wgGspiCOBVxKdye9ek5xHh7exItGHgkvW380igAFySY=.html\n')
        assert served['waas_honeypot'] == (
            '/wgGspiCOBVxKdye9ek5xHh7exItGHgkvW380igAFySY=.html')

    def test_an_ordinary_html_disallow_is_not_mistaken_for_the_honeypot(self):
        served = describe_served('User-agent: *\nDisallow: /index.html\n')
        assert served['waas_honeypot'] is None

    def test_sitemaps_are_collected(self):
        served = describe_served('Sitemap: https://x.test/s.xml\nUser-agent: *\n')
        assert served['sitemaps'] == ['https://x.test/s.xml']


# --- what a robots pattern is matched against ------------------------------


class TestRequestPath:
    def test_the_query_string_is_part_of_the_path(self):
        """Patterns like `/*?*sort=` only work if the matched string carries
        the query. `QueryString` is a separate field in the API's rows."""
        assert request_path(row(URL='/shop', QueryString='sort=asc')) == '/shop?sort=asc'

    def test_an_absent_query_string_is_the_three_character_dash(self):
        assert request_path(row(URL='/shop', QueryString='"-"')) == '/shop'

    def test_a_url_without_a_leading_slash_gets_one(self):
        assert request_path(row(URL='shop')).startswith('/shop')

    def test_segments_ignore_empty_components(self):
        assert _segments('/a//b/') == ['a', 'b']

    def test_query_keys_are_the_names_only(self):
        assert list(_query_keys('a=1&b=2&c')) == ['a', 'b', 'c']


# --- candidate collection --------------------------------------------------


class TestAggregation:
    def test_hosts_are_counted_separately(self):
        agg = feed_all(bulk(5, Host='a.test') + bulk(3, Host='b.test'))
        hosts = {h['host']: h for h in agg.result()['hosts']}
        assert hosts['a.test']['requests'] == 5
        assert hosts['b.test']['requests'] == 3

    def test_static_assets_count_toward_the_host_but_never_become_rules(self):
        """Disallowing a site's CSS is how you get a site that renders wrong
        in search results. Static paths are traffic, not candidates."""
        agg = feed_all(bulk(50, URL='/static/app.js', UserAgent=GOOGLEBOT))
        host = agg.candidates_for(HOST)
        assert host['crawler'] == 50
        assert host['prefixes'] == {}

    def test_the_busiest_crawler_host_is_chosen(self):
        """robots.txt is per host, so one file covering several would be
        wrong however carefully it was measured."""
        agg = feed_all(
            bulk(MIN_HOST_CRAWLER_REQUESTS + 10, Host='busy.test', UserAgent=GOOGLEBOT)
            + bulk(MIN_HOST_CRAWLER_REQUESTS + 1, Host='quiet.test', UserAgent=GOOGLEBOT))
        assert agg.best_host() == 'busy.test'

    def test_a_host_below_the_floor_is_not_proposed_for(self):
        agg = feed_all(bulk(5, UserAgent=GOOGLEBOT))
        assert agg.best_host() is None

    def test_numeric_segments_are_not_collected(self):
        """A number in a path is a value, not a name. Collecting them
        produced one rule per page number — `/*/2/`, `/*/3/`, `/*/4/` — each
        describing a slice of the same archive and none of them a pattern."""
        agg = feed_all([row(URL=f'/news/{n}/story', UserAgent=GOOGLEBOT)
                        for n in range(2, 40)])
        names = {name for _scope, name in agg.candidates_for(HOST)['segments']}
        assert names == {'story'}

    def test_a_segment_is_counted_site_wide_and_scoped(self):
        """Site-wide `page` is a mix because humans paginate too and fails
        the dominance test; `page` under one archive section passes it."""
        agg = feed_all([row(URL=f'/news/{y}/page/2', UserAgent=GOOGLEBOT)
                        for y in range(2000, 2030)])
        keys = agg.candidates_for(HOST)['segments']
        assert (None, 'page') in keys
        assert ('news', 'page') in keys

    def test_the_scoped_form_is_not_recorded_at_depth_one(self):
        """`/news/*/tag/` cannot match `/news/tag/x` — the wildcard would
        have to be empty. That case is the prefix `/news/tag`."""
        agg = feed_all(bulk(10, URL='/news/tag/climate', UserAgent=GOOGLEBOT))
        keys = agg.candidates_for(HOST)['segments']
        assert ('news', 'tag') not in keys
        assert (None, 'tag') in keys

    def test_prefix_variants_record_the_next_segment(self):
        agg = feed_all([row(URL=f'/shop/{n}') for n in range(5)])
        assert agg.candidates_for(HOST)['prefixes']['/shop']['variants'] == {
            '0', '1', '2', '3', '4'}

    def test_prefix_variants_fall_back_to_the_query_string(self):
        """`/search` has no child segments at all but thousands of distinct
        query strings. It is a space; the variants have to see that."""
        agg = feed_all([row(URL='/search', QueryString=f'q={n}') for n in range(4)])
        variants = agg.candidates_for(HOST)['prefixes']['/search']['variants']
        assert variants == {'q=0', 'q=1', 'q=2', 'q=3'}


# --- candidate selection ---------------------------------------------------


class TestPrefixCandidates:
    def test_a_crawler_dominated_space_is_proposed(self):
        agg = feed_all(varied(400, '/search-results')
                       + varied(20, '/search-results', crawler=False)
                       + bulk(2000, URL='/home', UserAgent=CHROME))
        assert '/search-results' in patterns(propose(agg.candidates_for(HOST)))

    def test_the_rule_carries_no_trailing_slash(self):
        """So that it covers the query-string form, which is usually most of
        the traffic it is meant to stop."""
        agg = feed_all(varied(400, '/search-results')
                       + bulk(2000, URL='/home', UserAgent=CHROME))
        assert '/search-results/' not in patterns(propose(agg.candidates_for(HOST)))

    def test_a_single_page_is_not_proposed_as_a_prefix(self):
        """A depth-3 prefix on a site with long article slugs is an
        individual article. One real corpus proposed a rule for one URL."""
        agg = feed_all(bulk(400, URL='/membership/committees/one-application',
                            UserAgent=GOOGLEBOT)
                       + bulk(2000, URL='/home', UserAgent=CHROME))
        host = agg.candidates_for(HOST)
        entry = host['prefixes']['/membership/committees']
        assert entry['crawler'] == 400                       # over every floor
        assert len(entry['variants']) < MIN_PREFIX_VARIANTS  # and still one page
        assert not any('one-application' in p
                       for p in patterns(propose(host)))

    def test_a_space_with_enough_variants_survives_the_same_filter(self):
        agg = feed_all(varied(400, '/archive')
                       + bulk(2000, URL='/home', UserAgent=CHROME))
        assert '/archive' in patterns(propose(agg.candidates_for(HOST)))

    def test_candidates_stay_shallow(self):
        agg = feed_all(varied(400, '/a/b/c') + bulk(2000, URL='/home', UserAgent=CHROME))
        for pattern in patterns(propose(agg.candidates_for(HOST))):
            assert pattern.count('/') <= MAX_PREFIX_DEPTH

    def test_a_dominated_parent_subsumes_its_children(self):
        """Nine rules describing one space is nine lines somebody has to
        review to learn what one line would have told them."""
        agg = feed_all(varied(400, '/archive')
                       + varied(400, '/archive/2025')
                       + bulk(4000, URL='/home', UserAgent=CHROME))
        chosen = patterns(propose(agg.candidates_for(HOST)))
        assert '/archive' in chosen
        assert '/archive/2025' not in chosen


class TestSegmentCandidates:
    def test_a_scoped_segment_needs_more_than_one_parent(self):
        """`/membership/*/x/` where the wildcard only ever took one value is
        a rule for one URL wearing a pattern's syntax."""
        agg = feed_all(bulk(400, URL='/membership/committees/one-application',
                            UserAgent=GOOGLEBOT)
                       + bulk(2000, URL='/home', UserAgent=CHROME))
        proposal = propose(agg.candidates_for(HOST))
        assert not any(p.startswith('/membership/*/') for p in patterns(proposal))

    def test_a_scoped_segment_with_several_parents_is_proposed(self):
        """Pagination under one section: crawler-only there, mixed site-wide,
        and the section itself is ordinary content. Only the scoped form
        describes what is actually happening."""
        rows = []
        for year in range(2000, 2000 + MIN_SCOPED_PARENTS + 4):
            rows += bulk(60, URL=f'/news/{year}/page/2', UserAgent=GOOGLEBOT)
            rows += bulk(40, URL=f'/news/{year}/story-{year}', UserAgent=CHROME)
        rows += bulk(200, URL='/shop/boots/page/2', UserAgent=CHROME)
        agg = feed_all(rows + bulk(2000, URL='/home', UserAgent=CHROME))
        chosen = patterns(propose(agg.candidates_for(HOST)))
        assert '/news/*/page/' in chosen
        assert '/*/page/' not in chosen
        assert '/news' not in chosen


class TestQueryCandidates:
    def test_an_enriched_parameter_is_proposed(self):
        """The section itself is shared with real visitors, so no path rule
        is safe there — but the faceted view only crawlers walk is."""
        agg = feed_all(varied(400, '/events', query='eventDisplay')
                       + bulk(400, URL='/events', UserAgent=CHROME)
                       + bulk(4000, URL='/home', UserAgent=CHROME))
        chosen = patterns(propose(agg.candidates_for(HOST)))
        assert '/*?*eventDisplay=' in chosen
        assert '/events' not in chosen

    def test_a_content_selecting_parameter_is_never_proposed(self):
        """`/*?*id=` is a site-wide rule. On a corpus where crawlers happen to
        dominate `?id=` it passes every statistical test while quietly
        proposing to de-index the catalogue. No measurement separates a crawl
        trap from a product page; a denylist does."""
        agg = feed_all(varied(2000, '/product', query='id')
                       + bulk(4000, URL='/home', UserAgent=CHROME))
        assert '/*?*id=' not in patterns(propose(agg.candidates_for(HOST)))

    def test_the_denylist_ignores_a_leading_underscore(self):
        assert 'id' in CONTENT_SELECTOR_KEYS
        agg = feed_all(varied(2000, '/product', query='_id')
                       + bulk(4000, URL='/home', UserAgent=CHROME))
        assert '/*?*_id=' not in patterns(propose(agg.candidates_for(HOST)))

    def test_enrichment_is_measured_against_the_host_not_a_flat_majority(self):
        """On a corpus that is 9% crawler, a parameter at 46% is the trap.
        Waiting for it to cross 50% means never naming it."""
        agg = feed_all(varied(300, '/events', query='eventDisplay')
                       + varied(400, '/events', query='eventDisplay', crawler=False)
                       + bulk(8000, URL='/home', UserAgent=CHROME))
        assert '/*?*eventDisplay=' in patterns(propose(agg.candidates_for(HOST)))


class TestTiers:
    """Two tiers, because the interesting traffic is rarely dominant.

    On a real corpus the site baseline was 16.6% crawler and the biggest
    crawl trap on the site ran 40-50% — enriched threefold and nowhere near
    dominance. An analyst blocked it anyway, on a content-duplication
    judgement that is not in the logs.
    """

    def confident_space(self):
        return varied(400, '/search-results') + varied(8, '/search-results',
                                                       crawler=False)

    def enriched_space(self):
        """Half crawler against a host baseline near a tenth: enriched
        fivefold, and nowhere near dominance."""
        return varied(1200, '/calendar') + varied(1200, '/calendar', crawler=False)

    def test_a_dominated_space_ships_active(self):
        agg = feed_all(self.confident_space() + bulk(4000, URL='/home', UserAgent=CHROME))
        assert '/search-results' in patterns(propose(agg.candidates_for(HOST)),
                                             TIER_CONFIDENT)

    def test_an_enriched_but_shared_space_is_held_for_review(self):
        agg = feed_all(self.enriched_space() + bulk(9000, URL='/home', UserAgent=CHROME))
        proposal = propose(agg.candidates_for(HOST))
        assert '/calendar' in patterns(proposal, TIER_REVIEW)
        assert '/calendar' not in patterns(proposal, TIER_CONFIDENT)

    def test_a_space_at_the_host_baseline_is_not_proposed_at_all(self):
        agg = feed_all(varied(500, '/blog') + varied(4500, '/blog', crawler=False)
                       + bulk(5000, URL='/home', UserAgent=CHROME))
        assert '/blog' not in patterns(propose(agg.candidates_for(HOST)))

    def test_review_rules_are_commented_out_in_the_file(self):
        agg = feed_all(self.enriched_space() + bulk(9000, URL='/home', UserAgent=CHROME))
        text = render_file(propose(agg.candidates_for(HOST)))
        assert '# Disallow: /calendar' in text
        assert '\nDisallow: /calendar' not in text

    def test_enabling_review_rules_renders_them_live(self):
        """The 'if you also enable these' figure has to come from replaying a
        real file, not from adding rule counts that overlap."""
        agg = feed_all(self.enriched_space() + bulk(9000, URL='/home', UserAgent=CHROME))
        text = render_file(propose(agg.candidates_for(HOST)), enable_review=True)
        assert '\nDisallow: /calendar' in text

    def test_an_active_rule_is_never_suppressed_by_a_review_rule(self):
        """A review rule may never be uncommented. If it had been allowed to
        subsume a live rule, the customer would quietly lose the reduction
        the file promised them."""
        agg = feed_all(self.enriched_space()
                       + varied(400, '/calendar/search')
                       + varied(4, '/calendar/search', crawler=False)
                       + bulk(9000, URL='/home', UserAgent=CHROME))
        proposal = propose(agg.candidates_for(HOST))
        assert '/calendar/search' in patterns(proposal, TIER_CONFIDENT)
        assert '/calendar' in patterns(proposal, TIER_REVIEW)


class TestRuleBudget:
    def test_the_budget_is_respected_and_the_rest_recorded(self):
        rows = bulk(20_000, URL='/home', UserAgent=CHROME)
        for i in range(8):
            rows += varied(300, f'/trap-{i}')
        proposal = propose(feed_all(rows).candidates_for(HOST), max_rules=3)
        assert len(proposal['rules']) == 3
        assert any(d['dropped'] == 'rule budget' for d in proposal['dropped'])


# --- rendering -------------------------------------------------------------


class TestRendering:
    def test_existing_rules_are_carried_over(self):
        """Dropping a rule the customer deliberately added is a worse failure
        than proposing nothing: it is an invisible change of policy."""
        current = Robots('User-agent: *\nDisallow: /admin\nDisallow: /tmp\n')
        text = render_file({'host': HOST, 'rules': [], 'review_count': 0},
                           current=current)
        assert 'Disallow: /admin' in text
        assert 'Disallow: /tmp' in text

    def test_duplicates_are_collapsed(self):
        current = Robots('User-agent: *\nDisallow: /a\n\nUser-agent: *\nDisallow: /a\n')
        assert _carry_over(current) == [(False, '/a')]

    def test_the_waas_honeypot_is_not_written_into_an_origin_file(self):
        """That line is injected into the response in flight, so it is not
        the origin's rule to keep. Writing it back would have WaaS stack its
        own copy on top and hard-code today's token into a lasting file."""
        current = Robots(
            'User-agent: *\n'
            'Disallow: /wgGspiCOBVxKdye9ek5xHh7exItGHgkvW380igAFySY=.html\n'
            'Disallow: /admin\n')
        assert _carry_over(current) == [(False, '/admin')]

    def test_sitemaps_survive(self):
        current = Robots('Sitemap: https://x.test/s.xml\nUser-agent: *\nAllow: /\n')
        text = render_file({'host': HOST, 'rules': [], 'review_count': 0},
                           current=current)
        assert 'Sitemap: https://x.test/s.xml' in text

    def test_the_rendered_file_parses_back_to_the_rules_it_states(self):
        """The only check that matters: what ships has to mean what the
        generator decided. A quoting or ordering slip here is invisible."""
        agg = feed_all(varied(400, '/search-results')
                       + bulk(4000, URL='/home', UserAgent=CHROME))
        proposal = propose(agg.candidates_for(HOST))
        reparsed = Robots(render_file(proposal))
        for rule in proposal['rules']:
            if rule['tier'] == TIER_CONFIDENT:
                assert not reparsed.allowed(GOOGLEBOT, rule['sample'])[0]

    def test_a_crawl_delay_is_emitted_when_asked_for(self):
        text = render_file({'host': HOST, 'rules': [], 'review_count': 0},
                           crawl_delay=10)
        assert 'Crawl-delay: 10' in text

    def test_the_header_states_the_measurement(self):
        measurement = {
            'crawler_requests': 1000,
            'current': {'requests': 10, 'request_share': 0.01, 'byte_share': 0.01},
            'proposed': {'requests': 300, 'request_share': 0.3, 'byte_share': 0.25},
            'net': {'requests': 290, 'bytes': 5_000_000_000},
            'ceiling': {'request_share': 0.09},
        }
        text = render_file({'host': HOST, 'rules': [], 'review_count': 0},
                           measurement=measurement)
        assert 'MEASURED' in text
        assert '1,000 sampled' in text
        assert '5.00 GB' in text
        assert 'Ceiling' in text


# --- measurement -----------------------------------------------------------


class TestReplay:
    def replay(self, rows, current='', proposed='', review=None):
        r = Replay(HOST, current, proposed, review)
        for row_ in rows:
            r.feed(row_)
        return r.result()

    def test_rows_for_other_hosts_are_ignored(self):
        """robots.txt is per host. Counting another host's traffic toward
        this file's impact is how a proposal overstates itself."""
        result = self.replay(bulk(10, Host='other.test', UserAgent=GOOGLEBOT),
                             proposed='User-agent: *\nDisallow: /\n')
        assert result['crawler_requests'] == 0

    def test_blocked_requests_and_bytes_are_counted(self):
        result = self.replay(bulk(10, URL='/trap', UserAgent=GOOGLEBOT, BytesSent='500'),
                             proposed='User-agent: *\nDisallow: /trap\n')
        assert result['proposed']['requests'] == 10
        assert result['proposed']['bytes'] == 5000
        assert result['proposed']['request_share'] == pytest.approx(1.0)

    def test_the_net_gain_excludes_what_the_current_file_already_blocked(self):
        """Reporting the proposed file's total as the saving would bill the
        customer for work their existing file is already doing."""
        result = self.replay(
            bulk(10, URL='/trap', UserAgent=GOOGLEBOT),
            current='User-agent: *\nDisallow: /trap\n',
            proposed='User-agent: *\nDisallow: /trap\n')
        assert result['proposed']['requests'] == 10
        assert result['net']['requests'] == 0

    def test_non_crawlers_count_toward_the_ceiling_not_the_saving(self):
        """robots.txt is honoured voluntarily and only by clients that declare
        themselves. Browser traffic matching the same patterns is traffic no
        crawl rule can touch, and saying so stops the proposal being read as
        a total."""
        result = self.replay(bulk(10, URL='/trap', UserAgent=CHROME),
                             proposed='User-agent: *\nDisallow: /trap\n')
        assert result['proposed']['requests'] == 0
        assert result['ceiling']['matched'] == 10
        assert result['ceiling']['request_share'] == pytest.approx(1.0)

    def test_the_ceiling_is_measured_against_the_star_group(self):
        """A non-crawler matches no named group, so the rules it would obey
        are the `*` ones."""
        result = self.replay(
            bulk(10, URL='/trap', UserAgent=CHROME),
            proposed='User-agent: Googlebot\nDisallow: /trap\n')
        assert result['ceiling']['matched'] == 0

    def test_impact_is_split_by_crawler(self):
        """A proposal can look strong overall while barely touching the
        crawler that matters most. On one real corpus the headline was fine
        and Googlebot was affected 9.2%."""
        result = self.replay(
            bulk(10, URL='/trap', UserAgent=GOOGLEBOT)
            + bulk(5, URL='/elsewhere', UserAgent=GOOGLEBOT)
            + bulk(8, URL='/trap', UserAgent=BINGBOT),
            proposed='User-agent: *\nDisallow: /trap\n')
        by_label = {c['label']: c for c in result['by_crawler']}
        assert by_label['Googlebot']['newly_blocked'] == 10
        assert by_label['Googlebot']['requests'] == 15
        assert by_label['Googlebot']['share_blocked'] == pytest.approx(10 / 15)
        assert by_label['bingbot']['share_blocked'] == pytest.approx(1.0)

    def test_which_rule_did_the_work_is_recorded(self):
        result = self.replay(
            bulk(10, URL='/trap', UserAgent=GOOGLEBOT)
            + bulk(3, URL='/other', UserAgent=GOOGLEBOT),
            proposed='User-agent: *\nDisallow: /trap\nDisallow: /other\n')
        by_pattern = {r['pattern']: r['requests'] for r in result['by_rule']}
        assert by_pattern == {'/trap': 10, '/other': 3}

    def test_the_group_gap_is_measured(self):
        """The difference between a merging and a non-merging crawler reading
        the same WaaS-rewritten file."""
        current = ('User-agent: *\nDisallow: /trap.html\n\n'
                   'User-agent: *\nDisallow: /real\n')
        result = self.replay(bulk(10, URL='/real', UserAgent=GOOGLEBOT),
                             current=current)
        assert result['group_gap'] == {'merged': 10, 'first_group_only': 0,
                                       'gap': 10}

    def test_the_review_variant_is_measured_separately(self):
        result = self.replay(
            bulk(10, URL='/trap', UserAgent=GOOGLEBOT)
            + bulk(20, URL='/calendar', UserAgent=GOOGLEBOT),
            proposed='User-agent: *\nDisallow: /trap\n',
            review='User-agent: *\nDisallow: /trap\nDisallow: /calendar\n')
        assert result['proposed']['requests'] == 10
        assert result['with_review']['requests'] == 30

    def test_with_review_is_absent_when_there_is_nothing_to_review(self):
        result = self.replay(bulk(5, UserAgent=GOOGLEBOT),
                             proposed='User-agent: *\n')
        assert result['with_review'] is None

    def test_extrapolation_uses_the_measured_scale_factor(self):
        r = Replay(HOST, '', 'User-agent: *\nDisallow: /trap\n')
        for row_ in bulk(10, URL='/trap', UserAgent=GOOGLEBOT):
            r.feed(row_)
        result = r.result(scale=24.87)
        assert result['net']['requests'] == 10
        assert result['net']['extrapolated_requests'] == 248


# --- findings --------------------------------------------------------------


def findings_by_code(report):
    return {f['code']: f for f in build_findings(report)}


class TestFindings:
    def test_nothing_to_propose_is_reported_as_a_result(self):
        """'No rules' is an answer, not a failure: it means crawl load here is
        spread across content real visitors use, so robots.txt is the wrong
        lever and caching is the right one."""
        codes = findings_by_code({'host': HOST, 'proposal': {'rules': []},
                                  'measurement': {}})
        assert 'robots_nothing_to_propose' in codes

    def test_a_measured_reduction_is_reported(self):
        codes = findings_by_code({
            'host': HOST,
            'proposal': {'rules': [{'pattern': '/x', 'tier': TIER_CONFIDENT}]},
            'measurement': {'crawler_requests': 1000,
                            'net': {'requests': 500, 'bytes': 1e9,
                                    'extrapolated_requests': 12_000},
                            'proposed': {'requests': 500}},
        })
        assert 'robots_measured_reduction' in codes
        assert '500' in codes['robots_measured_reduction']['title']

    def test_an_ineffective_current_file_is_called_out(self):
        """The path-anchoring defect, which is invisible until measured."""
        codes = findings_by_code({
            'host': HOST, 'current_text': 'User-agent: *\nDisallow: /tag\n',
            'proposal': {'rules': [{'pattern': '/x', 'tier': TIER_CONFIDENT}]},
            'measurement': {'crawler_requests': 100_000,
                            'current': {'requests': 60, 'request_share': 0.0006,
                                        'rules_hit': []},
                            'net': {}, 'proposed': {}},
        })
        assert 'robots_current_ineffective' in codes
        assert codes['robots_current_ineffective']['severity'] == 'warning'

    def test_the_review_tier_is_explained_with_both_numbers(self):
        codes = findings_by_code({
            'host': HOST,
            'proposal': {'crawler_share': 0.16, 'rules': [
                {'pattern': '/calendar', 'tier': TIER_REVIEW,
                 'crawler_requests': 38_296, 'human_requests': 38_551},
            ]},
            'measurement': {'crawler_requests': 160_515,
                            'proposed': {'requests': 40_010},
                            'with_review': {'requests': 67_858,
                                            'request_share': 0.4228},
                            'net': {}, 'current': {}},
        })
        assert 'robots_review_tier' in codes
        detail = codes['robots_review_tier']['detail']
        assert '67,858' in detail and '40,010' in detail

    def test_the_ceiling_is_reported_so_the_proposal_is_not_read_as_a_total(self):
        codes = findings_by_code({
            'host': HOST,
            'proposal': {'rules': [{'pattern': '/x', 'tier': TIER_CONFIDENT}]},
            'measurement': {'crawler_requests': 1000, 'net': {}, 'current': {},
                            'proposed': {},
                            'ceiling': {'human_requests': 800_000,
                                        'matched': 77_000,
                                        'request_share': 0.0968}},
        })
        assert 'robots_ceiling' in codes

    def test_findings_are_categorised_as_robots(self):
        """The report splits recommendations by who can act on them. WaaS
        cannot deploy an origin-served file, so these are advisory."""
        for f in build_findings({'host': HOST, 'proposal': {'rules': []},
                                 'measurement': {}}):
            assert f['category'] == 'robots'


# --- end to end ------------------------------------------------------------


class FakeStore:
    def __init__(self, rows):
        self._rows = rows

    def iter_rows(self, dates=None):
        return iter(self._rows)


class TestBuildReport:
    def corpus(self):
        return (varied(600, '/search-results')
                + varied(12, '/search-results', crawler=False)
                + bulk(6000, URL='/home', UserAgent=CHROME)
                + bulk(400, URL='/home', UserAgent=GOOGLEBOT))

    def test_the_shipped_file_is_the_file_that_was_measured(self):
        """Render, measure the rendered bytes, render again with the numbers.
        A late rule once invalidated an earlier measurement, and the published
        figure outlived the file that supported it."""
        report = build_report(FakeStore(self.corpus()), fetcher=None)
        reparsed = Robots(report['file'])
        measured = report['measurement']['proposed']['requests']

        blocked = 0
        for r in self.corpus():
            if r['UserAgent'] == GOOGLEBOT and not reparsed.allowed(
                    GOOGLEBOT, request_path(r))[0]:
                blocked += 1
        assert blocked == measured

    def test_no_host_with_enough_traffic_is_reported_rather_than_guessed(self):
        report = build_report(FakeStore(bulk(10, UserAgent=GOOGLEBOT)), fetcher=None)
        assert report['host'] is None
        assert report['findings'][0]['code'] == 'robots_no_host'

    def test_a_pasted_current_file_short_circuits_the_fetch(self):
        """Pasting the origin's file is strictly better evidence than
        fetching it through WaaS, which rewrites the response."""
        def explode(host, **kwargs):
            raise AssertionError('should not have fetched')

        report = build_report(FakeStore(self.corpus()), fetcher=explode,
                              current_text='User-agent: *\nDisallow: /admin\n')
        assert 'Disallow: /admin' in report['file']

    def test_a_failed_fetch_is_a_reportable_state_not_an_exception(self):
        report = build_report(
            FakeStore(self.corpus()),
            fetcher=lambda host, **kw: {'error': 'HTTP 403', 'text': None,
                                        'status': 403})
        assert report['fetch_error'] == 'HTTP 403'
        assert report['file']

    def test_the_scale_factor_reaches_the_header(self):
        report = build_report(FakeStore(self.corpus()), fetcher=None,
                              summary={'rows_sampled': 2_468_063}, scale=24.87)
        assert '2,468,063 rows' in report['file']
        assert report['measurement']['scale'] == 24.87

    def test_progress_is_reported_across_both_passes(self):
        seen = []
        build_report(FakeStore(self.corpus()), fetcher=None, yield_every=100,
                     on_progress=seen.append)
        assert seen and seen[-1] >= len(self.corpus())


# --- the page --------------------------------------------------------------


@pytest.fixture
def user(app, db):
    u = User(username='robots-tester', email='robots@example.com', role='user',
             is_active=True)
    u.set_password('x')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def account(app, db, user):
    acc = WaasAccount(user_id=user.id, account_name='Acme WaaS', is_active=True)
    acc.api_key = 'v4-key'
    db.session.add(acc)
    db.session.commit()
    return acc


@pytest.fixture
def logged_in_client(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True
    return client


def make_complete_pull(db, user, account, **kwargs):
    defaults = dict(
        user_id=user.id, account_id=account.id,
        app_id='app-1.example.com', app_name='app-1.example.com',
        mode=MODE_SAMPLE, window_days=7,
        range_start=1_767_225_600, range_end=1_767_398_400,
        session_id=str(uuid.uuid4()),
        status=LogPull.STATUS_COMPLETE, phase=LogPull.PHASE_DONE,
    )
    defaults.update(kwargs)
    pull = LogPull(**defaults)
    db.session.add(pull)
    db.session.commit()
    return pull


def analysis_for(tmp_path, pull_id, rows):
    from app.logpull.analysis import analyze_pull

    store = PullStore(str(tmp_path), pull_id)
    with store.open_day('2026-01-01') as writer:
        writer.write(rows)
    return analyze_pull(store, {'scale': 1.0, 'mode': MODE_SAMPLE},
                        check_host=lambda h: False)


SAMPLE_REPORT = {
    'host': HOST,
    'file': 'User-agent: *\nDisallow: /search-results\n',
    'proposal': {
        'host': HOST, 'crawler_share': 0.16, 'review_count': 1,
        'rules': [
            {'pattern': '/search-results', 'tier': TIER_CONFIDENT,
             'kind': 'prefix', 'crawler_requests': 9591, 'human_requests': 479,
             'crawler_share': 0.95, 'sample': '/search-results', 'reason': 'x'},
            {'pattern': '/calendar', 'tier': TIER_REVIEW, 'kind': 'prefix',
             'crawler_requests': 38_296, 'human_requests': 38_551,
             'crawler_share': 0.498, 'sample': '/calendar', 'reason': 'y'},
        ],
    },
    'measurement': {
        'crawler_requests': 160_515,
        'current': {'requests': 461, 'request_share': 0.0029,
                    'byte_share': 0.002, 'rules_hit': []},
        'proposed': {'requests': 40_010, 'request_share': 0.2493,
                     'byte_share': 0.217},
        'with_review': {'requests': 67_858, 'request_share': 0.4228,
                        'byte_share': 0.3631},
        'net': {'requests': 39_634, 'bytes': 4_990_000_000,
                'extrapolated_requests': 985_577},
        'by_crawler': [{'label': 'bingbot', 'requests': 17_078,
                        'newly_blocked': 10_127, 'share_blocked': 0.593}],
        'by_rule': [{'pattern': '/search-results', 'requests': 9591,
                     'bytes': 1000}],
        'ceiling': {'human_requests': 805_788, 'matched': 30_535,
                    'request_share': 0.0379},
        'group_gap': {'merged': 461, 'first_group_only': 85, 'gap': 376},
    },
    'findings': [],
    'served': None,
}


class TestResultsPage:
    def test_the_card_offers_to_generate_before_anything_exists(
            self, logged_in_client, db, user, account, tmp_path):
        pull = make_complete_pull(db, user, account)
        pull.result = {'analysis': analysis_for(tmp_path, pull.id, bulk(20))}
        db.session.commit()
        body = logged_in_client.get(f'/traffic/{pull.id}/results').get_data(as_text=True)
        assert 'robots.txt proposal' in body
        assert 'Generate and measure' in body

    def test_the_measured_numbers_are_rendered(
            self, logged_in_client, db, user, account, tmp_path):
        pull = make_complete_pull(db, user, account)
        pull.result = {'analysis': analysis_for(tmp_path, pull.id, bulk(20))}
        pull.report = {'robots': SAMPLE_REPORT}
        db.session.commit()
        body = logged_in_client.get(f'/traffic/{pull.id}/results').get_data(as_text=True)
        assert '24.9%' in body          # proposed share
        assert '/search-results' in body
        assert 'bingbot' in body

    def test_review_rules_are_shown_apart_from_active_ones(
            self, logged_in_client, db, user, account, tmp_path):
        """Presenting them in one list would imply the file blocks what it
        only offers to block."""
        pull = make_complete_pull(db, user, account)
        pull.result = {'analysis': analysis_for(tmp_path, pull.id, bulk(20))}
        pull.report = {'robots': SAMPLE_REPORT}
        db.session.commit()
        body = logged_in_client.get(f'/traffic/{pull.id}/results').get_data(as_text=True)
        assert 'Rules that ship active' in body
        assert 'commented out for review' in body

    def test_a_pull_without_a_proposal_still_renders(
            self, logged_in_client, db, user, account, tmp_path):
        """Pulls analysed before this feature existed are still in the
        database."""
        pull = make_complete_pull(db, user, account)
        pull.result = {'analysis': analysis_for(tmp_path, pull.id, bulk(20))}
        db.session.commit()
        assert logged_in_client.get(f'/traffic/{pull.id}/results').status_code == 200


class TestRoutes:
    def test_download_serves_the_file_as_an_attachment(
            self, logged_in_client, db, user, account):
        pull = make_complete_pull(db, user, account)
        pull.report = {'robots': SAMPLE_REPORT}
        db.session.commit()
        resp = logged_in_client.get(f'/traffic/{pull.id}/robots.txt')
        assert resp.status_code == 200
        assert 'Disallow: /search-results' in resp.get_data(as_text=True)
        assert 'attachment' in resp.headers['Content-Disposition']
        assert f'{HOST}.robots.txt' in resp.headers['Content-Disposition']

    def test_the_download_filename_cannot_carry_a_path(
            self, logged_in_client, db, user, account):
        """The host comes from a log row, which is client-supplied."""
        pull = make_complete_pull(db, user, account)
        pull.report = {'robots': {**SAMPLE_REPORT, 'host': '../../etc/passwd"x'}}
        db.session.commit()
        resp = logged_in_client.get(f'/traffic/{pull.id}/robots.txt')
        disposition = resp.headers['Content-Disposition']
        assert '/' not in disposition.split('filename=')[1]
        assert disposition.count('"') == 2

    def test_downloading_before_generating_redirects(
            self, logged_in_client, db, user, account):
        pull = make_complete_pull(db, user, account)
        resp = logged_in_client.get(f'/traffic/{pull.id}/robots.txt')
        assert resp.status_code == 302

    def test_generating_requires_a_post(self, logged_in_client, db, user, account):
        pull = make_complete_pull(db, user, account)
        assert logged_in_client.get(f'/traffic/{pull.id}/robots').status_code == 405

    def test_another_users_pull_is_not_reachable(self, logged_in_client, db,
                                                 user, account, app):
        """Account ownership is filtered on every query; a pull holds a
        customer's traffic."""
        other = User(username='someone-else', email='else@example.com',
                     role='user', is_active=True)
        other.set_password('x')
        db.session.add(other)
        db.session.commit()
        pull = make_complete_pull(db, other, account, user_id=other.id)
        pull.report = {'robots': SAMPLE_REPORT}
        db.session.commit()
        assert logged_in_client.get(f'/traffic/{pull.id}/robots.txt').status_code == 404

    def test_anonymous_users_are_redirected_to_login(self, client, db, user, account):
        pull = make_complete_pull(db, user, account)
        resp = client.get(f'/traffic/{pull.id}/robots.txt')
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']

    def test_an_expired_pull_refuses_rather_than_proposing_unmeasured(
            self, logged_in_client, db, user, account):
        """A proposal that was not measured against real traffic is exactly
        what this feature exists to avoid."""
        pull = make_complete_pull(db, user, account, raw_deleted=True)
        resp = logged_in_client.post(f'/traffic/{pull.id}/robots',
                                     data={'csrf_token': 'x'})
        assert resp.status_code == 302
        assert (pull.report or {}).get('robots') is None
