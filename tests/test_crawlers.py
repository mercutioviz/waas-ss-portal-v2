"""Tests for crawler classification and IP verification (app/logpull/crawlers.py).

Every failure mode pinned down here produces a confident wrong answer rather
than an exception, and most of them produce an *accusation*:

- Substring matching puts `27.34.64.9` inside `34.64.0.0/11` and silently
  clears an impostor. Containment is the whole point of the module.
- An unreachable range list that is treated as an empty list turns every
  verified crawler into an impostor at once. It must degrade to
  "unverifiable" instead.
- Shortest-token-first matching folds `Applebot-Extended` (an AI opt-out)
  into `Applebot` (a search crawler), so a robots.txt proposal aimed at the
  AI token looks like it would cost search traffic.
- A hard cap on a chronological stream freezes the URL table at whatever
  arrived in the first hour, and the report then describes that hour.
- Grouping unknown crawlers on the wrong product token produces one giant
  "bot" row that names nothing actionable.
"""
import json
import time
import uuid

import pytest

from app.logpull.analysis import analyze_pull
from app.logpull.crawlers import (
    AI_SHARE_FLOOR,
    CAT_AI,
    CAT_SEARCH,
    CAT_SEO,
    IMPOSTOR_SHARE_FLOOR,
    MIN_CATEGORY_REQUESTS,
    MIN_IMPOSTOR_REQUESTS,
    MIN_ROWS_FOR_FINDINGS,
    OTHER_UA_KEEP,
    VERIFY_NO_LIST,
    VERIFY_PUBLISHED,
    VERIFY_UNAVAILABLE,
    CrawlerAggregator,
    RangeVerifier,
    _path_prefix,
    _query_keys,
    _requests,
    _trim,
    classify_ua,
    crawler_product,
    load_ranges,
    looks_like_crawler,
    parse_prefixes,
    ranges_cache_dir,
)
from app.logpull.store import PullStore
from app.logpull.windows import MODE_SAMPLE
from app.models import LogPull, User, WaasAccount

BASE_MS = 1_767_225_600_000  # 2026-01-01T00:00:00Z in milliseconds

CHROME = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
          '(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36')
GOOGLEBOT = ('Mozilla/5.0 (compatible; Googlebot/2.1; '
             '+http://www.google.com/bot.html)')


def row(**kwargs):
    """One access-log row with the API's real field names and string types."""
    defaults = {
        'Host': 'www.example.com',
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


def feed_all(rows, verifier=None):
    agg = CrawlerAggregator(verifier=verifier)
    for r in rows:
        agg.feed(r)
    return agg


def crawler_named(result, label):
    for entry in result['crawlers']:
        if entry['label'] == label:
            return entry
    raise AssertionError(f'{label} not in {[c["label"] for c in result["crawlers"]]}')


def findings_by_code(result):
    return {f['code']: f for f in result['findings']}


def payload(*prefixes):
    """A published range list in the shape all four operators use."""
    return {'prefixes': [
        {'ipv6Prefix' if ':' in p else 'ipv4Prefix': p} for p in prefixes
    ]}


# --- published range lists -------------------------------------------------


class TestParsePrefixes:
    def test_reads_both_address_families(self):
        nets = parse_prefixes(payload('66.249.64.0/27', '2001:4860:4801::/48'))
        assert [str(n) for n in nets] == ['66.249.64.0/27', '2001:4860:4801::/48']

    def test_one_malformed_prefix_does_not_cost_the_rest_of_the_file(self):
        """A publisher typo must not silently empty the list — an empty list
        is indistinguishable from 'nothing verifies' downstream."""
        nets = parse_prefixes({'prefixes': [
            {'ipv4Prefix': '66.249.64.0/27'},
            {'ipv4Prefix': 'not-a-prefix'},
            {'ipv4Prefix': '66.249.65.0/27'},
        ]})
        assert len(nets) == 2

    def test_junk_payloads_yield_nothing_rather_than_raising(self):
        assert parse_prefixes(None) == []
        assert parse_prefixes([]) == []
        assert parse_prefixes({'prefixes': ['66.249.64.0/27']}) == []
        assert parse_prefixes({'prefixes': [{'cidr': '66.249.64.0/27'}]}) == []


class TestLoadRanges:
    sources = {'bing': 'https://example.invalid/bingbot.json'}

    def test_fetches_and_caches_to_disk(self, tmp_path):
        nets, meta = load_ranges(str(tmp_path), sources=self.sources,
                                 fetch=lambda url: payload('40.77.167.0/24'))
        assert len(nets['bing']) == 1
        assert meta['bing']['available'] is True
        assert meta['bing']['stale'] is False
        cached = json.loads((tmp_path / 'bing.json').read_text())
        assert cached['prefixes'][0]['ipv4Prefix'] == '40.77.167.0/24'

    def test_a_fresh_cache_is_used_without_fetching(self, tmp_path):
        (tmp_path / 'bing.json').write_text(json.dumps(payload('40.77.167.0/24')))

        def explode(url):
            raise AssertionError('should not have fetched')

        nets, meta = load_ranges(str(tmp_path), sources=self.sources,
                                 fetch=explode)
        assert len(nets['bing']) == 1
        assert meta['bing']['error'] is None

    def test_an_aged_cache_is_refetched(self, tmp_path):
        path = tmp_path / 'bing.json'
        path.write_text(json.dumps(payload('40.77.167.0/24')))
        nets, _ = load_ranges(str(tmp_path), sources=self.sources,
                              max_age_seconds=60, now=time.time() + 3600,
                              fetch=lambda url: payload('13.66.139.0/24',
                                                        '40.77.167.0/24'))
        assert len(nets['bing']) == 2

    def test_a_failed_fetch_falls_back_to_the_stale_cache(self, tmp_path):
        """Yesterday's ranges verify better than no ranges. The report says
        so rather than quietly presenting them as current."""
        (tmp_path / 'bing.json').write_text(json.dumps(payload('40.77.167.0/24')))

        def boom(url):
            raise OSError('connection refused')

        nets, meta = load_ranges(str(tmp_path), sources=self.sources,
                                 max_age_seconds=0, fetch=boom)
        assert len(nets['bing']) == 1
        assert meta['bing']['stale'] is True
        assert 'connection refused' in meta['bing']['error']

    def test_a_failed_fetch_with_no_cache_reports_unavailable(self, tmp_path):
        def boom(url):
            raise OSError('connection refused')

        nets, meta = load_ranges(str(tmp_path), sources=self.sources, fetch=boom)
        assert nets['bing'] == []
        assert meta['bing']['available'] is False
        assert meta['bing']['stale'] is False

    def test_an_empty_response_is_treated_as_a_failure(self, tmp_path):
        """A 200 carrying `{"prefixes": []}` would otherwise overwrite a good
        cache with a list that clears nobody and accuses everybody."""
        (tmp_path / 'bing.json').write_text(json.dumps(payload('40.77.167.0/24')))
        nets, meta = load_ranges(str(tmp_path), sources=self.sources,
                                 max_age_seconds=0,
                                 fetch=lambda url: {'prefixes': []})
        assert len(nets['bing']) == 1
        assert meta['bing']['stale'] is True
        cached = json.loads((tmp_path / 'bing.json').read_text())
        assert cached['prefixes']

    def test_a_corrupt_cache_file_is_refetched(self, tmp_path):
        (tmp_path / 'bing.json').write_text('{"prefixes": [trunca')
        nets, meta = load_ranges(str(tmp_path), sources=self.sources,
                                 fetch=lambda url: payload('40.77.167.0/24'))
        assert len(nets['bing']) == 1
        assert meta['bing']['available'] is True

    def test_cache_dir_hangs_off_the_instance_path(self):
        assert ranges_cache_dir('/srv/app/instance').startswith('/srv/app/instance')


# --- verification ----------------------------------------------------------


class TestRangeVerifier:
    def verifier(self, *prefixes):
        return RangeVerifier({'bing': parse_prefixes(payload(*prefixes))})

    def test_an_address_inside_a_published_prefix_verifies(self):
        v = self.verifier('40.77.167.0/24')
        assert v.verify(('bing',), '40.77.167.33') is True

    def test_an_address_outside_every_prefix_is_an_impostor(self):
        v = self.verifier('40.77.167.0/24')
        assert v.verify(('bing',), '203.0.113.9') is False

    def test_containment_not_substring(self):
        """`'34.64.' in '27.34.64.9'` is true. This is the bug the whole
        module exists to avoid, so it gets its own test."""
        v = self.verifier('34.64.0.0/11')
        assert v.verify(('bing',), '34.64.1.1') is True
        assert v.verify(('bing',), '27.34.64.9') is False
        assert v.verify(('bing',), '134.64.0.1') is False

    def test_a_crawler_with_no_published_list_is_unverifiable(self):
        """Not False. An empty source tuple means the operator publishes
        nothing, which is not evidence of anything."""
        assert self.verifier('40.77.167.0/24').verify((), '203.0.113.9') is None

    def test_an_unavailable_list_is_unverifiable_rather_than_damning(self):
        assert RangeVerifier({}).verify(('bing',), '203.0.113.9') is None
        assert RangeVerifier({'bing': []}).verify(('bing',), '203.0.113.9') is None

    def test_a_missing_client_ip_is_unverifiable(self):
        """A gap in the log record is not a false claim by the client."""
        v = self.verifier('40.77.167.0/24')
        assert v.verify(('bing',), '') is None
        assert v.verify(('bing',), None) is None

    def test_a_malformed_address_is_an_impostor(self):
        """Unlike a missing IP, a value that is present and not an address
        came off the wire that way."""
        assert self.verifier('40.77.167.0/24').verify(('bing',), 'nonsense') is False

    def test_families_do_not_match_across_each_other(self):
        v = RangeVerifier({'bing': parse_prefixes(payload('2001:4860::/32'))})
        assert v.verify(('bing',), '2001:4860::1') is True
        assert v.verify(('bing',), '40.77.167.33') is False

    def test_a_zone_suffixed_v6_address_still_parses(self):
        v = RangeVerifier({'bing': parse_prefixes(payload('2001:4860::/32'))})
        assert v.verify(('bing',), '2001:4860::1%eth0') is True

    def test_any_of_several_sources_is_enough(self):
        v = RangeVerifier({'a': parse_prefixes(payload('40.77.167.0/24')),
                           'b': parse_prefixes(payload('66.249.64.0/27'))})
        assert v.verify(('a', 'b'), '66.249.64.1') is True

    def test_one_available_source_makes_the_pair_verifiable(self):
        v = RangeVerifier({'a': parse_prefixes(payload('40.77.167.0/24')),
                           'b': []})
        assert v.available(('a', 'b')) is True
        assert v.available(('b',)) is False

    def test_repeat_lookups_are_cached_by_source_and_address(self):
        v = self.verifier('40.77.167.0/24')
        assert v.verify(('bing',), '40.77.167.33') is True
        assert v.verify(('bing',), '40.77.167.33') is True
        assert len(v._cache) == 1


# --- classification --------------------------------------------------------


class TestClassifyUa:
    def test_a_known_crawler_is_identified(self):
        token, label, category, sources = classify_ua(GOOGLEBOT)
        assert (token, label, category) == ('googlebot', 'Googlebot', CAT_SEARCH)
        assert 'google-common' in sources

    def test_longest_token_wins_so_extended_is_not_folded_into_applebot(self):
        """Applebot and Applebot-Extended are different crawlers with
        different robots.txt opt-outs. Collapsing them makes an AI opt-out
        look like it would cost search traffic."""
        assert classify_ua('Applebot-Extended/1.0')[1] == 'Applebot-Extended'
        assert classify_ua('Applebot-Extended/1.0')[2] == CAT_AI
        assert classify_ua('Applebot/0.1')[1] == 'Applebot'
        assert classify_ua('Applebot/0.1')[2] == CAT_SEARCH

    def test_matching_is_case_insensitive(self):
        """Real corpora carry `GoogleBot/2.1`. A case-sensitive test drops
        those rows into the unclassified bucket."""
        assert classify_ua('compatible; GoogleBot/2.1')[1] == 'Googlebot'
        assert classify_ua('BINGBOT/2.0')[1] == 'bingbot'

    def test_an_ordinary_browser_is_not_a_crawler(self):
        assert classify_ua(CHROME) is None

    def test_empty_input_is_not_a_crawler(self):
        assert classify_ua('') is None
        assert classify_ua(None) is None

    def test_crawlers_without_a_published_list_carry_no_sources(self):
        assert classify_ua('ClaudeBot/1.0')[3] == ()
        assert classify_ua('ClaudeBot/1.0')[2] == CAT_AI


class TestLooksLikeCrawler:
    def test_an_unregistered_self_declared_bot_is_caught(self):
        assert looks_like_crawler('SomeNewBot/1.0 (+http://example.com)')
        assert looks_like_crawler('Mozilla/5.0 (compatible; NewSpider/2)')
        assert looks_like_crawler('Scrapy/2.11 (+https://scrapy.org)')

    def test_an_ordinary_browser_is_not(self):
        assert not looks_like_crawler(CHROME)
        assert not looks_like_crawler('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0)')

    def test_cubot_phones_are_not_crawlers(self):
        """CUBOT is an Android handset brand and appears in genuine mobile
        UAs. A bare 'bot' substring test files those users as robots."""
        assert not looks_like_crawler(
            'Mozilla/5.0 (Linux; Android 13; CUBOT_NOTE_20) AppleWebKit/537.36')

    def test_empty_input_is_not_a_crawler(self):
        assert not looks_like_crawler('')
        assert not looks_like_crawler(None)


class TestCrawlerProduct:
    def test_the_first_candidate_wins_not_the_longest(self):
        """The product token leads the UA; the contact URL that follows it
        often holds a longer bot-ish string."""
        assert crawler_product(
            'tphotobot/0.1 (+https://crawler.estidraft.com/bot)') == 'tphotobot'

    def test_a_spaced_product_name_is_kept_whole(self):
        assert crawler_product('HubSpot Crawler 1.0') == 'HubSpot Crawler'

    def test_a_bare_marker_from_a_contact_url_is_skipped(self):
        """Otherwise every UA ending `+http://…/bot.html` groups under 'bot'
        and the table names nothing."""
        assert crawler_product(GOOGLEBOT) == 'Googlebot'

    def test_a_trailing_bot_does_not_absorb_a_version_number(self):
        """The leading-word allowance must start with a letter, or
        `Chrome/145.0.0.0 Safari/537.36 SomeBot` groups as '537.36 SomeBot'."""
        assert crawler_product(CHROME + ' SomeBot') == 'SomeBot'

    def test_a_ua_with_no_product_token_is_reported_as_itself(self):
        assert crawler_product('Scrapy/2.11') == 'Scrapy/2.11'

    def test_the_result_is_length_bounded(self):
        assert len(crawler_product('x' * 500 + 'bot')) <= 64

    def test_empty_input_does_not_raise(self):
        assert crawler_product('') == ''
        assert crawler_product(None) == ''


# --- URL-space helpers -----------------------------------------------------


class TestPathPrefix:
    def test_two_segments_are_kept(self):
        assert _path_prefix('/events/2026/january/kickoff') == '/events/2026'

    def test_short_paths_are_returned_whole(self):
        assert _path_prefix('/search_gcse') == '/search_gcse'
        assert _path_prefix('/') == '/'
        assert _path_prefix('') == '/'

    def test_query_and_fragment_are_stripped(self):
        assert _path_prefix('/events/list?tribe-bar-date=2026-05') == '/events/list'
        assert _path_prefix('/events/list#today') == '/events/list'


class TestQueryKeys:
    def test_keys_are_split_out_of_the_query_string(self):
        assert list(_query_keys('a=1&b=2&c=3')) == ['a', 'b', 'c']

    def test_a_valueless_key_still_counts(self):
        assert list(_query_keys('ical&eventDisplay=list')) == ['ical', 'eventDisplay']

    def test_empty_segments_are_dropped(self):
        assert list(_query_keys('&&a=1&')) == ['a']


class TestTrim:
    def test_the_heavy_hitters_survive_and_the_tail_goes(self):
        table = {f'k{i}': [i, 0, 0] for i in range(100)}
        caps = {}
        _trim(table, 10, _requests, caps, 'trimmed')
        assert len(table) == 10
        assert 'k99' in table and 'k0' not in table
        assert caps['trimmed'] is True

    def test_nothing_happens_below_twice_the_budget(self):
        table = {f'k{i}': [1, 0, 0] for i in range(19)}
        caps = {}
        _trim(table, 10, _requests, caps, 'trimmed')
        assert len(table) == 19
        assert caps == {}

    def test_trimming_is_lossy_rather_than_a_hard_cap(self):
        """A hard cap on a chronological stream freezes the table at
        whatever arrived first. A latecomer that outgrows the incumbents
        must still be able to take their place."""
        agg = CrawlerAggregator()
        for i in range(OTHER_UA_KEEP * 2 + 10):
            agg.feed(row(UserAgent=f'EarlyBot{i}/1.0'))
        for _ in range(50):
            agg.feed(row(UserAgent='LateBot/1.0'))
        top = agg.result()['other_crawlers']['top']
        assert top[0]['product'] == 'LateBot'
        assert agg.caps['other_crawlers_trimmed'] is True


# --- aggregation -----------------------------------------------------------


class TestAggregation:
    def test_humans_and_crawlers_are_counted_apart(self):
        result = feed_all([row()] * 7 + [row(UserAgent=GOOGLEBOT)] * 3).result()
        assert result['rows'] == 10
        assert result['crawler_requests'] == 3
        assert result['human_requests'] == 7
        assert result['crawler_request_share'] == pytest.approx(0.3)

    def test_bytes_are_split_the_same_way(self):
        result = feed_all([row(BytesSent='100')] * 2
                          + [row(UserAgent=GOOGLEBOT, BytesSent='900')]).result()
        assert result['crawler_bytes'] == 900
        assert result['human_bytes'] == 200
        assert result['crawler_byte_share'] == pytest.approx(900 / 1100)

    def test_unknown_self_declared_crawlers_land_in_the_other_bucket(self):
        result = feed_all([row(UserAgent='ShapBot/2.0')] * 4
                          + [row(UserAgent='tphotobot/0.1')]).result()
        assert result['other_crawlers']['requests'] == 5
        assert result['other_crawlers']['top'][0] == {
            'product': 'ShapBot', 'requests': 4, 'bytes': 4096}
        assert result['crawler_requests'] == 5
        assert result['crawlers'] == []

    def test_absent_fields_arrive_as_a_dash_and_are_treated_as_unset(self):
        """The API sends the literal 3-character string `"-"`, not null."""
        result = feed_all([row(UserAgent='"-"', QueryString='"-"',
                               BytesSent='"-"')] * 3).result()
        assert result['human_requests'] == 3
        assert result['crawler_bytes'] == 0

    def test_extrapolation_uses_the_sampling_scale(self):
        result = feed_all([row(UserAgent=GOOGLEBOT, BytesSent='1000')] * 4
                          ).result(scale=10.0)
        assert result['extrapolated_crawler_requests'] == 40
        assert result['extrapolated_crawler_bytes'] == 40000

    def test_per_crawler_rows_carry_category_and_query_share(self):
        rows = ([row(UserAgent=GOOGLEBOT, QueryString='q=1')] * 3
                + [row(UserAgent=GOOGLEBOT)] * 1)
        google = crawler_named(feed_all(rows).result(), 'Googlebot')
        assert google['requests'] == 4
        assert google['category_label'] == 'Search engine'
        assert google['query_share'] == pytest.approx(0.75)

    def test_status_classes_are_bucketed(self):
        rows = ([row(UserAgent=GOOGLEBOT, HTTPStatus=200)] * 2
                + [row(UserAgent=GOOGLEBOT, HTTPStatus=404)])
        google = crawler_named(feed_all(rows).result(), 'Googlebot')
        assert google['status_classes'] == {'2xx': 2, '4xx': 1}

    def test_categories_roll_up_across_crawlers(self):
        rows = ([row(UserAgent=GOOGLEBOT)] * 3
                + [row(UserAgent='GPTBot/1.0')] * 2
                + [row(UserAgent='ClaudeBot/1.0')] * 1)
        result = feed_all(rows).result()
        ai = [c for c in result['categories'] if c['category'] == CAT_AI][0]
        assert ai['requests'] == 3
        assert ai['crawlers'] == 2
        assert ai['share_of_crawl'] == pytest.approx(0.5)


class TestThreeStateVerification:
    def verifier(self):
        return RangeVerifier({
            'google-common': parse_prefixes(payload('66.249.64.0/27')),
        })

    def test_a_crawler_from_a_published_range_is_verified(self):
        result = feed_all([row(UserAgent=GOOGLEBOT, ClientIP='66.249.64.5')] * 3,
                          verifier=self.verifier()).result()
        google = crawler_named(result, 'Googlebot')
        assert (google['verified'], google['impostor']) == (3, 0)
        assert google['verification'] == VERIFY_PUBLISHED

    def test_a_crawler_from_outside_it_is_an_impostor(self):
        result = feed_all([row(UserAgent=GOOGLEBOT, ClientIP='203.0.113.9')] * 2,
                          verifier=self.verifier()).result()
        google = crawler_named(result, 'Googlebot')
        assert (google['verified'], google['impostor']) == (0, 2)
        assert google['impostor_share'] == pytest.approx(1.0)
        assert google['top_impostor_ips'][0] == {'ip': '203.0.113.9', 'requests': 2}

    def test_a_crawler_with_no_published_list_is_never_an_impostor(self):
        result = feed_all([row(UserAgent='ClaudeBot/1.0')] * 5,
                          verifier=self.verifier()).result()
        claude = crawler_named(result, 'ClaudeBot')
        assert (claude['verified'], claude['impostor']) == (0, 0)
        assert claude['unverifiable'] == 5
        assert claude['verification'] == VERIFY_NO_LIST

    def test_an_unreachable_list_downgrades_to_unverifiable(self):
        """The single most damaging failure available: treating an empty
        fetch as an empty allow-list accuses every real crawler at once."""
        result = feed_all([row(UserAgent=GOOGLEBOT, ClientIP='66.249.64.5')] * 4,
                          verifier=RangeVerifier({'google-common': []})).result()
        google = crawler_named(result, 'Googlebot')
        assert google['impostor'] == 0
        assert google['unverifiable'] == 4
        assert google['verification'] == VERIFY_UNAVAILABLE

    def test_with_no_verifier_at_all_nothing_is_accused(self):
        result = feed_all([row(UserAgent=GOOGLEBOT, ClientIP='203.0.113.9')] * 4
                          ).result()
        assert crawler_named(result, 'Googlebot')['impostor'] == 0

    def test_distinct_client_ips_are_counted(self):
        rows = [row(UserAgent=GOOGLEBOT, ClientIP=f'66.249.64.{i}')
                for i in range(5)]
        assert crawler_named(feed_all(rows).result(), 'Googlebot')['distinct_ips'] == 5


class TestUrlSpace:
    def test_crawler_and_human_hits_are_cross_tabulated_per_prefix(self):
        rows = ([row(URL='/search_gcse', UserAgent=GOOGLEBOT)] * 9
                + [row(URL='/search_gcse')] * 1
                + [row(URL='/articles/launch/photos')] * 20)
        space = {r['prefix']: r for r in feed_all(rows).result()['url_space']}
        assert space['/search_gcse']['crawler_requests'] == 9
        assert space['/search_gcse']['human_requests'] == 1
        assert space['/search_gcse']['crawler_share'] == pytest.approx(0.9)
        assert space['/articles/launch']['crawler_share'] == 0

    def test_query_keys_are_cross_tabulated_too(self):
        rows = ([row(QueryString='tribe-bar-date=2026-05&eventDisplay=list',
                     UserAgent=GOOGLEBOT)] * 8
                + [row(QueryString='tribe-bar-date=2026-05')] * 2)
        keys = {k['key']: k for k in feed_all(rows).result()['query_keys']}
        assert keys['tribe-bar-date']['crawler_requests'] == 8
        assert keys['tribe-bar-date']['human_requests'] == 2
        assert keys['eventDisplay']['crawler_share'] == pytest.approx(1.0)

    def test_rows_with_no_url_are_skipped_rather_than_bucketed_as_root(self):
        result = feed_all([row(URL='"-"', UserAgent=GOOGLEBOT)] * 3).result()
        assert result['url_space'] == []
        assert result['crawler_requests'] == 3

    def test_unknown_crawlers_count_as_crawlers_in_the_cross_tab(self):
        """The "other" bucket is still crawl load — leaving it on the human
        side of the cross-tab understates every prefix it touches."""
        rows = [row(URL='/feeds/all', UserAgent='SomeNewBot/1.0')] * 4
        space = feed_all(rows).result()['url_space'][0]
        assert space['crawler_requests'] == 4
        assert space['human_requests'] == 0


# --- findings --------------------------------------------------------------


def bulk(n, **kwargs):
    return [row(**kwargs) for _ in range(n)]


class TestFindings:
    def test_nothing_is_claimed_from_too_few_rows(self):
        result = feed_all(bulk(MIN_ROWS_FOR_FINDINGS - 1, UserAgent=GOOGLEBOT)).result()
        assert result['findings'] == []

    def test_crawler_share_is_reported_once_it_passes_the_floor(self):
        rows = bulk(400, UserAgent=GOOGLEBOT) + bulk(1200)
        codes = findings_by_code(feed_all(rows).result())
        assert 'crawler_traffic_share' in codes
        assert codes['crawler_traffic_share']['severity'] == 'info'

    def test_a_heavy_crawler_share_is_a_warning(self):
        rows = bulk(1000, UserAgent=GOOGLEBOT) + bulk(1000)
        codes = findings_by_code(feed_all(rows).result())
        assert codes['crawler_traffic_share']['severity'] == 'warning'

    def test_a_modest_crawler_share_is_not_reported_at_all(self):
        rows = bulk(100, UserAgent=GOOGLEBOT) + bulk(1900)
        assert 'crawler_traffic_share' not in findings_by_code(feed_all(rows).result())

    def test_impostors_are_reported_against_waas_config_not_robots(self):
        """robots.txt is honoured voluntarily; a client lying about its
        identity has already opted out, so the remedy is a WaaS rule."""
        verifier = RangeVerifier({'google-common': parse_prefixes(
            payload('66.249.64.0/27'))})
        rows = (bulk(900, UserAgent=GOOGLEBOT, ClientIP='66.249.64.5')
                + bulk(300, UserAgent=GOOGLEBOT, ClientIP='203.0.113.9')
                + bulk(900))
        codes = findings_by_code(feed_all(rows, verifier=verifier).result())
        assert codes['crawler_impostors']['category'] == 'waas_config'
        assert codes['crawler_impostors']['severity'] == 'warning'
        assert codes['crawler_impostors']['evidence']['crawlers'][0]['impostor'] == 300

    def test_a_handful_of_impostors_is_not_worth_a_finding(self):
        """bingbot runs ~3 impostors in 19,000 requests on a real corpus.
        Reporting that as an incident trains the reader to ignore the card."""
        verifier = RangeVerifier({'google-common': parse_prefixes(
            payload('66.249.64.0/27'))})
        rows = (bulk(2000, UserAgent=GOOGLEBOT, ClientIP='66.249.64.5')
                + bulk(MIN_IMPOSTOR_REQUESTS - 1, UserAgent=GOOGLEBOT,
                       ClientIP='203.0.113.9'))
        assert 'crawler_impostors' not in findings_by_code(
            feed_all(rows, verifier=verifier).result())

    def test_impostors_below_the_share_floor_are_not_reported(self):
        verifier = RangeVerifier({'google-common': parse_prefixes(
            payload('66.249.64.0/27'))})
        clean = int(MIN_IMPOSTOR_REQUESTS / IMPOSTOR_SHARE_FLOOR) + 500
        rows = (bulk(clean, UserAgent=GOOGLEBOT, ClientIP='66.249.64.5')
                + bulk(MIN_IMPOSTOR_REQUESTS + 1, UserAgent=GOOGLEBOT,
                       ClientIP='203.0.113.9'))
        assert 'crawler_impostors' not in findings_by_code(
            feed_all(rows, verifier=verifier).result())

    def test_unverifiable_crawlers_never_produce_an_impostor_finding(self):
        rows = bulk(2000, UserAgent='ClaudeBot/1.0', ClientIP='203.0.113.9')
        assert 'crawler_impostors' not in findings_by_code(feed_all(rows).result())

    def test_ai_crawler_load_is_informational_and_points_at_robots(self):
        rows = (bulk(MIN_CATEGORY_REQUESTS + 100, UserAgent='GPTBot/1.0')
                + bulk(1500, UserAgent=GOOGLEBOT))
        codes = findings_by_code(feed_all(rows).result())
        assert codes['ai_crawler_load']['severity'] == 'info'
        assert codes['ai_crawler_load']['category'] == 'robots'

    def test_ai_load_below_the_share_floor_is_not_reported(self):
        ai = MIN_CATEGORY_REQUESTS + 100
        search = int(ai / AI_SHARE_FLOOR)
        rows = bulk(ai, UserAgent='GPTBot/1.0') + bulk(search, UserAgent=GOOGLEBOT)
        assert 'ai_crawler_load' not in findings_by_code(feed_all(rows).result())

    def test_seo_crawler_load_is_a_warning(self):
        """Unlike AI and search crawlers, backlink tools index the site for
        someone else's product."""
        rows = bulk(MIN_CATEGORY_REQUESTS + 100, UserAgent='AhrefsBot/7.0') + bulk(1500)
        codes = findings_by_code(feed_all(rows).result())
        assert codes['seo_crawler_load']['severity'] == 'warning'
        assert crawler_named(feed_all(rows).result(), 'AhrefsBot')['category'] == CAT_SEO

    def test_query_traps_name_the_parameters_by_enrichment_not_majority(self):
        """On a corpus that is mostly human, a parameter crawlers take 40% of
        is a trap even though it never crosses half."""
        rows = (bulk(900, UserAgent=GOOGLEBOT, QueryString='tribe-bar-date=2026-05')
                + bulk(1400, QueryString='tribe-bar-date=2026-05')
                + bulk(4000))
        codes = findings_by_code(feed_all(rows).result())
        assert '?tribe-bar-date=' in codes['crawler_query_traps']['detail']
        assert codes['crawler_query_traps']['category'] == 'robots'

    def test_a_parameter_split_like_the_site_overall_is_not_named(self):
        """Crawlers being 30% of a parameter on a site where they are 30% of
        everything says nothing about that parameter."""
        rows = (bulk(900, UserAgent=GOOGLEBOT, QueryString='ver=4.1')
                + bulk(900, UserAgent=GOOGLEBOT)
                + bulk(2100, QueryString='ver=4.1')
                + bulk(2100))
        codes = findings_by_code(feed_all(rows).result())
        assert 'crawler_query_traps' in codes
        assert '?ver=' not in codes['crawler_query_traps']['detail']

    def test_a_crawler_dominated_prefix_is_reported(self):
        rows = (bulk(1200, URL='/search_gcse', UserAgent=GOOGLEBOT)
                + bulk(60, URL='/search_gcse')
                + bulk(8000, URL='/articles/launch'))
        codes = findings_by_code(feed_all(rows).result())
        assert '/search_gcse' in codes['crawler_url_space']['detail']

    def test_a_prefix_that_is_a_rounding_error_overall_still_counts(self):
        """An absolute floor, not a share of the corpus: 1,200 unwanted
        requests are 1,200 unwanted requests on a site of any size."""
        rows = (bulk(1200, URL='/search_gcse', UserAgent=GOOGLEBOT)
                + bulk(60, URL='/search_gcse')
                + bulk(100_000, URL='/articles/launch'))
        agg = CrawlerAggregator()
        for r in rows:
            agg.feed(r)
        assert 'crawler_url_space' in findings_by_code(agg.result())

    def test_a_small_crawler_dominated_prefix_is_below_the_floor(self):
        rows = (bulk(300, URL='/feeds/all', UserAgent=GOOGLEBOT)
                + bulk(3000, URL='/articles/launch'))
        assert 'crawler_url_space' not in findings_by_code(feed_all(rows).result())

    def test_an_unavailable_range_list_is_surfaced_to_the_reader(self):
        """Otherwise the verification column silently means less than it
        looks like it means."""
        agg = feed_all(bulk(2000, UserAgent=GOOGLEBOT))
        meta = {'bing': {'available': False, 'stale': False,
                         'error': 'connection refused', 'prefixes': 0,
                         'url': 'https://example.invalid/bingbot.json'}}
        codes = findings_by_code(agg.result(ranges_meta=meta))
        assert 'crawler_ranges_unavailable' in codes

    def test_fresh_range_lists_produce_no_finding(self):
        agg = feed_all(bulk(2000, UserAgent=GOOGLEBOT))
        meta = {'bing': {'available': True, 'stale': False, 'error': None,
                         'prefixes': 28, 'url': 'x'}}
        assert 'crawler_ranges_unavailable' not in findings_by_code(
            agg.result(ranges_meta=meta))

    def test_warnings_sort_ahead_of_information(self):
        rows = (bulk(1000, UserAgent=GOOGLEBOT)
                + bulk(MIN_CATEGORY_REQUESTS + 100, UserAgent='GPTBot/1.0')
                + bulk(1000))
        severities = [f['severity'] for f in feed_all(rows).result()['findings']]
        assert severities == sorted(severities, key=lambda s: s != 'warning')


# --- wiring into the pull analysis ----------------------------------------


class TestAnalyzePullIntegration:
    def no_dns(self, host):
        return bool(host) and '.' in host

    def write(self, tmp_path, pull_id, rows):
        store = PullStore(str(tmp_path), pull_id)
        with store.open_day('2026-01-01') as writer:
            writer.write(rows)
        return store

    def test_crawler_analysis_rides_along_on_the_single_pass(self, tmp_path):
        store = self.write(tmp_path, 1,
                           bulk(6, UserAgent=GOOGLEBOT) + bulk(4))
        result = analyze_pull(store, {'scale': 1.0, 'mode': MODE_SAMPLE},
                              check_host=self.no_dns)
        assert result['sample']['rows'] == 10
        assert result['crawlers']['crawler_requests'] == 6

    def test_the_cache_sections_are_unchanged_by_the_crawler_pass(self, tmp_path):
        store = self.write(tmp_path, 2, bulk(5, URL='/static/app.js'))
        result = analyze_pull(store, {'scale': 1.0}, check_host=self.no_dns)
        assert result['repeat_fetch']['excess_requests'] == 4
        assert 'revalidation' in result

    def test_crawler_findings_merge_into_one_recommendation_list(self, tmp_path):
        """The reader cares about what to change, not about which pass
        noticed it."""
        store = self.write(tmp_path, 3,
                           bulk(1000, UserAgent=GOOGLEBOT) + bulk(1000))
        result = analyze_pull(store, {'scale': 1.0}, check_host=self.no_dns)
        codes = {f['code'] for f in result['findings']}
        assert 'crawler_traffic_share' in codes
        severities = [f['severity'] for f in result['findings']]
        assert severities == sorted(severities, key=lambda s: s != 'warning')

    def test_the_sampling_scale_reaches_the_crawler_section(self, tmp_path):
        store = self.write(tmp_path, 4, bulk(4, UserAgent=GOOGLEBOT,
                                             BytesSent='1000'))
        result = analyze_pull(store, {'scale': 10.0}, check_host=self.no_dns)
        assert result['crawlers']['extrapolated_crawler_requests'] == 40

    def test_a_missing_ranges_dir_degrades_to_unverifiable(self, tmp_path):
        """No network in the analysis worker must not mean accusations."""
        store = self.write(tmp_path, 5,
                           bulk(20, UserAgent=GOOGLEBOT, ClientIP='203.0.113.9'))
        result = analyze_pull(store, {'scale': 1.0}, check_host=self.no_dns)
        google = crawler_named(result['crawlers'], 'Googlebot')
        assert google['impostor'] == 0
        assert google['unverifiable'] == 20

    def test_a_supplied_verifier_is_used(self, tmp_path):
        store = self.write(tmp_path, 6,
                           bulk(20, UserAgent=GOOGLEBOT, ClientIP='203.0.113.9'))
        verifier = RangeVerifier({'google-common': parse_prefixes(
            payload('66.249.64.0/27'))})
        result = analyze_pull(store, {'scale': 1.0}, check_host=self.no_dns,
                              crawler_verifier=verifier)
        assert crawler_named(result['crawlers'], 'Googlebot')['impostor'] == 20


# --- the results page ------------------------------------------------------


@pytest.fixture
def user(app, db):
    u = User(username='crawl-tester', email='crawl@example.com', role='user',
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


class TestResultsPage:
    def analysis_for(self, tmp_path, pull_id, rows, verifier=None):
        """A real `analyze_pull` result, so the page is exercised against the
        shape it actually gets rather than a hand-made stand-in."""
        store = PullStore(str(tmp_path), pull_id)
        with store.open_day('2026-01-01') as writer:
            writer.write(rows)
        return analyze_pull(store, {'scale': 1.0, 'mode': MODE_SAMPLE},
                            check_host=lambda h: False,
                            crawler_verifier=verifier)

    def test_the_crawler_cards_render(self, logged_in_client, db, user, account,
                                      tmp_path):
        pull = make_complete_pull(db, user, account)
        pull.result = {'analysis': self.analysis_for(
            tmp_path, pull.id,
            bulk(30, UserAgent=GOOGLEBOT, URL='/search_gcse')
            + bulk(10, UserAgent='ClaudeBot/1.0')
            + bulk(60))}
        db.session.commit()
        body = logged_in_client.get(f'/traffic/{pull.id}/results').get_data(as_text=True)
        assert 'Crawler traffic' in body
        assert 'Googlebot' in body
        assert 'ClaudeBot' in body
        assert '/search_gcse' in body

    def test_verification_state_is_shown_per_crawler(self, logged_in_client, db,
                                                     user, account, tmp_path):
        verifier = RangeVerifier({'google-common': parse_prefixes(
            payload('66.249.64.0/27'))})
        pull = make_complete_pull(db, user, account)
        pull.result = {'analysis': self.analysis_for(
            tmp_path, pull.id,
            bulk(20, UserAgent=GOOGLEBOT, ClientIP='66.249.64.5')
            + bulk(5, UserAgent=GOOGLEBOT, ClientIP='203.0.113.9')
            + bulk(10, UserAgent='ClaudeBot/1.0'), verifier=verifier)}
        db.session.commit()
        body = logged_in_client.get(f'/traffic/{pull.id}/results').get_data(as_text=True)
        assert 'impostor' in body          # Googlebot, 5 of 25
        assert 'No published list' in body  # ClaudeBot

    def test_an_unloadable_list_reads_differently_from_no_list_at_all(
            self, logged_in_client, db, user, account, tmp_path):
        """"Not checked" and "No published list" are different claims about
        the evidence. Rendering both as one phrase throws away the only
        distinction the verification column carries."""
        pull = make_complete_pull(db, user, account)
        pull.result = {'analysis': self.analysis_for(
            tmp_path, pull.id, bulk(20, UserAgent=GOOGLEBOT),
            verifier=RangeVerifier({'google-common': []}))}
        db.session.commit()
        body = logged_in_client.get(f'/traffic/{pull.id}/results').get_data(as_text=True)
        assert 'Not checked' in body
        assert 'No published list' not in body

    def test_the_cards_are_absent_rather_than_broken_without_crawler_data(
            self, logged_in_client, db, user, account, tmp_path):
        """Pulls analysed before this feature existed are still in the
        database and must keep rendering."""
        pull = make_complete_pull(db, user, account)
        analysis = self.analysis_for(tmp_path, pull.id, bulk(10))
        analysis.pop('crawlers')
        pull.result = {'analysis': analysis}
        db.session.commit()
        resp = logged_in_client.get(f'/traffic/{pull.id}/results')
        assert resp.status_code == 200
        assert 'Crawler traffic' not in resp.get_data(as_text=True)
