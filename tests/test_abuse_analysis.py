"""Tests for the per-IP abuse profile over a completed pull
(app/logpull/abuse.py).

Every failure mode pinned here produces a *confident wrong answer* rather than
an error, which is why they need tests rather than a traceback:

- The crawler gate must be registry membership, not `verify() is True`. Most
  operators publish no prefix list, so `verify()` returns `None` for them
  forever — gating on True drops all of Meta, Yandex, Baidu and ClaudeBot into
  the threat list. On the corpus this module was built from, Meta's crawler
  alone filled 17 of the top 18 slots.
- A crawler's identifying token usually sits at the *end* of its User-Agent.
  Matching against a truncated prefix silently reclassifies crawlers as
  suspicious; in testing it under-counted them threefold.
- `verify()` returning `None` means "no list to check against", which is the
  opposite of "outside the published list". Accusing on `None` libels every
  address of every operator that publishes nothing.
- `EpochTime` arrives as a JSON string of milliseconds. An int guard drops
  every row and every timing metric reports a confident zero.
- Absent fields arrive as the literal 3-character string `"-"`, which is
  truthy — a bare check counts every empty field as a present `Referer` or
  `Cookie` and inverts both signals rather than merely weakening them.
- Row order within a day is not strictly monotonic. Unsorted gaps go negative
  and the regularity statistic becomes meaningless.
"""
import uuid

import pytest

from app.logpull.abuse import (
    BAND_HIGH,
    MAX_URLS_PER_IP,
    MIN_REQUESTS,
    MIN_ROWS_FOR_FINDINGS,
    AbuseAggregator,
    _cv,
    _entropy,
    _epoch_ms,
    _subnet,
    analyze_pull,
    build_findings,
    count_candidates,
)
from app.logpull.crawlers import RangeVerifier
from app.logpull.store import PullStore
from app.logpull.windows import MODE_SAMPLE
from app.models import LogPull, User, WaasAccount

BASE_MS = 1_767_225_600_000  # 2026-01-01T00:00:00Z

GOOGLEBOT_UA = ('Mozilla/5.0 (compatible; Googlebot/2.1; '
                '+http://www.google.com/bot.html)')
META_UA = ('meta-externalagent/1.1 (+https://developers.facebook.com'
           '/docs/sharing/webmasters/crawler)')
BROWSER_UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36')


def row(**kwargs):
    """One access-log row with the API's real field names and string types."""
    defaults = {
        'Host': 'www.example.com',
        'URL': '/index.html',
        'QueryString': '"-"',
        'ClientIP': '198.51.100.7',
        'ClientIP_country_code': 'US',
        'HTTPStatus': 200,
        'BytesSent': '1024',
        'Method': 'GET',
        'EpochTime': str(BASE_MS),
        'UserAgent': BROWSER_UA,
        'Referer': 'https://www.example.com/',
        'Cookie': 'session=abc',
        'WFMatched': 'VALID',
    }
    defaults.update(kwargs)
    return defaults


def bulk(n, *, start_ms=BASE_MS, step_ms=1000, **kwargs):
    """`n` rows marching forward in time."""
    return [row(EpochTime=str(start_ms + i * step_ms), **kwargs)
            for i in range(n)]


def feed_all(rows, candidates=None, verifier=None):
    if candidates is None:
        candidates = {r['ClientIP'] for r in rows}
    agg = AbuseAggregator(candidates, verifier=verifier)
    for r in rows:
        agg.feed(r)
    return agg


def profile_for(result, ip):
    for bucket in ('suspects', 'crawlers'):
        for entry in result.get(bucket) or []:
            if entry['ip'] == ip:
                return entry
    return None


# --- field handling --------------------------------------------------------


class TestFieldHandling:
    def test_epoch_time_is_a_string_of_milliseconds(self):
        assert _epoch_ms(str(BASE_MS)) == BASE_MS
        assert _epoch_ms(BASE_MS) == BASE_MS
        assert _epoch_ms(f'{BASE_MS}.0') == BASE_MS

    def test_epoch_time_rejects_the_dash_sentinel(self):
        assert _epoch_ms('"-"') is None
        assert _epoch_ms(None) is None

    def test_timestamps_survive_as_floats_not_ints(self):
        """Sub-second spacing is the whole signal for a fast scanner."""
        agg = feed_all(bulk(40, step_ms=50))
        profile = agg.profiles['198.51.100.7']
        gaps = {round(b - a, 3)
                for a, b in zip(sorted(profile.timestamps),
                                sorted(profile.timestamps)[1:])}
        assert gaps == {0.05}

    def test_dash_sentinel_is_not_a_present_referer_or_cookie(self):
        """The sentinel is the 3-character string `"-"`, which is truthy."""
        agg = feed_all(bulk(40, Referer='"-"', Cookie='"-"'))
        profile = agg.profiles['198.51.100.7']
        assert profile.referers == 0
        assert profile.cookies == 0

    def test_real_headers_are_counted(self):
        agg = feed_all(bulk(40))
        profile = agg.profiles['198.51.100.7']
        assert profile.referers == 40
        assert profile.cookies == 40

    def test_assets_are_split_from_pages_by_extension(self):
        rows = bulk(10, URL='/app.js') + bulk(10, URL='/about')
        profile = feed_all(rows).profiles['198.51.100.7']
        assert profile.assets == 10
        assert profile.pages == 10


class TestIntervalStatistics:
    def test_out_of_order_rows_still_yield_a_sane_cv(self):
        """Within a day the drain's order is not strictly monotonic."""
        ordered = [0.0, 1.0, 2.0, 3.0, 4.0]
        shuffled = [3.0, 0.0, 4.0, 1.0, 2.0]
        assert _cv(ordered) == _cv(shuffled)
        assert _cv(shuffled) == pytest.approx(0.0)

    def test_cv_needs_enough_points_to_mean_anything(self):
        assert _cv([1.0]) is None
        assert _cv([]) is None

    def test_irregular_spacing_scores_above_regular(self):
        regular = _cv([0.0, 1.0, 2.0, 3.0, 4.0, 5.0])
        ragged = _cv([0.0, 0.1, 9.0, 9.2, 30.0, 60.0])
        assert ragged > regular

    def test_entropy_is_zero_for_a_single_url(self):
        from collections import Counter
        assert _entropy(Counter({'/a': 100})) == pytest.approx(0.0)
        assert _entropy(Counter({'/a': 50, '/b': 50})) == pytest.approx(1.0)

    def test_subnet_rolls_v4_to_24(self):
        assert _subnet('198.51.100.7') == '198.51.100.0/24'
        assert _subnet('not-an-ip') is None


# --- the candidate pass ----------------------------------------------------


class TestCandidatePass:
    def test_below_threshold_addresses_are_not_candidates(self, tmp_path):
        store = PullStore(str(tmp_path), 1)
        with store.open_day('2026-01-01') as writer:
            writer.write(bulk(MIN_REQUESTS + 5, ClientIP='203.0.113.1'))
            writer.write(bulk(3, ClientIP='203.0.113.2'))
        candidates, rows, distinct = count_candidates(store)
        assert candidates == {'203.0.113.1'}
        assert rows == MIN_REQUESTS + 8
        assert distinct == 2

    def test_skipped_rows_are_still_counted_in_the_total(self):
        rows = bulk(40, ClientIP='203.0.113.1') + bulk(5, ClientIP='203.0.113.2')
        agg = feed_all(rows, candidates={'203.0.113.1'})
        assert agg.rows == 45
        assert agg.skipped_rows == 5
        assert set(agg.profiles) == {'203.0.113.1'}

    def test_rows_without_a_client_ip_are_tracked_separately(self):
        agg = feed_all(bulk(5, ClientIP='"-"'), candidates=set())
        assert agg.rows == 5
        assert agg.undated_rows == 5
        assert agg.profiles == {}


# --- crawler handling (the load-bearing part) ------------------------------


class TestCrawlerLane:
    def test_meta_lands_in_the_crawler_lane_despite_never_verifying(self):
        """The single most important test in this file.

        Meta publishes no prefix list, so `verify()` returns `None` for it
        permanently. A `verify() is True` gate would route Meta's crawler into
        the threat list — on the reference corpus that was 17 of the top 18
        scored addresses.
        """
        rows = bulk(60, ClientIP='57.141.4.65', UserAgent=META_UA,
                    URL='/page', Referer='"-"', Cookie='"-"')
        result = feed_all(rows).result()

        assert [c['ip'] for c in result['crawlers']] == ['57.141.4.65']
        assert result['suspects'] == []
        entry = result['crawlers'][0]
        assert entry['crawler'] == 'meta-externalagent'
        assert entry['verified'] is False
        assert entry['verification'] == 'no_published_list'
        assert entry['impostor'] is False

    def test_a_crawler_token_at_the_end_of_the_ua_still_classifies(self):
        """Googlebot's token trails a long prefix; a truncated match loses it."""
        assert GOOGLEBOT_UA.index('Googlebot') > 20
        rows = bulk(60, ClientIP='66.249.67.1', UserAgent=GOOGLEBOT_UA)
        result = feed_all(rows).result()
        assert [c['crawler'] for c in result['crawlers']] == ['Googlebot']
        assert result['suspects'] == []

    def test_an_unverifiable_crawler_is_never_accused_of_impersonation(self):
        """`None` means no list to check, not a failed check."""
        rows = bulk(60, ClientIP='203.0.113.9', UserAgent=META_UA)
        result = feed_all(rows, verifier=RangeVerifier()).result()
        assert result['impostors'] == []
        assert result['crawlers'][0]['impostor'] is False

    def test_an_address_outside_a_published_range_is_an_impostor(self):
        import ipaddress
        verifier = RangeVerifier({
            'google-common': [ipaddress.ip_network('66.249.64.0/19')],
        })
        rows = bulk(60, ClientIP='203.0.113.9', UserAgent=GOOGLEBOT_UA)
        result = feed_all(rows, verifier=verifier).result()

        assert [i['ip'] for i in result['impostors']] == ['203.0.113.9']
        entry = result['suspects'][0]
        assert entry['impostor'] is True
        assert 'impostor' in entry['signals']
        assert result['crawlers'] == []

    def test_an_address_inside_a_published_range_verifies(self):
        import ipaddress
        verifier = RangeVerifier({
            'google-common': [ipaddress.ip_network('66.249.64.0/19')],
        })
        rows = bulk(60, ClientIP='66.249.67.1', UserAgent=GOOGLEBOT_UA)
        result = feed_all(rows, verifier=verifier).result()
        entry = result['crawlers'][0]
        assert entry['verified'] is True
        assert entry['verification'] == 'published_list'
        assert result['impostors'] == []

    def test_an_impostor_outscores_the_same_traffic_from_a_real_crawler(self):
        import ipaddress
        verifier = RangeVerifier({
            'google-common': [ipaddress.ip_network('66.249.64.0/19')],
        })
        fake = feed_all(bulk(60, ClientIP='203.0.113.9',
                             UserAgent=GOOGLEBOT_UA),
                        verifier=verifier).result()
        assert fake['suspects'][0]['score'] > 0


# --- scoring ---------------------------------------------------------------


class TestScoring:
    def test_a_scanner_outscores_a_browser_on_identical_volume(self):
        browser = bulk(200, ClientIP='203.0.113.1', step_ms=7000)
        browser += bulk(200, ClientIP='203.0.113.1', URL='/style.css',
                        step_ms=7000)
        scanner = bulk(400, ClientIP='203.0.113.2', step_ms=100,
                       URL='/admin', Referer='"-"', Cookie='"-"',
                       HTTPStatus=404)
        result = feed_all(browser + scanner).result()

        scores = {s['ip']: s['score'] for s in result['suspects']}
        assert scores['203.0.113.2'] > scores['203.0.113.1']

    def test_a_scanner_trips_the_expected_signals(self):
        """`signals` is the top four by weight, not the full set — the table
        column has to stay readable. The underlying ratios carry the rest."""
        scanner = bulk(400, ClientIP='203.0.113.2', step_ms=100,
                       URL='/admin', Referer='"-"', Cookie='"-"',
                       HTTPStatus=404)
        entry = feed_all(scanner).result()['suspects'][0]

        assert len(entry['signals']) <= 4
        assert 'err4xx' in entry['signals']
        assert 'no_assets' in entry['signals']
        assert entry['err4xx_share'] == pytest.approx(1.0)
        assert entry['asset_share'] == pytest.approx(0.0)
        assert entry['referer_share'] == pytest.approx(0.0)
        assert entry['cookie_share'] == pytest.approx(0.0)

    def test_rotating_user_agents_raises_the_score(self):
        steady = bulk(120, ClientIP='203.0.113.1')
        churn = [row(ClientIP='203.0.113.2',
                     EpochTime=str(BASE_MS + i * 1000),
                     UserAgent=f'{BROWSER_UA} variant/{i % 40}')
                 for i in range(120)]
        result = feed_all(steady + churn).result()
        scores = {s['ip']: s['score'] for s in result['suspects']}
        assert scores['203.0.113.2'] > scores['203.0.113.1']

    def test_waf_invalid_rows_contribute(self):
        clean = feed_all(bulk(100, ClientIP='203.0.113.1')).result()
        flagged = feed_all(bulk(100, ClientIP='203.0.113.1',
                                WFMatched='INVALID')).result()
        assert flagged['suspects'][0]['waf_invalid_share'] == pytest.approx(1.0)
        assert (flagged['suspects'][0]['score']
                > clean['suspects'][0]['score'])

    def test_a_high_band_address_is_counted_as_flagged(self):
        rows = []
        for i in range(600):
            rows.append(row(ClientIP='203.0.113.2',
                            EpochTime=str(BASE_MS + i * 50),
                            URL='/wp-login.php', HTTPStatus=404,
                            Referer='"-"', Cookie='"-"',
                            WFMatched='INVALID',
                            UserAgent=f'scanner/{i % 30}'))
        result = feed_all(rows).result()
        assert result['suspects'][0]['score'] >= BAND_HIGH
        assert result['suspects'][0]['band'] == 'high'
        assert result['flagged_high'] == 1


class TestSampledPullSuppression:
    """A sampled pull collects 300s of every 7200s.

    An address seen inside a single window has uniformly small gaps whatever
    it was really doing, so the regularity test fires on it by construction —
    39% of candidates on the reference 30-day sample were confined to one
    window, and the unsuppressed scorer flagged 835 of 3,044 as high
    confidence. Leaving the signal out beats warning about it.
    """

    def _rows(self):
        return bulk(120, ClientIP='203.0.113.1', step_ms=200,
                    URL='/probe', Referer='"-"', Cookie='"-"')

    def test_timing_signals_are_dropped_on_a_sampled_pull(self):
        agg = AbuseAggregator({'203.0.113.1'}, sampled=True)
        for r in self._rows():
            agg.feed(r)
        entry = agg.result()['suspects'][0]
        assert 'metronome' not in entry['signals']
        assert 'rate' not in entry['signals']
        assert entry['timing_suppressed'] is True

    def test_timing_signals_survive_on_a_full_pull(self):
        entry = feed_all(self._rows()).result()['suspects'][0]
        assert 'metronome' in entry['signals']
        assert entry['timing_suppressed'] is False

    def test_rate_is_null_rather_than_wrong_when_suppressed(self):
        agg = AbuseAggregator({'203.0.113.1'}, sampled=True)
        for r in self._rows():
            agg.feed(r)
        entry = agg.result()['suspects'][0]
        assert entry['rate_per_min'] is None
        assert entry['gap_cv'] is None

    def test_suppression_does_not_merely_scale_the_score_down(self):
        """The dropped weights leave the denominator too, so a genuinely
        abusive address still scores on the signals that survive."""
        rows = bulk(200, ClientIP='203.0.113.1', step_ms=200, URL='/wp-login',
                    HTTPStatus=404, Referer='"-"', Cookie='"-"',
                    WFMatched='INVALID')
        agg = AbuseAggregator({'203.0.113.1'}, sampled=True)
        for r in rows:
            agg.feed(r)
        assert agg.result()['suspects'][0]['score'] >= BAND_HIGH

    def test_analyze_pull_infers_sampling_from_the_summary(self, tmp_path):
        store = PullStore(str(tmp_path), 7)
        with store.open_day('2026-01-01') as writer:
            writer.write(self._rows())
        sampled = analyze_pull(store, {'mode': 'sample'})
        full = analyze_pull(store, {'mode': 'full'})
        assert sampled['suspects'][0]['timing_suppressed'] is True
        assert full['suspects'][0]['timing_suppressed'] is False


# --- bounded memory --------------------------------------------------------


class TestCaps:
    def test_url_table_is_trimmed_by_weight_not_by_arrival(self):
        """A hard first-seen cap lets the first hour decide the report."""
        rows = []
        for i in range(MAX_URLS_PER_IP * 3):
            rows.append(row(ClientIP='203.0.113.1', URL=f'/early-{i}',
                            EpochTime=str(BASE_MS + i * 1000)))
        heavy_at = BASE_MS + MAX_URLS_PER_IP * 3 * 1000
        for i in range(500):
            rows.append(row(ClientIP='203.0.113.1', URL='/late-heavy',
                            EpochTime=str(heavy_at + i * 1000)))
        profile = feed_all(rows).profiles['203.0.113.1']

        assert len(profile.urls) <= MAX_URLS_PER_IP * 2
        assert profile.urls['/late-heavy'] == 500

    def test_the_rate_uses_the_true_span_not_the_retained_sample(self):
        """The timestamp list is capped; the request count is not.

        Taking the span from the capped sample divides the full count by a
        truncated window. On the reference corpus that inflated the headline
        rate 3.5x (1,517/min reported as 5,394/min) and placed `last_seen` an
        hour and a half before the traffic actually stopped.
        """
        from app.logpull import abuse
        original = abuse.MAX_TIMESTAMPS_PER_IP
        try:
            abuse.MAX_TIMESTAMPS_PER_IP = 10
            # 100 rows, one per second: exactly 99 seconds end to end.
            agg = feed_all(bulk(100, ClientIP='203.0.113.1', step_ms=1000))
            entry = agg.result()['suspects'][0]
        finally:
            abuse.MAX_TIMESTAMPS_PER_IP = original

        assert entry['requests'] == 100
        assert entry['last_seen'] - entry['first_seen'] == 99
        assert entry['rate_per_min'] == pytest.approx(100 / (99 / 60), rel=0.01)

    def test_hitting_the_candidate_ceiling_sets_a_flag(self):
        from app.logpull import abuse
        rows = [row(ClientIP=f'203.0.113.{i}') for i in range(5)]
        agg = AbuseAggregator({r['ClientIP'] for r in rows})
        original = abuse.MAX_CANDIDATES
        try:
            abuse.MAX_CANDIDATES = 2
            for r in rows:
                agg.feed(r)
        finally:
            abuse.MAX_CANDIDATES = original
        assert agg.caps.get('candidates') is True
        assert len(agg.profiles) == 2


# --- rollups ---------------------------------------------------------------


class TestRollups:
    def test_a_crawler_only_range_is_dropped_from_the_rollup(self):
        rows = []
        for host in range(1, 6):
            rows += bulk(40, ClientIP=f'66.249.67.{host}',
                         UserAgent=GOOGLEBOT_UA)
        result = feed_all(rows).result()
        assert result['subnets'] == []

    def test_a_mixed_range_survives_the_rollup(self):
        rows = []
        for host in range(1, 6):
            rows += bulk(40, ClientIP=f'203.0.113.{host}',
                         Referer='"-"', Cookie='"-"', URL='/probe')
        result = feed_all(rows).result()
        assert result['subnets']
        entry = result['subnets'][0]
        assert entry['key'] == '203.0.113.0/24'
        assert entry['distinct_ips'] == 5
        assert entry['non_crawler_ips'] == 5


# --- findings --------------------------------------------------------------


class TestFindings:
    def test_no_findings_below_the_row_floor(self):
        data = {'rows': MIN_ROWS_FOR_FINDINGS - 1, 'suspects': [],
                'impostors': [], 'subnets': [], 'sample': {}}
        assert build_findings(data) == []

    def test_findings_carry_a_renderable_category(self):
        """An unknown category lands in a bucket report.py never renders."""
        from app.logpull.report import SECTIONS
        valid = {s['key'] for s in SECTIONS}
        data = {
            'rows': 50_000,
            'suspects': [{'ip': '203.0.113.2', 'band': 'high', 'requests': 9000,
                          'rate_per_min': 500.0, 'err4xx_share': 0.9,
                          'distinct_uas': 40, 'signals': ['err4xx']}],
            'impostors': [{'ip': '203.0.113.9', 'requests': 100}],
            'subnets': [{'key': '203.0.113.0/24', 'requests': 9000,
                         'distinct_ips': 9, 'requests_per_ip': 1000}],
            'sample': {'mode': 'sample'},
        }
        findings = build_findings(data)
        assert findings
        assert {f['category'] for f in findings} <= valid

    def test_findings_use_only_the_two_supported_severities(self):
        data = {
            'rows': 50_000,
            'suspects': [{'ip': '203.0.113.2', 'band': 'high', 'requests': 9000,
                          'rate_per_min': 500.0, 'err4xx_share': 0.9,
                          'distinct_uas': 40, 'signals': ['err4xx']}],
            'impostors': [], 'subnets': [], 'sample': {},
        }
        assert {f['severity'] for f in build_findings(data)} <= {'warning', 'info'}

    def test_a_sampled_pull_is_called_out(self):
        data = {'rows': 50_000, 'suspects': [], 'impostors': [], 'subnets': [],
                'sample': {'mode': 'sample'}}
        codes = {f['code'] for f in build_findings(data)}
        assert 'abuse_sampled_pull' in codes

    def test_the_headline_count_is_the_total_not_the_stored_page(self):
        """`suspects` is truncated to TOP_PROFILES; the counts are not.

        Counting the truncated list reported "500 addresses" on a corpus that
        actually had 835 — a confident undercount pinned to the storage cap.
        """
        shown = [{'ip': f'203.0.113.{i}', 'band': 'high', 'requests': 100,
                  'rate_per_min': 500.0, 'err4xx_share': 0.9,
                  'distinct_uas': 40, 'signals': ['err4xx']}
                 for i in range(10)]
        data = {'rows': 50_000, 'suspects': shown, 'flagged_high': 835,
                'impostors': [], 'subnets': [], 'sample': {}}
        finding = build_findings(data)[0]
        assert '835' in finding['title']
        assert finding['evidence']['addresses'] == 835

    def test_a_null_rate_does_not_break_the_headline(self):
        """Suppressed timing leaves `rate_per_min` as None."""
        data = {
            'rows': 50_000,
            'suspects': [{'ip': '203.0.113.2', 'band': 'high', 'requests': 900,
                          'rate_per_min': None, 'err4xx_share': 0.9,
                          'distinct_uas': 40, 'signals': ['err4xx']}],
            'flagged_high': 1, 'impostors': [], 'subnets': [],
            'sample': {'mode': 'sample'},
        }
        finding = build_findings(data)[0]
        assert '/min' not in finding['detail']
        assert '203.0.113.2' in finding['detail']


# --- end to end over a store ----------------------------------------------


class TestAnalyzePull:
    def test_reads_rows_back_off_disk_and_profiles_them(self, tmp_path):
        store = PullStore(str(tmp_path), 1)
        with store.open_day('2026-01-01') as writer:
            writer.write(bulk(60, ClientIP='203.0.113.1', step_ms=100,
                              URL='/admin', Referer='"-"', Cookie='"-"'))
            writer.write(bulk(5, ClientIP='203.0.113.99'))
        result = analyze_pull(store, {'mode': 'full'})

        assert result['rows'] == 65
        assert result['distinct_ips'] == 2
        assert result['candidate_ips'] == 1
        assert [s['ip'] for s in result['suspects']] == ['203.0.113.1']

    def test_a_pull_with_no_rows_does_not_explode(self, tmp_path):
        store = PullStore(str(tmp_path), 2)
        store.ensure()
        result = analyze_pull(store, {'mode': 'full'})
        assert result['rows'] == 0
        assert result['suspects'] == []
        assert result['findings'] == []

    def test_progress_is_reported_across_both_passes(self, tmp_path):
        store = PullStore(str(tmp_path), 3)
        with store.open_day('2026-01-01') as writer:
            writer.write(bulk(60, ClientIP='203.0.113.1'))
        seen = []
        analyze_pull(store, {'mode': 'full'}, on_progress=seen.append,
                     yield_every=10)
        assert seen
        assert seen == sorted(seen)


# --- routes ----------------------------------------------------------------


@pytest.fixture
def user(app, db):
    u = User(username='abuse-tester', email='abuse@example.com', role='user',
             is_active=True)
    u.set_password('x')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def other_user(app, db):
    u = User(username='abuse-other', email='other@example.com', role='user',
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


@pytest.fixture
def spawned(monkeypatch):
    calls = []
    monkeypatch.setattr('app.routes.traffic.socketio.start_background_task',
                        lambda fn, *a, **kw: calls.append((fn.__name__, a)))
    return calls


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


class TestAbuseRoutes:
    def test_it_spawns_a_background_task(self, logged_in_client, db, user,
                                         account, spawned):
        pull = make_complete_pull(db, user, account)
        resp = logged_in_client.post(f'/traffic/{pull.id}/abuse')
        assert resp.status_code == 302
        assert spawned and spawned[0][0] == 'run_abuse_analysis'

    def test_it_refuses_once_the_raw_rows_expired(self, logged_in_client, db,
                                                  user, account, spawned):
        pull = make_complete_pull(db, user, account, raw_deleted=True)
        logged_in_client.post(f'/traffic/{pull.id}/abuse')
        assert spawned == []

    def test_it_refuses_while_the_pull_is_still_running(self, logged_in_client,
                                                        db, user, account,
                                                        spawned):
        pull = make_complete_pull(db, user, account,
                                  status=LogPull.STATUS_RUNNING)
        logged_in_client.post(f'/traffic/{pull.id}/abuse')
        assert spawned == []

    def test_another_users_pull_is_not_found(self, logged_in_client, db,
                                             other_user, account, spawned):
        pull = make_complete_pull(db, other_user, account,
                                  user_id=other_user.id)
        assert logged_in_client.post(
            f'/traffic/{pull.id}/abuse').status_code == 404
        assert spawned == []

    def test_the_results_page_renders_before_any_profile_exists(
            self, logged_in_client, db, user, account):
        pull = make_complete_pull(db, user, account)
        resp = logged_in_client.get(f'/traffic/{pull.id}/abuse')
        assert resp.status_code == 200
        assert b'No profile yet' in resp.data

    def test_the_results_page_renders_a_stored_profile(self, logged_in_client,
                                                       db, user, account):
        pull = make_complete_pull(db, user, account)
        pull.report = {'abuse': {
            'rows': 50_000, 'profiled_ips': 2, 'distinct_ips': 900,
            'min_requests': 30, 'flagged_high': 1, 'flagged_medium': 0,
            'suspects_total': 1, 'crawlers_total': 1,
            'suspects': [{'ip': '203.0.113.2', 'score': 0.52, 'band': 'high',
                          'requests': 9000, 'rate_per_min': 500.0,
                          'asset_share': 0.0, 'err4xx_share': 0.46,
                          'distinct_uas': 40, 'countries': ['US'],
                          'signals': ['err4xx', 'ua_churn'],
                          'impostor': False, 'crawler': None}],
            'crawlers': [{'ip': '66.249.67.1', 'crawler': 'Googlebot',
                          'requests': 400, 'bytes': 1024,
                          'verification': 'published_list', 'verified': True}],
            'impostors': [], 'subnets': [], 'cohorts': [], 'caps': {},
            'findings': [], 'sample': {},
        }}
        db.session.commit()

        resp = logged_in_client.get(f'/traffic/{pull.id}/abuse')
        assert resp.status_code == 200
        assert b'203.0.113.2' in resp.data
        assert b'Googlebot' in resp.data

    def test_a_sampled_pull_is_warned_about_on_the_page(self, logged_in_client,
                                                        db, user, account):
        pull = make_complete_pull(db, user, account, mode=MODE_SAMPLE)
        resp = logged_in_client.get(f'/traffic/{pull.id}/abuse')
        assert b'sampled pull' in resp.data
