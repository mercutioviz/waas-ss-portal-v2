"""Tests for the cache analysis over a completed pull and the live header
audit (app/logpull/analysis.py, app/logpull/header_audit.py).

The failure modes worth pinning down here all produce a *clean-looking* wrong
answer rather than an error:

- `EpochTime` arrives as a JSON string of milliseconds. An int guard drops
  every row and the repeat metric reports a confident zero.
- Absent fields arrive as the literal 3-character string `"-"`.
- A 404 that repeats in a loop outranks every real asset and would send the
  live audit off to probe URLs that do not exist.
- A single conditional probe carrying both validators reports "conditional
  requests unsupported" and hides the ETag that caused it. Only the
  three-probe split distinguishes the two.
- `Host` comes off the wire, so an injected header must not be able to steer
  an outbound request at the portal's own network.
"""
import json
import socket
import uuid

import pytest

from app.logpull.analysis import (
    MIN_AUDIT_HOST_REQUESTS,
    MIN_ROWS_FOR_FINDINGS,
    REPEAT_BUCKET_MS,
    TOP_ASSETS_PER_HOST,
    CacheAggregator,
    _epoch_ms,
    _RepeatTracker,
    analyze_pull,
    is_auditable_host,
)
from app.logpull.header_audit import (
    VERDICT_CHALLENGED,
    VERDICT_ERROR,
    VERDICT_ETAG_REJECTED,
    VERDICT_ETAG_SUPPRESSES,
    VERDICT_NO_CONDITIONAL,
    VERDICT_NO_VALIDATORS,
    VERDICT_OK,
    _classify,
    audit,
    build_findings,
    probe_asset,
)
from app.logpull.store import PullStore
from app.logpull.windows import MODE_SAMPLE
from app.models import LogPull, User, WaasAccount

BASE_MS = 1_767_225_600_000  # 2026-01-01T00:00:00Z in milliseconds


def row(**kwargs):
    """One access-log row with the API's real field names and string types."""
    defaults = {
        'Host': 'www.example.com',
        'URL': '/static/app.js',
        'ClientIP': '198.51.100.7',
        'HTTPStatus': 200,
        'BytesSent': '1024',
        'CacheHit': '0',
        'EpochTime': str(BASE_MS),
        'UserAgent': 'Mozilla/5.0',
    }
    defaults.update(kwargs)
    return defaults


def feed_all(rows):
    agg = CacheAggregator()
    for r in rows:
        agg.feed(r)
    return agg


def no_dns(host):
    """`check_host` stub: accept anything that looks like a name, skip DNS."""
    return bool(host) and '.' in host


# --- field parsing ---------------------------------------------------------


class TestEpochMs:
    def test_parses_the_string_of_milliseconds_the_api_sends(self):
        """The field is a JSON string, not a number. Treating it as an int
        drops every row and the repeat metric reports a clean zero."""
        assert _epoch_ms('1767225600000') == 1_767_225_600_000

    def test_parses_a_real_int_too(self):
        assert _epoch_ms(1_767_225_600_000) == 1_767_225_600_000

    def test_unset_field_is_none(self):
        assert _epoch_ms('-') is None
        assert _epoch_ms('"-"') is None
        assert _epoch_ms(None) is None
        assert _epoch_ms('') is None

    def test_garbage_is_none_not_an_exception(self):
        assert _epoch_ms('not-a-time') is None


# --- repeat fetch ----------------------------------------------------------


class TestRepeatTracker:
    def test_counts_only_the_repeats_not_the_first_fetch(self):
        t = _RepeatTracker()
        for _ in range(3):
            t.add(100, '10.0.0.1', '/a.js')
        t.finish()
        assert t.excess == 2
        assert t.repeated_keys == 1
        assert t.tracked_keys == 1

    def test_a_single_fetch_is_not_redundant(self):
        t = _RepeatTracker()
        t.add(100, '10.0.0.1', '/a.js')
        t.finish()
        assert t.excess == 0
        assert t.repeated_keys == 0

    def test_different_buckets_do_not_merge(self):
        """Two fetches an hour apart are not a caching failure."""
        t = _RepeatTracker()
        t.add(100, '10.0.0.1', '/a.js')
        t.add(112, '10.0.0.1', '/a.js')
        t.finish()
        assert t.excess == 0

    def test_different_clients_do_not_merge(self):
        t = _RepeatTracker()
        t.add(100, '10.0.0.1', '/a.js')
        t.add(100, '10.0.0.2', '/a.js')
        t.finish()
        assert t.excess == 0

    def test_old_buckets_are_folded_and_dropped(self):
        """Memory has to stay bounded over tens of millions of rows, so
        completed buckets fold into the totals and are released."""
        t = _RepeatTracker(retain=2)
        for bucket in range(50):
            t.add(bucket, '10.0.0.1', '/a.js')
            t.add(bucket, '10.0.0.1', '/a.js')
        assert len(t._open) <= 3
        t.finish()
        assert t.excess == 50

    def test_rows_arriving_after_their_bucket_closed_are_counted_separately(self):
        t = _RepeatTracker(retain=1)
        t.add(100, '10.0.0.1', '/a.js')
        t.add(110, '10.0.0.1', '/a.js')
        t.add(100, '10.0.0.1', '/a.js')  # late
        t.finish()
        assert t.late_rows == 1
        assert t.excess == 0

    def test_undated_rows_are_counted_not_guessed_at(self):
        t = _RepeatTracker()
        t.add(None, '10.0.0.1', '/a.js')
        t.finish()
        assert t.undated_rows == 1
        assert t.excess == 0

    def test_a_bucket_that_hits_the_key_cap_is_flagged(self):
        t = _RepeatTracker(max_keys=2)
        t.add(1, 'a', '/1.js')
        t.add(1, 'b', '/2.js')
        t.add(1, 'c', '/3.js')
        t.finish()
        assert t.capped is True


class TestRepeatThroughTheAggregator:
    def test_string_epoch_rows_produce_a_repeat_count(self):
        """End-to-end version of the EpochTime trap: if the parse is wrong
        this returns zero rather than failing."""
        rows = [row(EpochTime=str(BASE_MS + i)) for i in range(4)]
        result = feed_all(rows).result(check_host=no_dns)
        assert result['repeat_fetch']['excess_requests'] == 3

    def test_a_304_still_counts_as_a_request_that_did_not_need_to_happen(self):
        rows = [row(), row(HTTPStatus=304, BytesSent='144')]
        result = feed_all(rows).result(check_host=no_dns)
        assert result['repeat_fetch']['excess_requests'] == 1

    def test_dynamic_urls_are_not_tracked(self):
        rows = [row(URL='/search') for _ in range(5)]
        result = feed_all(rows).result(check_host=no_dns)
        assert result['repeat_fetch']['excess_requests'] == 0
        assert result['repeat_fetch']['static_rows'] == 0

    def test_wasted_bytes_use_the_measured_average_size(self):
        rows = [row(BytesSent='2000') for _ in range(3)]
        repeat = feed_all(rows).result(check_host=no_dns)['repeat_fetch']
        assert repeat['excess_requests'] == 2
        assert repeat['excess_bytes'] == 4000

    def test_extrapolation_uses_the_measured_scale_factor(self):
        rows = [row() for _ in range(3)]
        repeat = feed_all(rows).result(scale=24.87, check_host=no_dns)['repeat_fetch']
        assert repeat['excess_requests'] == 2
        assert repeat['extrapolated_requests'] == int(2 * 24.87)


# --- revalidation ----------------------------------------------------------


class TestRevalidation:
    def test_ratio_is_304_over_200_plus_304(self):
        rows = [row() for _ in range(9)] + [row(HTTPStatus=304)]
        reval = feed_all(rows).result(check_host=no_dns)['revalidation']
        by_ext = {r['extension']: r for r in reval['by_extension']}
        assert by_ext['js']['full'] == 9
        assert by_ext['js']['revalidated'] == 1
        assert by_ext['js']['ratio'] == pytest.approx(0.1)

    def test_other_statuses_do_not_participate(self):
        """A 404 is not a cache miss and a 500 is not a revalidation."""
        rows = [row(), row(HTTPStatus=404), row(HTTPStatus=500)]
        reval = feed_all(rows).result(check_host=no_dns)['revalidation']
        by_ext = {r['extension']: r for r in reval['by_extension']}
        assert by_ext['js']['total'] == 1

    def test_static_ratio_aggregates_across_extensions(self):
        rows = [row(URL='/a.js'), row(URL='/b.css', HTTPStatus=304)]
        reval = feed_all(rows).result(check_host=no_dns)['revalidation']
        assert reval['static_full'] == 1
        assert reval['static_revalidated'] == 1
        assert reval['static_ratio'] == pytest.approx(0.5)

    def test_extensionless_urls_land_in_their_own_bucket(self):
        rows = [row(URL='/api/search')]
        reval = feed_all(rows).result(check_host=no_dns)['revalidation']
        by_ext = {r['extension']: r for r in reval['by_extension']}
        assert by_ext['(none)']['full'] == 1
        assert by_ext['(none)']['static'] is False


# --- hosts, errors, edge cache --------------------------------------------


class TestHostBreakdown:
    def test_request_share_and_byte_share_are_tracked_separately(self):
        """The finding usually lives in the gap between the two: a host can
        be a small share of requests and most of the egress."""
        rows = ([row(Host='www.example.com', BytesSent='100') for _ in range(90)]
                + [row(Host='my.example.com', BytesSent='10000') for _ in range(10)])
        hosts = {h['host']: h for h in feed_all(rows).result(check_host=no_dns)['hosts']}
        assert hosts['my.example.com']['request_share'] == pytest.approx(0.1)
        assert hosts['my.example.com']['byte_share'] == pytest.approx(100000 / 109000)
        assert hosts['my.example.com']['skew'] > 2.5

    def test_hosts_are_ranked_by_bytes_not_requests(self):
        rows = ([row(Host='chatty.example.com', BytesSent='10') for _ in range(50)]
                + [row(Host='heavy.example.com', BytesSent='100000')])
        hosts = feed_all(rows).result(check_host=no_dns)['hosts']
        assert hosts[0]['host'] == 'heavy.example.com'


class TestNotFound:
    def test_404s_are_excluded_from_the_asset_ranking(self):
        """A path that 404s in a loop outranks every real asset and sends
        the header audit off to probe a URL that does not exist."""
        rows = ([row(URL='/missing.js', HTTPStatus=404) for _ in range(100)]
                + [row(URL='/real.js') for _ in range(5)])
        agg = feed_all(rows)
        result = agg.result(check_host=no_dns)
        assert result['not_found']['rows'] == 100
        assert result['not_found']['top'][0]['url'] == '/missing.js'
        assert [t['url'] for t in result['audit_targets']] == ['/real.js']

    def test_share_is_measured_against_all_rows(self):
        rows = [row(HTTPStatus=404)] + [row() for _ in range(3)]
        result = feed_all(rows).result(check_host=no_dns)
        assert result['not_found']['share'] == pytest.approx(0.25)


class TestEdgeCache:
    def test_static_and_dynamic_are_measured_separately(self):
        rows = ([row(CacheHit='1') for _ in range(8)]
                + [row(URL='/search', CacheHit='0') for _ in range(100)])
        edge = feed_all(rows).result(check_host=no_dns)['edge_cache']
        assert edge['static_hit_rate'] == pytest.approx(1.0)
        assert edge['dynamic_hit_rate'] == pytest.approx(0.0)

    def test_status_classes_are_grouped(self):
        rows = [row(), row(HTTPStatus=304), row(HTTPStatus=404), row(HTTPStatus=503)]
        classes = feed_all(rows).result(check_host=no_dns)['status_classes']
        assert classes == {'2xx': 1, '3xx': 1, '4xx': 1, '5xx': 1}


class TestUnsetFields:
    def test_dash_fields_do_not_crash_or_count(self):
        """Absent fields arrive as the literal 3-character string `"-"`."""
        rows = [row(Host='-', ClientIP='-', BytesSent='-', CacheHit='-',
                    EpochTime='-')]
        result = feed_all(rows).result(check_host=no_dns)
        assert result['sample']['rows'] == 1
        assert result['sample']['bytes'] == 0
        assert result['hosts'] == []
        assert result['repeat_fetch']['undated_rows'] == 0  # no ClientIP, not tracked


# --- audit target selection ------------------------------------------------


class TestAuditTargets:
    def test_top_assets_per_host_are_capped(self):
        rows = [row(URL=f'/a{i}.js') for i in range(20)
                for _ in range(MIN_AUDIT_HOST_REQUESTS)]
        result = feed_all(rows).result(check_host=no_dns)
        assert len(result['audit_targets']) == TOP_ASSETS_PER_HOST

    def test_a_host_seen_only_a_handful_of_times_is_not_probed(self):
        """`Host` is client-supplied; one injected header must not be able to
        put a destination on the probe list."""
        rows = ([row(Host='real.example.com') for _ in range(MIN_AUDIT_HOST_REQUESTS)]
                + [row(Host='injected.example.com')])
        result = feed_all(rows).result(check_host=no_dns)
        assert {t['host'] for t in result['audit_targets']} == {'real.example.com'}

    def test_hosts_rejected_by_the_safety_check_are_reported_not_dropped(self):
        rows = [row(Host='internal.corp') for _ in range(MIN_AUDIT_HOST_REQUESTS)]
        result = feed_all(rows).result(check_host=lambda host: False)
        assert result['audit_targets'] == []
        assert result['audit_skipped_hosts'] == ['internal.corp']


class TestIsAuditableHost:
    def test_rejects_names_that_are_not_dns_names(self):
        for bad in ('', 'localhost', '192.168.1.1', 'has space.com',
                    '-leading.example.com', 'http://example.com/x'):
            assert is_auditable_host(bad, resolve=False) is False

    def test_accepts_an_ordinary_hostname(self):
        assert is_auditable_host('www.example.com', resolve=False) is True

    def test_rejects_a_name_resolving_into_private_space(self, monkeypatch):
        """Without this a log row carrying `Host: metadata.internal` would
        turn the audit into an outbound probe of our own network."""
        monkeypatch.setattr(
            socket, 'getaddrinfo',
            lambda *a, **kw: [(None, None, None, '', ('169.254.169.254', 443))])
        assert is_auditable_host('metadata.example.com') is False

    def test_rejects_a_name_that_does_not_resolve(self, monkeypatch):
        def boom(*a, **kw):
            raise socket.gaierror('nope')
        monkeypatch.setattr(socket, 'getaddrinfo', boom)
        assert is_auditable_host('nxdomain.example.com') is False

    def test_accepts_a_name_resolving_to_public_space(self, monkeypatch):
        monkeypatch.setattr(
            socket, 'getaddrinfo',
            lambda *a, **kw: [(None, None, None, '', ('93.184.216.34', 443))])
        assert is_auditable_host('www.example.com') is True

    def test_rejects_when_any_address_is_private(self, monkeypatch):
        """A split-horizon name that resolves to both must not sneak through."""
        monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **kw: [
            (None, None, None, '', ('93.184.216.34', 443)),
            (None, None, None, '', ('10.0.0.5', 443)),
        ])
        assert is_auditable_host('split.example.com') is False


# --- findings --------------------------------------------------------------


def findings_by_code(result):
    return {f['code']: f for f in result['findings']}


class TestFindings:
    def test_nothing_is_reported_below_the_sample_floor(self):
        rows = [row() for _ in range(10)]
        assert feed_all(rows).result(check_host=no_dns)['findings'] == []

    def test_zero_edge_hits_reads_as_caching_switched_off(self):
        rows = [row(CacheHit='0') for _ in range(MIN_ROWS_FOR_FINDINGS + 1)]
        codes = findings_by_code(feed_all(rows).result(check_host=no_dns))
        assert 'edge_cache_inactive' in codes
        assert codes['edge_cache_inactive']['category'] == 'waas_config'

    def test_a_working_edge_cache_produces_no_such_finding(self):
        rows = [row(CacheHit='1') for _ in range(MIN_ROWS_FOR_FINDINGS + 1)]
        assert 'edge_cache_inactive' not in findings_by_code(
            feed_all(rows).result(check_host=no_dns))

    def test_low_revalidation_is_an_origin_finding(self):
        rows = [row(EpochTime=str(BASE_MS + i * REPEAT_BUCKET_MS))
                for i in range(MIN_ROWS_FOR_FINDINGS + 1)]
        codes = findings_by_code(feed_all(rows).result(check_host=no_dns))
        assert codes['browser_revalidation_low']['category'] == 'origin'

    def test_repeat_fetch_finding_carries_its_evidence(self):
        rows = [row(ClientIP=f'198.51.100.{i % 5}')
                for i in range(MIN_ROWS_FOR_FINDINGS + 1)]
        codes = findings_by_code(feed_all(rows).result(scale=2.0, check_host=no_dns))
        finding = codes['repeat_fetch']
        assert finding['evidence']['excess_requests'] > 0
        assert finding['evidence']['extrapolated_requests'] >= \
            finding['evidence']['excess_requests']
        assert finding['evidence']['top']

    def test_host_egress_skew_is_reported(self):
        rows = ([row(Host='www.example.com', BytesSent='100') for _ in range(2000)]
                + [row(Host='my.example.com', BytesSent='50000') for _ in range(600)])
        codes = findings_by_code(feed_all(rows).result(check_host=no_dns))
        assert 'host_egress_skew' in codes
        assert 'my.example.com' in codes['host_egress_skew']['detail']

    def test_404_volume_is_reported_separately(self):
        rows = ([row(URL='/gone.js', HTTPStatus=404) for _ in range(200)]
                + [row() for _ in range(1800)])
        codes = findings_by_code(feed_all(rows).result(check_host=no_dns))
        assert 'not_found_volume' in codes

    def test_warnings_sort_ahead_of_info(self):
        rows = ([row(Host='www.example.com', BytesSent='100') for _ in range(2000)]
                + [row(Host='my.example.com', BytesSent='50000') for _ in range(600)])
        findings = feed_all(rows).result(check_host=no_dns)['findings']
        severities = [f['severity'] for f in findings]
        assert severities == sorted(severities, key=lambda s: 0 if s == 'warning' else 1)


# --- streaming over a real store ------------------------------------------


class TestAnalyzePull:
    def test_reads_rows_back_off_disk_and_aggregates(self, tmp_path):
        store = PullStore(str(tmp_path), 1)
        with store.open_day('2026-01-01') as writer:
            writer.write([row() for _ in range(5)])
        result = analyze_pull(store, {'scale': 1.0, 'mode': MODE_SAMPLE},
                              check_host=no_dns)
        assert result['sample']['rows'] == 5
        assert result['repeat_fetch']['excess_requests'] == 4

    def test_takes_the_scale_factor_from_the_collection_summary(self, tmp_path):
        store = PullStore(str(tmp_path), 2)
        with store.open_day('2026-01-01') as writer:
            writer.write([row(BytesSent='1000') for _ in range(4)])
        result = analyze_pull(store, {'scale': 10.0}, check_host=no_dns)
        assert result['sample']['scale'] == 10.0
        assert result['sample']['extrapolated_bytes'] == 40000

    def test_progress_is_reported_at_the_chunk_boundary(self, tmp_path):
        store = PullStore(str(tmp_path), 3)
        with store.open_day('2026-01-01') as writer:
            writer.write([row() for _ in range(25)])
        seen = []
        analyze_pull(store, {}, on_progress=seen.append, yield_every=10,
                     check_host=no_dns)
        assert seen[:2] == [10, 20]
        assert seen[-1] == 25

    def test_cancellation_is_honoured_mid_stream(self, tmp_path):
        from app.logpull.windows import Cancelled

        store = PullStore(str(tmp_path), 4)
        with store.open_day('2026-01-01') as writer:
            writer.write([row() for _ in range(50)])
        with pytest.raises(Cancelled):
            analyze_pull(store, {}, yield_every=10, should_cancel=lambda: True,
                         check_host=no_dns)

    def test_a_torn_final_line_does_not_fail_the_analysis(self, tmp_path):
        """A pull killed mid-write leaves one unparseable line; the store
        skips it, so the analysis must still produce a result."""
        import gzip

        store = PullStore(str(tmp_path), 5)
        store.ensure()
        with gzip.open(store.day_path('2026-01-01'), 'wt') as fh:
            fh.write(json.dumps(row()) + '\n')
            fh.write('{"Host": "trunc')
        result = analyze_pull(store, {}, check_host=no_dns)
        assert result['sample']['rows'] == 1

    def test_days_are_read_in_order(self, tmp_path):
        store = PullStore(str(tmp_path), 6)
        with store.open_day('2026-01-02') as writer:
            writer.write([row(EpochTime=str(BASE_MS + 86_400_000))])
        with store.open_day('2026-01-01') as writer:
            writer.write([row()])
        result = analyze_pull(store, {}, check_host=no_dns)
        assert result['sample']['rows'] == 2
        assert result['repeat_fetch']['late_rows'] == 0


# --- header audit: classification -----------------------------------------


def probe_record(**kwargs):
    base = {'status': 200, 'etag': '"abc-gzip"', 'last_modified': 'Mon, 01 Jan 2026 00:00:00 GMT'}
    base.update(kwargs)
    return base


class TestClassify:
    def test_date_alone_works_but_both_together_do_not(self):
        """The headline finding. RFC 9110 §13.2.2 makes a server receiving
        both validators honour the ETag and ignore the date, so a broken
        ETag suppresses a Last-Modified that works perfectly on its own."""
        record = probe_record(inm_status=200, ims_status=304, both_status=200)
        assert _classify(record) == VERDICT_ETAG_SUPPRESSES

    def test_a_single_combined_probe_would_have_said_unsupported(self):
        """Same origin behaviour, seen only through the combined probe: the
        verdict is wrong and the cause is invisible. This is why there are
        three probes."""
        record = probe_record(inm_status=None, ims_status=None, both_status=200)
        assert _classify(record) == VERDICT_NO_CONDITIONAL

    def test_both_returning_304_is_healthy(self):
        record = probe_record(inm_status=304, ims_status=304, both_status=304)
        assert _classify(record) == VERDICT_OK

    def test_everything_200_means_conditionals_are_ignored(self):
        record = probe_record(inm_status=200, ims_status=200, both_status=200)
        assert _classify(record) == VERDICT_NO_CONDITIONAL

    def test_an_etag_only_asset_that_rejects_its_own_etag(self):
        record = probe_record(last_modified=None, inm_status=200)
        assert _classify(record) == VERDICT_ETAG_REJECTED

    def test_an_etag_only_asset_that_honours_it(self):
        record = probe_record(last_modified=None, inm_status=304)
        assert _classify(record) == VERDICT_OK

    def test_no_validators_at_all(self):
        assert _classify(probe_record(etag=None, last_modified=None)) == \
            VERDICT_NO_VALIDATORS

    def test_a_challenged_probe_never_reaches_validator_logic(self):
        """Headers read off a CAPTCHA page describe the CAPTCHA page."""
        record = probe_record(challenged=True, inm_status=200, ims_status=304)
        assert _classify(record) == VERDICT_CHALLENGED

    def test_an_error_wins_over_everything(self):
        assert _classify(probe_record(error='Timed out')) == VERDICT_ERROR


# --- header audit: probing -------------------------------------------------


class FakeRaw:
    def __init__(self, body):
        self._body = body

    def read(self, n, decode_content=False):
        return self._body[:n]


class FakeResponse:
    def __init__(self, status, headers=None, body=b''):
        self.status_code = status
        self.headers = headers or {}
        self.raw = FakeRaw(body)

    def close(self):
        pass


class FakeSession:
    """Answers by probe shape: which conditional headers were sent."""

    def __init__(self, plan, baseline_headers=None, body=b'x' * 10):
        self.plan = plan
        self.baseline_headers = baseline_headers or {}
        self.body = body
        self.calls = []

    def get(self, url, headers=None, timeout=None, allow_redirects=None,
            stream=None):
        headers = headers or {}
        inm = 'If-None-Match' in headers
        ims = 'If-Modified-Since' in headers
        key = ('both' if inm and ims else 'inm' if inm else 'ims' if ims
               else 'baseline')
        self.calls.append((key, url, headers))
        if key == 'baseline':
            return FakeResponse(200, dict(self.baseline_headers), self.body)
        status = self.plan[key]
        return FakeResponse(status, {}, b'' if status == 304 else self.body)


HEALTHY_HEADERS = {
    'Cache-Control': 'public, max-age=31536000',
    'ETag': '"abc"',
    'Last-Modified': 'Mon, 01 Jan 2026 00:00:00 GMT',
    'Content-Type': 'application/javascript',
    'Content-Encoding': 'gzip',
}

BROKEN_ETAG_HEADERS = dict(HEALTHY_HEADERS, ETag='"abc-gzip"')

TARGET = {'host': 'www.example.com', 'url': '/static/app.js', 'requests': 900}


def no_sleep(_seconds):
    pass


class TestProbeAsset:
    def test_sends_exactly_three_conditional_probes(self):
        session = FakeSession({'inm': 200, 'ims': 304, 'both': 200},
                              BROKEN_ETAG_HEADERS)
        probe_asset(TARGET, session=session, sleep=no_sleep)
        assert [c[0] for c in session.calls] == ['baseline', 'inm', 'ims', 'both']

    def test_each_probe_carries_only_its_own_validator(self):
        session = FakeSession({'inm': 200, 'ims': 304, 'both': 200},
                              BROKEN_ETAG_HEADERS)
        probe_asset(TARGET, session=session, sleep=no_sleep)
        sent = {key: hdrs for key, _url, hdrs in session.calls}
        assert 'If-Modified-Since' not in sent['inm']
        assert 'If-None-Match' not in sent['ims']
        assert sent['both']['If-None-Match'] == '"abc-gzip"'
        assert 'If-Modified-Since' in sent['both']

    def test_detects_the_etag_suppression_pattern_end_to_end(self):
        session = FakeSession({'inm': 200, 'ims': 304, 'both': 200},
                              BROKEN_ETAG_HEADERS)
        record = probe_asset(TARGET, session=session, sleep=no_sleep)
        assert record['verdict'] == VERDICT_ETAG_SUPPRESSES

    def test_a_healthy_origin_reads_as_healthy(self):
        session = FakeSession({'inm': 304, 'ims': 304, 'both': 304},
                              HEALTHY_HEADERS)
        record = probe_asset(TARGET, session=session, sleep=no_sleep)
        assert record['verdict'] == VERDICT_OK
        assert record['max_age'] == 31536000
        assert record['has_lifetime'] is True

    def test_records_the_absence_of_compression(self):
        """WaaS strips Accept-Encoding before the origin sees it, so a
        missing Content-Encoding here is expected — and is the finding."""
        headers = dict(HEALTHY_HEADERS)
        headers.pop('Content-Encoding')
        session = FakeSession({'inm': 304, 'ims': 304, 'both': 304}, headers)
        record = probe_asset(TARGET, session=session, sleep=no_sleep)
        assert record['content_encoding'] is None

    def test_an_html_body_for_a_js_url_is_treated_as_a_challenge(self):
        session = FakeSession({}, {'Content-Type': 'text/html; charset=utf-8'},
                              body=b'<html>captcha</html>')
        record = probe_asset(TARGET, session=session, sleep=no_sleep)
        assert record['challenged'] is True
        assert record['verdict'] == VERDICT_CHALLENGED
        # The conditional probes are not even attempted on a challenge.
        assert [c[0] for c in session.calls] == ['baseline']

    def test_the_status_and_size_of_every_probe_are_kept(self):
        session = FakeSession({'inm': 200, 'ims': 304, 'both': 200},
                              BROKEN_ETAG_HEADERS)
        record = probe_asset(TARGET, session=session, sleep=no_sleep)
        labels = [p['label'] for p in record['probes']]
        assert labels == ['baseline', 'inm', 'ims', 'both']
        assert all(p['status'] is not None for p in record['probes'])
        assert all(p['bytes'] is not None for p in record['probes'])

    def test_a_network_error_is_recorded_not_raised(self):
        import requests as requests_mod

        class Boom:
            def get(self, *a, **kw):
                raise requests_mod.exceptions.ConnectTimeout('nope')

        record = probe_asset(TARGET, session=Boom(), sleep=no_sleep)
        assert record['verdict'] == VERDICT_ERROR
        assert record['error']

    def test_a_tls_failure_is_a_result_not_a_silence(self):
        import requests as requests_mod

        class BadCert:
            def get(self, *a, **kw):
                raise requests_mod.exceptions.SSLError('bad cert')

        record = probe_asset(TARGET, session=BadCert(), sleep=no_sleep)
        assert 'TLS error' in record['error']

    def test_the_absolute_url_keeps_the_logged_path(self):
        session = FakeSession({'inm': 304}, {'ETag': '"a"',
                                             'Content-Type': 'text/css'})
        record = probe_asset({'host': 'www.example.com', 'url': '/a b.css'},
                             session=session, sleep=no_sleep)
        assert record['absolute_url'].startswith('https://www.example.com/')
        assert ' ' not in record['absolute_url']


class TestAudit:
    def test_probes_each_target_and_counts_verdicts(self):
        session = FakeSession({'inm': 200, 'ims': 304, 'both': 200},
                              BROKEN_ETAG_HEADERS)
        targets = [dict(TARGET, url=f'/a{i}.js') for i in range(3)]
        result = audit(targets, session=session, sleep=no_sleep)
        assert result['probed'] == 3
        assert result['verdicts'][VERDICT_ETAG_SUPPRESSES] == 3

    def test_stops_at_the_wall_clock_budget_rather_than_half_measuring(self):
        session = FakeSession({'inm': 304, 'ims': 304, 'both': 304},
                              HEALTHY_HEADERS)
        ticks = iter(range(0, 1000))
        result = audit([dict(TARGET, url=f'/a{i}.js') for i in range(10)],
                       session=session, sleep=no_sleep,
                       budget_seconds=2, clock=lambda: next(ticks))
        assert result['budget_exceeded'] is True
        assert result['probed'] < 10

    def test_an_empty_target_list_is_fine(self):
        result = audit([], sleep=no_sleep)
        assert result['probed'] == 0
        assert result['findings'] == []


class TestAuditFindings:
    def test_the_etag_finding_names_the_origin_side_fix(self):
        records = [{'host': 'www.example.com', 'url': '/a.js',
                    'verdict': VERDICT_ETAG_SUPPRESSES}]
        finding = build_findings(records)[0]
        assert finding['category'] == 'origin'
        assert finding['severity'] == 'warning'
        assert 'If-None-Match' in finding['detail']
        assert '13.2.2' in finding['detail']

    def test_missing_lifetime_is_reported(self):
        records = [{'host': 'h', 'url': '/a.js', 'status': 200,
                    'verdict': VERDICT_NO_CONDITIONAL, 'has_lifetime': False,
                    'no_store': False}]
        codes = {f['code'] for f in build_findings(records)}
        assert 'origin_no_freshness_lifetime' in codes

    def test_an_explicit_no_store_is_not_a_missing_lifetime(self):
        records = [{'host': 'h', 'url': '/a.js', 'status': 200,
                    'verdict': VERDICT_NO_CONDITIONAL, 'has_lifetime': False,
                    'no_store': True}]
        codes = {f['code'] for f in build_findings(records)}
        assert 'origin_no_freshness_lifetime' not in codes

    def test_uncompressed_text_is_a_waas_config_note_not_an_origin_bug(self):
        records = [{'host': 'h', 'url': '/a.js', 'status': 200,
                    'verdict': VERDICT_OK, 'has_lifetime': True,
                    'content_encoding': None}]
        finding = next(f for f in build_findings(records)
                       if f['code'] == 'waas_compression_absent')
        assert finding['category'] == 'waas_config'
        assert finding['severity'] == 'info'

    def test_challenged_probes_are_excluded_from_the_conclusions(self):
        records = [{'host': 'h', 'url': '/a.js', 'status': 200,
                    'verdict': VERDICT_CHALLENGED, 'has_lifetime': False,
                    'content_encoding': None}]
        codes = {f['code'] for f in build_findings(records)}
        assert codes == {'audit_challenged'}

    def test_a_healthy_origin_still_says_something_useful(self):
        records = [{'host': 'h', 'url': '/a.js', 'status': 200,
                    'verdict': VERDICT_OK, 'has_lifetime': True,
                    'content_encoding': 'gzip'}]
        codes = {f['code'] for f in build_findings(records)}
        assert 'origin_conditional_ok' in codes


# --- routes ----------------------------------------------------------------


@pytest.fixture
def user(app, db):
    u = User(username='ca-tester', email='ca@example.com', role='user',
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


class TestAnalysisRoutes:
    def test_reanalysis_spawns_a_background_task(self, logged_in_client, db,
                                                 user, account, spawned):
        pull = make_complete_pull(db, user, account)
        resp = logged_in_client.post(f'/traffic/{pull.id}/analyze')
        assert resp.status_code == 302
        assert spawned and spawned[0][0] == 'run_log_pull_analysis'
        db.session.refresh(pull)
        assert pull.phase == LogPull.PHASE_ANALYZING

    def test_reanalysis_refuses_once_the_raw_rows_expired(self, logged_in_client,
                                                          db, user, account, spawned):
        pull = make_complete_pull(db, user, account, raw_deleted=True)
        logged_in_client.post(f'/traffic/{pull.id}/analyze')
        assert spawned == []

    def test_reanalysis_refuses_while_the_pull_is_still_running(
            self, logged_in_client, db, user, account, spawned):
        pull = make_complete_pull(db, user, account,
                                  status=LogPull.STATUS_RUNNING)
        logged_in_client.post(f'/traffic/{pull.id}/analyze')
        assert spawned == []

    def test_analysis_is_post_only(self, logged_in_client, db, user, account):
        pull = make_complete_pull(db, user, account)
        assert logged_in_client.get(f'/traffic/{pull.id}/analyze').status_code == 405

    def test_another_users_pull_cannot_be_analyzed(self, logged_in_client, db,
                                                   user, account, spawned):
        other = User(username='someone-else', email='other@example.com',
                     role='user', is_active=True)
        other.set_password('x')
        db.session.add(other)
        db.session.commit()
        theirs = make_complete_pull(db, other, account)
        assert logged_in_client.post(
            f'/traffic/{theirs.id}/analyze').status_code == 404
        assert spawned == []


class TestHeaderAuditRoute:
    def test_spawns_when_the_analysis_found_targets(self, logged_in_client, db,
                                                    user, account, spawned):
        pull = make_complete_pull(db, user, account)
        pull.result = {'analysis': {'audit_targets': [dict(TARGET)]}}
        db.session.commit()
        resp = logged_in_client.post(f'/traffic/{pull.id}/audit')
        assert resp.status_code == 302
        assert spawned[0][0] == 'run_header_audit'

    def test_refuses_with_nothing_to_probe(self, logged_in_client, db, user,
                                           account, spawned):
        """The audit's target list comes from the analysis; without one there
        is nothing to probe and no reason to touch the customer's origin."""
        pull = make_complete_pull(db, user, account)
        logged_in_client.post(f'/traffic/{pull.id}/audit')
        assert spawned == []

    def test_audit_is_post_only(self, logged_in_client, db, user, account):
        pull = make_complete_pull(db, user, account)
        assert logged_in_client.get(f'/traffic/{pull.id}/audit').status_code == 405

    def test_results_page_renders_an_analysis(self, logged_in_client, db, user,
                                              account):
        rows = [row() for _ in range(MIN_ROWS_FOR_FINDINGS + 1)]
        analysis = feed_all(rows).result(check_host=no_dns)
        pull = make_complete_pull(db, user, account)
        pull.result = {'rows_sampled': len(rows), 'scale': 1.0, 'analysis': analysis}
        db.session.commit()
        resp = logged_in_client.get(f'/traffic/{pull.id}/results')
        assert resp.status_code == 200
        assert b'Cache analysis' in resp.data
        assert b'Redundant fetches' in resp.data

    def test_results_page_renders_a_header_audit(self, logged_in_client, db,
                                                 user, account):
        pull = make_complete_pull(db, user, account)
        pull.result = {'analysis': feed_all([row()]).result(check_host=no_dns)}
        pull.report = {'header_audit': {
            'probed': 1, 'requested': 1, 'verdicts': {},
            'assets': [{'host': 'www.example.com', 'url': '/a.js', 'status': 200,
                        'etag': '"x-gzip"', 'last_modified': 'Mon',
                        'inm_status': 200, 'ims_status': 304, 'both_status': 200,
                        'verdict': VERDICT_ETAG_SUPPRESSES}],
            'findings': build_findings([{'host': 'h', 'url': '/a.js',
                                         'verdict': VERDICT_ETAG_SUPPRESSES}]),
        }}
        db.session.commit()
        resp = logged_in_client.get(f'/traffic/{pull.id}/results')
        assert resp.status_code == 200
        assert b'ETag cancels Last-Modified' in resp.data
