"""Tests for app/traffic_insights.py — the performance + traffic-health
aggregation behind the review report's "Performance & Traffic Health" card.

Pure-function tests over synthetic TR (access) log rows; no app context and
no network. Thresholds under test come from the module's own constants so
the tests track the module rather than hard-coding magic numbers.
"""

from app import traffic_insights as ti


def _row(url='/page', status=200, cache_hit=0, time_taken=100, server_time=80, **extra):
    row = {
        'LogType': 'TR',
        'URL': url,
        'HTTPStatus': status,
        'CacheHit': cache_hit,
        'TimeTaken': time_taken,
        'ServerTime': server_time,
    }
    row.update(extra)
    return row


def _rows(n, **kwargs):
    return [_row(**kwargs) for _ in range(n)]


def _finding_codes(report):
    return {f['code'] for f in report['findings']}


class TestSampleGuardrails:
    def test_empty_logs(self):
        report = ti.analyze([])
        assert report['sample']['rows'] == 0
        assert report['sample']['insufficient'] is True
        assert report['findings'] == []

    def test_none_is_safe(self):
        assert ti.analyze(None)['sample']['rows'] == 0

    def test_below_min_sample_emits_no_findings(self):
        """A handful of requests can't support a rate or a percentile."""
        logs = _rows(ti.MIN_SAMPLE - 1, status=500)
        report = ti.analyze(logs)
        assert report['sample']['insufficient'] is True
        assert report['findings'] == []
        # Metrics are still computed, just not turned into conclusions.
        assert report['errors']['by_class']['5xx'] == ti.MIN_SAMPLE - 1

    def test_at_min_sample_findings_are_emitted(self):
        report = ti.analyze(_rows(ti.MIN_SAMPLE, status=500))
        assert report['sample']['insufficient'] is False
        assert 'errors_server' in _finding_codes(report)

    def test_truncated_flag_set_when_api_total_exceeds_rows(self):
        report = ti.analyze(_rows(60), total_from_api=5000)
        assert report['sample']['truncated'] is True
        assert report['sample']['total_from_api'] == 5000

    def test_not_truncated_when_totals_match(self):
        report = ti.analyze(_rows(60), total_from_api=60)
        assert report['sample']['truncated'] is False


class TestCacheSplit:
    """The whole point of splitting static from dynamic: on a dynamic-heavy
    app the overall hit rate is near zero and means nothing."""

    def test_healthy_static_rate_is_not_flagged_despite_low_overall_rate(self):
        # 200 dynamic misses (correct behaviour) + 50 static requests at 80% hit.
        logs = _rows(200, url='/api/search', cache_hit=0)
        logs += _rows(40, url='/static/app.js', cache_hit=1)
        logs += _rows(10, url='/static/app.js', cache_hit=0)

        report = ti.analyze(logs)
        overall_hit_rate = 40 / 250
        assert overall_hit_rate < 0.2, 'precondition: overall rate looks alarming'
        assert report['cache']['static_hit_rate'] == 0.8
        assert report['cache']['dynamic_hit_rate'] == 0.0
        assert 'cache_static_miss' not in _finding_codes(report)

    def test_poor_static_rate_is_flagged(self):
        logs = _rows(60, url='/static/app.js', cache_hit=0)
        report = ti.analyze(logs)
        assert 'cache_static_miss' in _finding_codes(report)
        finding = next(f for f in report['findings'] if f['code'] == 'cache_static_miss')
        assert finding['evidence']['static_total'] == 60
        assert finding['evidence']['static_hits'] == 0

    def test_non_200_responses_are_excluded(self):
        """A 304 is a successful revalidation, not a cache miss to fix, and a
        404 was never cacheable — counting either inflates the miss rate."""
        logs = _rows(30, url='/static/a.css', status=200, cache_hit=1)
        logs += _rows(50, url='/static/a.css', status=304, cache_hit=0)
        logs += _rows(50, url='/static/missing.css', status=404, cache_hit=0)

        report = ti.analyze(logs)
        assert report['cache']['static_total'] == 30
        assert report['cache']['static_hit_rate'] == 1.0
        assert 'cache_static_miss' not in _finding_codes(report)

    def test_small_static_sample_is_not_flagged(self):
        logs = _rows(ti.MIN_STATIC_SAMPLE - 1, url='/static/app.js', cache_hit=0)
        logs += _rows(60, url='/api/data', cache_hit=0)
        report = ti.analyze(logs)
        assert 'cache_static_miss' not in _finding_codes(report)

    def test_extension_detection(self):
        assert ti._is_static('/assets/app.min.js') is True
        assert ti._is_static('/img/logo.PNG') is True
        assert ti._is_static('/api/v1/users') is False
        assert ti._is_static('/download') is False
        assert ti._is_static('') is False

    def test_top_uncached_static_ranks_by_request_count(self):
        logs = _rows(40, url='/static/big.js', cache_hit=0)
        logs += _rows(25, url='/static/small.js', cache_hit=0)
        report = ti.analyze(logs)
        top = report['cache']['top_uncached_static']
        assert top[0] == {'url': '/static/big.js', 'count': 40}


class TestLatency:
    def test_origin_bound_traffic_is_flagged(self):
        logs = _rows(60, time_taken=800, server_time=760)
        report = ti.analyze(logs)
        assert 'latency_origin_bound' in _finding_codes(report)
        finding = next(f for f in report['findings'] if f['code'] == 'latency_origin_bound')
        assert finding['evidence']['origin_share_p50'] == 760 / 800

    def test_fast_traffic_is_not_flagged(self):
        report = ti.analyze(_rows(60, time_taken=100, server_time=95))
        assert 'latency_origin_bound' not in _finding_codes(report)

    def test_waf_dominated_traffic_is_not_origin_bound(self):
        report = ti.analyze(_rows(60, time_taken=900, server_time=100))
        codes = _finding_codes(report)
        assert 'latency_origin_bound' not in codes
        assert 'latency_waf_overhead' in codes

    def test_negative_overhead_is_clamped(self):
        """Total and origin are stamped by different clocks; some rows come
        back with origin > total."""
        logs = _rows(60, time_taken=100, server_time=150)
        report = ti.analyze(logs)
        assert report['latency']['overhead_p50_ms'] == 0
        assert report['latency']['overhead_p95_ms'] == 0

    def test_rows_missing_server_time_still_count_toward_total(self):
        logs = [_row(time_taken=100, server_time=None) for _ in range(60)]
        report = ti.analyze(logs)
        assert report['latency']['sample'] == 60
        assert report['latency']['total_p50_ms'] == 100
        assert report['latency']['origin_p50_ms'] is None
        assert report['latency']['origin_share_p50'] is None

    def test_slow_urls_need_a_minimum_group_size(self):
        logs = _rows(60, url='/fast', time_taken=50, server_time=40)
        logs += _rows(ti.MIN_URL_GROUP - 1, url='/slow', time_taken=9000, server_time=8900)
        report = ti.analyze(logs)
        ranked = {row['url'] for row in report['latency']['slowest_urls']}
        assert '/slow' not in ranked, 'group below MIN_URL_GROUP must not be ranked'
        assert 'latency_slow_urls' not in _finding_codes(report)

    def test_slow_urls_are_flagged_above_the_group_size(self):
        logs = _rows(60, url='/fast', time_taken=50, server_time=40)
        logs += _rows(ti.MIN_URL_GROUP, url='/slow', time_taken=9000, server_time=8900)
        report = ti.analyze(logs)
        assert 'latency_slow_urls' in _finding_codes(report)
        assert report['latency']['slowest_urls'][0]['url'] == '/slow'


class TestPercentile:
    def test_empty_is_none(self):
        assert ti._percentile([], 0.5) is None

    def test_single_value(self):
        assert ti._percentile([7], 0.95) == 7

    def test_nearest_rank(self):
        values = list(range(1, 101))  # 1..100
        assert ti._percentile(values, 0.5) == 50
        assert ti._percentile(values, 0.95) == 95
        assert ti._percentile(values, 0.99) == 99

    def test_unsorted_input(self):
        assert ti._percentile([9, 1, 5], 0.5) == 5


class TestErrors:
    def test_client_error_rate_flagged(self):
        logs = _rows(90, status=200)
        logs += _rows(10, url='/missing', status=404)
        report = ti.analyze(logs)
        assert report['errors']['client_error_rate'] == 0.1
        assert 'errors_client' in _finding_codes(report)
        finding = next(f for f in report['findings'] if f['code'] == 'errors_client')
        assert finding['evidence']['top_404'][0] == {'url': '/missing', 'count': 10}

    def test_low_client_error_rate_not_flagged(self):
        logs = _rows(99, status=200) + _rows(1, status=404)
        assert 'errors_client' not in _finding_codes(ti.analyze(logs))

    def test_server_error_rate_flagged(self):
        logs = _rows(97, status=200) + _rows(3, url='/broken', status=500)
        report = ti.analyze(logs)
        assert 'errors_server' in _finding_codes(report)
        finding = next(f for f in report['findings'] if f['code'] == 'errors_server')
        assert finding['evidence']['top_5xx'][0] == {'url': '/broken', 'count': 3}

    def test_status_classes_counted(self):
        logs = _rows(50, status=200) + _rows(5, status=301) + _rows(5, status=403)
        by_class = ti.analyze(logs)['errors']['by_class']
        assert by_class['2xx'] == 50
        assert by_class['3xx'] == 5
        assert by_class['4xx'] == 5
        assert by_class['5xx'] == 0

    def test_unparseable_status_is_skipped(self):
        logs = _rows(60, status=200) + [_row(status='"-"'), _row(status=None)]
        assert ti.analyze(logs)['errors']['classified'] == 60


class TestFieldSentinels:
    def test_quoted_dash_is_treated_as_absent(self):
        """Empty fields arrive as the literal 3-char string `"-"`."""
        assert ti._unset('"-"') is True
        assert ti._unset('-') is True
        assert ti._unset('') is True
        assert ti._unset(None) is True
        assert ti._unset('/real/path') is False

    def test_rows_with_sentinel_urls_are_not_ranked(self):
        logs = _rows(60, url='"-"', status=404)
        report = ti.analyze(logs)
        assert report['errors']['top_404'] == []

    def test_string_numerics_are_coerced(self):
        logs = [_row(status='200', cache_hit='1', time_taken='120', server_time='100')
                for _ in range(60)]
        report = ti.analyze(logs)
        assert report['latency']['total_p50_ms'] == 120
        assert report['cache']['dynamic_hits'] == 60


class TestFindingOrdering:
    def test_warnings_sort_before_info(self):
        logs = _rows(60, url='/static/app.js', cache_hit=0, time_taken=900, server_time=100)
        report = ti.analyze(logs)
        severities = [f['severity'] for f in report['findings']]
        assert severities == sorted(severities, key=lambda s: 0 if s == 'warning' else 1)
        assert 'warning' in severities and 'info' in severities

    def test_every_finding_carries_evidence(self):
        logs = _rows(60, url='/static/app.js', cache_hit=0, status=404)
        for finding in ti.analyze(logs)['findings']:
            assert finding['evidence'], f'{finding["code"]} has no evidence'
            assert finding['code'] and finding['title'] and finding['detail']
