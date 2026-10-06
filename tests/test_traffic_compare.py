"""Tests for `app.logpull.compare` — before/after window comparison.

The arithmetic here is the whole deliverable: if the control adjustment or
the per-hour normalisation is wrong, the feature produces a confident wrong
number rather than an obvious failure. So the maths is tested directly
rather than through the CLI.
"""
import math

import pytest

from app.logpull.compare import (
    SEGMENT_HUMAN,
    WindowAggregator,
    attribute_change,
    attribute_segment,
    collect_window,
    compare_windows,
    crawler_segment,
    delta,
    field_segment,
    geometric_mean,
    parse_duration,
    plan_comparison,
    plan_labels,
)
from app.logpull.windows import Window

CHANGE_AT = 1_791_300_000          # arbitrary fixed instant
HOUR = 3600


def row(*, ua='Mozilla/5.0', url='/index.html', status=200, sent=1000,
        ip='1.2.3.4', host='example.com'):
    return {
        'UserAgent': ua, 'URL': url, 'HTTPStatus': status,
        'BytesSent': sent, 'ClientIP': ip, 'Host': host,
    }


GOOGLEBOT = ('Mozilla/5.0 (compatible; Googlebot/2.1; '
             '+http://www.google.com/bot.html)')


# --- duration parsing ------------------------------------------------------


@pytest.mark.parametrize('text,expected', [
    ('90s', 90), ('30m', 1800), ('2h', 7200), ('1d', 86400),
    ('120', 120), ('1.5h', 5400),
])
def test_parse_duration(text, expected):
    assert parse_duration(text) == expected


@pytest.mark.parametrize('bad', ['', '0h', '-5m', 'soon'])
def test_parse_duration_rejects_nonsense(bad):
    with pytest.raises(ValueError):
        parse_duration(bad)


# --- window planning -------------------------------------------------------


def test_plan_puts_the_guard_only_after_the_change():
    plan = plan_comparison(CHANGE_AT, 2 * HOUR, guard=180,
                           now=CHANGE_AT + 10 * HOUR)
    # `before` ends exactly at the change; nothing is discarded on that side.
    assert plan['before'] == Window(CHANGE_AT - 2 * HOUR, CHANGE_AT)
    assert plan['after'] == Window(CHANGE_AT + 180, CHANGE_AT + 180 + 2 * HOUR)


def test_control_days_shift_both_windows_by_whole_days():
    plan = plan_comparison(CHANGE_AT, HOUR, guard=0, control_days=2,
                           now=CHANGE_AT + 10 * HOUR)
    assert [c['day'] for c in plan['controls']] == [1, 2]
    for control in plan['controls']:
        shift = control['day'] * 86400
        assert control['before'] == Window(plan['before'].start - shift,
                                           plan['before'].end - shift)
        assert control['after'] == Window(plan['after'].start - shift,
                                          plan['after'].end - shift)
        # Same clock position is the entire point of a control day.
        assert control['after'].width == plan['after'].width


def test_plan_refuses_an_after_window_that_has_not_happened_yet():
    # A half-filled "after" window is the most flattering possible artefact,
    # so this must fail loudly rather than return short data.
    with pytest.raises(ValueError, match='not yet'):
        plan_comparison(CHANGE_AT, 2 * HOUR, guard=0, now=CHANGE_AT + HOUR)


def test_plan_lag_margin_is_enforced():
    with pytest.raises(ValueError):
        plan_comparison(CHANGE_AT, HOUR, guard=0, lag=300,
                        now=CHANGE_AT + HOUR + 100)
    plan = plan_comparison(CHANGE_AT, HOUR, guard=0, lag=300,
                           now=CHANGE_AT + HOUR + 400)
    assert plan['after'].end == CHANGE_AT + HOUR


def test_plan_labels_cover_every_window():
    plan = plan_comparison(CHANGE_AT, HOUR, control_days=2,
                           now=CHANGE_AT + 10 * HOUR)
    labels = dict(plan_labels(plan))
    assert set(labels) == {
        'before', 'after',
        'control-1d-before', 'control-1d-after',
        'control-2d-before', 'control-2d-after',
    }


# --- segmentation ----------------------------------------------------------


def test_crawler_segment_names_known_crawlers():
    name, category, verified = crawler_segment(row(ua=GOOGLEBOT))
    assert name == 'Googlebot'
    assert category == 'search'
    assert verified is None          # no verifier supplied


def test_crawler_segment_falls_back_to_human_for_browsers():
    name, category, _ = crawler_segment(row())
    assert (name, category) == (SEGMENT_HUMAN, 'human')


def test_unverifiable_is_not_the_same_as_failed_verification():
    class NeverKnows:
        def verify(self, sources, ip):
            return None

    _name, _cat, verified = crawler_segment(row(ua=GOOGLEBOT), NeverKnows())
    assert verified is None

    class Rejects:
        def verify(self, sources, ip):
            return False

    _name, _cat, verified = crawler_segment(row(ua=GOOGLEBOT), Rejects())
    assert verified is False


def test_field_segment_splits_on_any_log_field():
    segment = field_segment('Host')
    assert segment(row(host='a.example.com'))[0] == 'a.example.com'
    assert segment({'Host': '"-"'})[0] == '(unset)'


# --- aggregation -----------------------------------------------------------


def aggregate(rows, *, window=Window(0, HOUR), **kwargs):
    agg = WindowAggregator('w', window, **kwargs)
    for r in rows:
        agg.feed(r)
    return agg.result()


def test_rates_are_normalised_per_hour():
    result = aggregate([row(sent=500)] * 60, window=Window(0, 2 * HOUR))
    assert result['rows'] == 60
    assert result['bytes'] == 30_000
    assert result['requests_per_hour'] == 30.0
    assert result['bytes_per_hour'] == 15_000.0


def test_segment_shares_and_averages():
    rows = [row(ua=GOOGLEBOT, sent=2000)] * 3 + [row(sent=1000)] * 1
    result = aggregate(rows)
    bot = result['segments']['Googlebot']
    assert bot['requests'] == 3
    assert bot['bytes'] == 6000
    assert bot['avg_bytes'] == 2000
    assert bot['request_share'] == pytest.approx(0.75)
    assert bot['byte_share'] == pytest.approx(6000 / 7000)


def test_status_bytes_are_tracked_per_class():
    rows = [row(ua=GOOGLEBOT, status=200, sent=100_000),
            row(ua=GOOGLEBOT, status=404, sent=300)]
    bot = aggregate(rows)['segments']['Googlebot']
    assert bot['status'] == {'2xx': 1, '4xx': 1}
    assert bot['status_bytes'] == {'2xx': 100_000, '4xx': 300}


def test_focus_url_matches_by_substring_and_splits_by_segment():
    target = '/media/mageplaza/search/default_0_history.js'
    rows = [
        row(ua=GOOGLEBOT, url=target, status=200, sent=120_000),
        row(ua=GOOGLEBOT, url=target, status=200, sent=120_000),
        row(url=target, status=200, sent=120_000),
        row(url='/elsewhere.js', sent=999),
    ]
    focus = aggregate(rows, focus_url=target)['focus']
    assert focus['requests'] == 3
    assert focus['bytes'] == 360_000
    assert focus['by_segment']['Googlebot']['requests'] == 2
    assert focus['by_segment'][SEGMENT_HUMAN]['requests'] == 1
    assert [m['url'] for m in focus['matched_urls']] == [target]


def test_url_tables_cap_by_bytes_and_flag_it():
    agg = WindowAggregator('w', Window(0, HOUR), max_tracked_urls=3)
    for i in range(10):
        agg.feed(row(ua=GOOGLEBOT, url=f'/a{i}.js', sent=100 * i))
    result = agg.result()
    # Totals stay exact even though the URL list was capped.
    assert result['segments']['Googlebot']['requests'] == 10
    assert result['caps'].get('segment_urls') is True


# --- comparison ------------------------------------------------------------


def test_delta_refuses_to_invent_a_percentage_from_zero():
    assert delta(0, 50) == {'before': 0, 'after': 50, 'abs': 50,
                            'pct': None, 'ratio': None}
    assert delta(100, 50)['pct'] == pytest.approx(-0.5)
    assert delta(100, 50)['ratio'] == pytest.approx(0.5)


def test_compare_keeps_a_segment_that_vanished():
    before = aggregate([row(ua=GOOGLEBOT, sent=5000)])
    after = aggregate([row(sent=5000)])
    comparison = compare_windows(before, after)
    names = {r['segment'] for r in comparison['segments']}
    assert 'Googlebot' in names
    bot = next(r for r in comparison['segments'] if r['segment'] == 'Googlebot')
    assert bot['after']['bytes'] == 0
    assert bot['delta']['bytes_per_hour']['pct'] == pytest.approx(-1.0)


def test_compare_sorts_by_the_larger_side_so_collapses_stay_visible():
    before = aggregate([row(ua=GOOGLEBOT, sent=100_000)] * 10
                       + [row(sent=100)] * 5)
    after = aggregate([row(ua=GOOGLEBOT, sent=100)] * 10
                      + [row(sent=100)] * 5)
    comparison = compare_windows(before, after)
    assert comparison['segments'][0]['segment'] == 'Googlebot'


# --- attribution -----------------------------------------------------------


def test_geometric_mean_cancels_opposite_ratios():
    assert geometric_mean([0.5, 2.0]) == pytest.approx(1.0)
    assert geometric_mean([2, 8]) == pytest.approx(4.0)
    assert geometric_mean([]) is None
    assert geometric_mean([0, -1]) is None


def test_attribution_subtracts_what_the_control_days_did():
    # Treatment halved. Control days were flat, so the halving is the change.
    out = attribute_change((100.0, 50.0), [(200.0, 200.0), (120.0, 120.0)])
    assert out['expected_ratio'] == pytest.approx(1.0)
    assert out['expected_after'] == pytest.approx(100.0)
    assert out['attributable_abs'] == pytest.approx(-50.0)
    assert out['attributable_pct'] == pytest.approx(-0.5)
    assert out['outside_control_range'] is True


def test_attribution_discounts_a_drop_the_control_days_also_had():
    # Everything halved that day, change or no change: nothing attributable.
    out = attribute_change((100.0, 50.0), [(200.0, 100.0), (80.0, 40.0)])
    assert out['expected_ratio'] == pytest.approx(0.5)
    assert out['expected_after'] == pytest.approx(50.0)
    assert out['attributable_abs'] == pytest.approx(0.0)
    assert out['adjusted_ratio'] == pytest.approx(1.0)
    assert out['outside_control_range'] is False


def test_attribution_without_controls_claims_nothing():
    out = attribute_change((100.0, 50.0), [])
    assert out['observed']['pct'] == pytest.approx(-0.5)
    assert out['expected_ratio'] is None
    assert out['attributable_abs'] is None
    assert out['outside_control_range'] is None


def test_attribution_ignores_a_control_day_with_no_baseline():
    out = attribute_change((100.0, 50.0), [(0.0, 10.0), (100.0, 100.0)])
    assert out['control_ratios'] == [1.0]
    assert out['expected_ratio'] == pytest.approx(1.0)


def test_attribute_segment_reads_a_planned_run():
    def window(label, bot_bytes, hours=1.0):
        return {
            'label': label, 'hours': hours,
            'segments': {'Googlebot': {'bytes_per_hour': bot_bytes}},
        }

    windows = {
        'before': window('before', 1000.0),
        'after': window('after', 100.0),
        'control-1d-before': window('c1b', 1000.0),
        'control-1d-after': window('c1a', 900.0),
    }
    out = attribute_segment('Googlebot', 'bytes_per_hour', windows)
    assert out['control_ratios'] == [pytest.approx(0.9)]
    assert out['expected_after'] == pytest.approx(900.0)
    assert out['attributable_abs'] == pytest.approx(-800.0)


def test_absent_segment_in_a_collected_window_counts_as_zero():
    windows = {
        'before': {'segments': {'Googlebot': {'bytes_per_hour': 500.0}}},
        'after': {'segments': {}},
    }
    out = attribute_segment('Googlebot', 'bytes_per_hour', windows)
    assert out['observed']['after'] == 0.0
    assert out['observed']['pct'] == pytest.approx(-1.0)


# --- collection ------------------------------------------------------------


class FakeSource:
    """Stands in for `LogSource` — counts and pages from a fixed row list."""

    def __init__(self, rows):
        self.rows = rows

    def count(self, window):
        return len(self.rows)

    def page(self, window, page):
        return self.rows if page == 1 else []


def test_collect_window_writes_a_marker_and_is_skipped_on_rerun(tmp_path):
    from app.logpull.store import PullStore

    store = PullStore(str(tmp_path), 'compare/run-1')
    source = FakeSource([row(sent=10), row(sent=20)])

    first = collect_window(source, store, 'before', Window(0, HOUR))
    assert first['rows'] == 2
    assert first['reused'] is False
    assert store.is_day_done('before')

    second = collect_window(source, store, 'before', Window(0, HOUR))
    assert second['reused'] is True

    rows = list(store.iter_rows(dates={'before'}))
    assert [r['BytesSent'] for r in rows] == [10, 20]


def test_collect_window_force_recollects(tmp_path):
    from app.logpull.store import PullStore

    store = PullStore(str(tmp_path), 'compare/run-2')
    collect_window(FakeSource([row()]), store, 'after', Window(0, HOUR))
    again = collect_window(FakeSource([row(), row()]), store, 'after',
                           Window(0, HOUR), force=True)
    assert again['rows'] == 2
    assert again['reused'] is False


# --- timeline --------------------------------------------------------------


def timeline_store(tmp_path, rows_by_label):
    from app.logpull.store import PullStore

    store = PullStore(str(tmp_path), 'compare/timeline')
    for label, rows in rows_by_label.items():
        writer = store.open_day(label)
        writer.write(rows)
        writer.close()
        store.mark_day_done(label, {'label': label, 'rows': len(rows)})
    return store


def at(seconds, **kwargs):
    # EpochTime arrives as a quoted millisecond string; the timeline has to
    # parse it the same way the rest of the package does.
    return dict(row(**kwargs), EpochTime=f'"{seconds * 1000}"')


def test_timeline_buckets_and_splits_highlighted_segments(tmp_path):
    from app.logpull.compare import timeline

    store = timeline_store(tmp_path, {
        'before': [at(0, ua=GOOGLEBOT, sent=100), at(59, sent=7)],
        'after': [at(600, ua=GOOGLEBOT, sent=1), at(601, sent=5)],
    })
    data = timeline(store, ('before', 'after'), bucket=600,
                    highlight=['Googlebot'])
    assert [b['start'] for b in data['bins']] == [0, 600]
    first, second = data['bins']
    assert first['groups']['Googlebot'] == {
        'requests': 1, 'bytes': 100, 'focus_requests': 0, 'focus_bytes': 0}
    assert first['groups']['rest']['bytes'] == 7
    assert second['groups']['Googlebot']['bytes'] == 1


def test_timeline_tracks_the_focus_url_separately(tmp_path):
    from app.logpull.compare import timeline

    target = '/big.js'
    store = timeline_store(tmp_path, {
        'before': [at(0, ua=GOOGLEBOT, url=target, sent=1000),
                   at(1, ua=GOOGLEBOT, url='/small.js', sent=10)],
        'after': [at(600, ua=GOOGLEBOT, url=target, status=404, sent=138)],
    })
    data = timeline(store, ('before', 'after'), bucket=600,
                    focus_url=target, highlight=['Googlebot'])
    before, after = data['bins']
    assert before['focus_requests'] == 1
    assert before['focus_bytes'] == 1000
    assert before['groups']['Googlebot']['focus_bytes'] == 1000
    # The non-focus request is in `requests` but not in `focus_requests`.
    assert before['requests'] == 2
    assert after['focus_status'] == {'4xx': 1}


def test_timeline_omits_empty_buckets_rather_than_zero_filling(tmp_path):
    from app.logpull.compare import timeline

    store = timeline_store(tmp_path, {
        'before': [at(0, sent=1)],
        'after': [at(1800, sent=1)],
    })
    data = timeline(store, ('before', 'after'), bucket=600)
    # A gap in collection and a quiet bucket are different facts.
    assert [b['start'] for b in data['bins']] == [0, 1800]


def test_timeline_skips_rows_with_an_unparseable_timestamp(tmp_path):
    from app.logpull.compare import timeline

    store = timeline_store(tmp_path, {
        'before': [at(0, sent=1), dict(row(sent=99), EpochTime='"-"')],
    })
    data = timeline(store, ('before',), bucket=600)
    assert len(data['bins']) == 1
    assert data['bins'][0]['requests'] == 1


def test_math_module_is_used_for_geometric_mean_not_a_float_product():
    # Guards against reintroducing a naive product, which underflows on the
    # long control runs this is meant to survive.
    assert geometric_mean([1e-200, 1e-200]) == pytest.approx(1e-200)
    assert not math.isnan(geometric_mean([1e-200, 1e200]))
