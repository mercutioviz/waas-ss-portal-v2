"""Tests for custom collection ranges on the ordinary pull form.

Until this landed, every pull was "the last 7 or 30 days, ending now"
(`ALLOWED_WINDOW_DAYS`, `_range_for`). The engine underneath was always
range-agnostic — `LogPull.range_start/range_end` are arbitrary epochs and
`plan_days` clips partial days at both ends — so what is tested here is the
validation layer, which is the only thing standing between a user and a
window that cannot honestly be collected.
"""
from datetime import datetime, timezone

import pytest

from app.models import LogPull
from app.routes.traffic import (
    INGEST_LAG_SECONDS,
    MAX_CUSTOM_SPAN_DAYS,
    RangeError,
    _custom_range,
    _parse_instant,
    _resolve_range,
)

#: Minute-aligned on purpose: the form's `datetime-local` inputs carry
#: `step="60"`, so a round trip through the browser cannot preserve seconds.
NOW = 1_791_320_040
HOUR = 3600


def now_dt():
    return datetime.fromtimestamp(NOW, tz=timezone.utc)


def iso(epoch):
    """A naive ISO string, the way a `datetime-local` input submits one."""
    return (datetime.fromtimestamp(epoch, tz=timezone.utc)
            .strftime('%Y-%m-%dT%H:%M'))


# --- instant parsing -------------------------------------------------------


def test_naive_input_is_read_as_utc():
    # The browser submits datetime-local with no zone. Reading it as server
    # local time would silently shift every custom range by the host offset.
    assert _parse_instant('2026-10-06T17:17') == int(
        datetime(2026, 10, 6, 17, 17, tzinfo=timezone.utc).timestamp())


def test_explicit_zone_is_respected():
    assert _parse_instant('2026-10-06T17:17:00Z') == _parse_instant(
        '2026-10-06T17:17')


@pytest.mark.parametrize('bad', ['', '   ', 'yesterday', '2026-13-45T99:99'])
def test_unparseable_instants_are_refused(bad):
    with pytest.raises(RangeError):
        _parse_instant(bad)


# --- range validation ------------------------------------------------------


def test_valid_range_round_trips():
    start, end = _custom_range(iso(NOW - 4 * HOUR), iso(NOW - 2 * HOUR),
                               now=now_dt())
    assert (start, end) == (NOW - 4 * HOUR, NOW - 2 * HOUR)


def test_end_before_start_is_refused():
    with pytest.raises(RangeError, match='after the start'):
        _custom_range(iso(NOW - 2 * HOUR), iso(NOW - 4 * HOUR), now=now_dt())


def test_zero_length_range_is_refused():
    with pytest.raises(RangeError, match='after the start'):
        _custom_range(iso(NOW - 2 * HOUR), iso(NOW - 2 * HOUR), now=now_dt())


def test_span_beyond_the_ceiling_is_refused():
    start = NOW - (MAX_CUSTOM_SPAN_DAYS + 1) * 86400
    with pytest.raises(RangeError, match='maximum'):
        _custom_range(iso(start), iso(NOW - 2 * HOUR), now=now_dt())


def test_span_exactly_at_the_ceiling_is_allowed():
    end = NOW - 2 * HOUR
    start = end - MAX_CUSTOM_SPAN_DAYS * 86400
    assert _custom_range(iso(start), iso(end), now=now_dt()) == (start, end)


def test_a_window_still_filling_is_refused():
    # The most flattering possible artefact in a before/after comparison is a
    # half-collected "after" window presented as complete.
    with pytest.raises(RangeError, match='too recent'):
        _custom_range(iso(NOW - HOUR), iso(NOW - INGEST_LAG_SECONDS // 2),
                      now=now_dt())


def test_a_window_just_past_the_lag_is_allowed():
    end = NOW - INGEST_LAG_SECONDS - 60
    start, resolved_end = _custom_range(iso(end - HOUR), iso(end), now=now_dt())
    assert (start, resolved_end) == (end - HOUR, end)


# --- resolver --------------------------------------------------------------


def test_presets_still_end_now():
    start, end, days = _resolve_range({'window_days': '7'}, now=now_dt())
    assert days == 7
    assert end == NOW
    assert end - start == 7 * 86400


@pytest.mark.parametrize('raw', ['', 'nonsense', '3', '365', None])
def test_unknown_presets_fall_back_to_the_default(raw):
    _start, _end, days = _resolve_range({'window_days': raw}, now=now_dt())
    assert days == 7


def test_custom_resolves_and_rounds_window_days_for_the_column():
    # window_days is non-null on the row, so it still has to carry something
    # sane even when the range is not a whole number of days.
    start, end, days = _resolve_range({
        'window_days': 'custom',
        'range_start': iso(NOW - 2 * HOUR - 7200),
        'range_end': iso(NOW - 2 * HOUR),
    }, now=now_dt())
    assert end - start == 2 * HOUR
    assert days == 1            # rounded up from 0.08d, never 0


def test_custom_propagates_its_error():
    with pytest.raises(RangeError):
        _resolve_range({'window_days': 'custom', 'range_start': '',
                        'range_end': ''}, now=now_dt())


# --- display ---------------------------------------------------------------


@pytest.mark.parametrize('span,expected', [
    (7 * 86400, '7d'),
    (30 * 86400, '30d'),
    (2 * HOUR, '2h'),
    (6 * HOUR, '6h'),
    (90 * 60, '1.5h'),
    (45 * 60, '45m'),
    (0, '—'),
])
def test_range_label_describes_the_actual_span(span, expected):
    # Rendering a two-hour window as "0d" — or rounding it to "1d" — would
    # misdescribe every figure measured over it.
    pull = LogPull(range_start=NOW - span, range_end=NOW)
    assert pull.range_label == expected


def test_range_description_carries_the_end_time():
    pull = LogPull(range_start=NOW - 2 * HOUR, range_end=NOW)
    assert pull.range_description.startswith('2h ending ')
    assert pull.range_description.endswith(' UTC')
