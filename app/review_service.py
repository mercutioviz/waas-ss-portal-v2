"""Pure aggregation layer for the Account/Config Review report (Phase 6).

Combines Phases 1-4's outputs (FP/FN scoring, config-vs-traffic
recommendations, trend history, baseline comparison) into a single
synthesis dict. No WaasClient or DB access happens here -- callers
(app/routes/review.py) do all fetching and pass plain dicts/lists in, so
this module is testable with synthetic data alone.
"""
from app.config_advisor import advise

REQUEST_LIMIT_KEYS = [
    'max_request_length', 'max_request_line_length', 'max_url_length',
    'max_number_of_headers', 'max_header_value_length',
    'max_cookie_name_length', 'max_cookie_value_length',
]

FP_LIKELY_THRESHOLD = 70
FP_POSSIBLE_THRESHOLD = 40


def _summarize_config(security_config):
    security_config = security_config or {}
    clickjacking = security_config.get('clickjacking_protection', {}) or {}
    data_theft = security_config.get('data_theft_protection', {}) or {}
    return {
        'protection_mode': security_config.get('protection_mode', security_config.get('mode')),
        'clickjacking_enabled': bool(clickjacking.get('enable_clickjack_prevention')),
        'data_theft_enabled': bool(data_theft.get('enabled')),
    }


def _summarize_fp(fp_groups):
    fp_groups = fp_groups or []
    likely_fp = [g for g in fp_groups if g.get('fp_confidence', 0) >= FP_LIKELY_THRESHOLD]
    possible_fp = [g for g in fp_groups if FP_POSSIBLE_THRESHOLD <= g.get('fp_confidence', 0) < FP_LIKELY_THRESHOLD]
    gaps = [g for g in fp_groups if g.get('fn_flag')]
    return {
        'total_groups': len(fp_groups),
        'likely_fp_count': len(likely_fp),
        'possible_fp_count': len(possible_fp),
        'possible_gap_count': len(gaps),
        'top_likely_fp': sorted(likely_fp, key=lambda g: g.get('fp_confidence', 0), reverse=True)[:5],
        'top_gaps': sorted(gaps, key=lambda g: g.get('count', 0), reverse=True)[:5],
    }


def _summarize_history(snapshots):
    """snapshots: list of plain dicts (id, resource_type, resource_label,
    created_at, is_reverted), most-recent-first."""
    snapshots = snapshots or []
    return {
        'total_count': len(snapshots),
        'recent': snapshots[:10],
    }


def _summarize_trend(metric_snapshots):
    """metric_snapshots: list of plain dicts (e.g. SecurityMetricSnapshot.to_dict()),
    ordered oldest-first. Returns None if there's no history yet."""
    metric_snapshots = metric_snapshots or []
    if not metric_snapshots:
        return None

    first, last = metric_snapshots[0], metric_snapshots[-1]
    return {
        'sample_count': len(metric_snapshots),
        'first_captured_at': first.get('captured_at'),
        'last_captured_at': last.get('captured_at'),
        'latest_blocked_count': last.get('blocked_count', 0),
        'latest_unique_ip_count': last.get('unique_ip_count', 0),
        'blocked_count_delta': last.get('blocked_count', 0) - first.get('blocked_count', 0),
    }


def _diff_section(field_prefix, live, baseline):
    live = live or {}
    baseline = baseline or {}
    gaps = []
    for key in sorted(set(live) | set(baseline)):
        live_value = live.get(key)
        baseline_value = baseline.get(key)
        if live_value != baseline_value:
            gaps.append({
                'field': f'{field_prefix}.{key}',
                'live_value': live_value,
                'baseline_value': baseline_value,
            })
    return gaps


def _summarize_baseline(security_config, baseline):
    """baseline: {'name': str, 'config': dict} -- the same partial-dict shape
    ConfigTemplate.config_dict/get_security_config() both share. Returns None
    if no baseline was selected."""
    if not baseline:
        return None

    live = security_config or {}
    base_cfg = baseline.get('config') or {}
    gaps = []

    live_mode = live.get('protection_mode')
    base_mode = base_cfg.get('protection_mode')
    if live_mode != base_mode:
        gaps.append({'field': 'protection_mode', 'live_value': live_mode, 'baseline_value': base_mode})

    for key in REQUEST_LIMIT_KEYS:
        live_value = (live.get('request_limits') or {}).get(key)
        base_value = (base_cfg.get('request_limits') or {}).get(key)
        if live_value != base_value:
            gaps.append({'field': f'request_limits.{key}', 'live_value': live_value, 'baseline_value': base_value})

    gaps.extend(_diff_section('clickjacking_protection', live.get('clickjacking_protection'), base_cfg.get('clickjacking_protection')))
    gaps.extend(_diff_section('data_theft_protection', live.get('data_theft_protection'), base_cfg.get('data_theft_protection')))

    return {
        'name': baseline.get('name'),
        'gap_count': len(gaps),
        'gaps': gaps,
    }


def build_review(security_config, fp_groups=None, traffic_stats=None, site_profile_signal=None,
                  snapshots=None, metric_snapshots=None, baseline=None):
    """Synthesize everything into the review report's data model.

    Every argument is a plain dict/list (or None) -- no ORM objects, no
    WaasClient. Callers are responsible for fetching and shaping the data.
    """
    return {
        'config_summary': _summarize_config(security_config),
        'fp_summary': _summarize_fp(fp_groups),
        'recommendations': advise(security_config, fp_groups, traffic_stats, site_profile_signal),
        'history_summary': _summarize_history(snapshots),
        'trend_summary': _summarize_trend(metric_snapshots),
        'baseline_summary': _summarize_baseline(security_config, baseline),
    }
