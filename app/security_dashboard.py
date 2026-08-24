"""Per-app security dashboard aggregation.

Pure function over already-fetched WAF log entries — no network calls here.
Mirrors the grouping approach used by logs.fp_analysis() and
main.dashboard_chart_data(), factored out since this is now a third call site.
"""
from collections import Counter
from datetime import datetime, timedelta

# quick_range -> (number of buckets, seconds per bucket)
BUCKET_CONFIG = {
    'r_1h': (12, 5 * 60),
    'r_24h': (24, 60 * 60),
    'r_7d': (28, 6 * 60 * 60),
    'r_14d': (28, 12 * 60 * 60),
    'r_30d': (30, 24 * 60 * 60),
    'r_45d': (45, 24 * 60 * 60),
    'r_60d': (60, 24 * 60 * 60),
}
DEFAULT_BUCKETS = (24, 60 * 60)

TOP_N = 5


def _bucket_label_format(bucket_seconds):
    if bucket_seconds < 60 * 60:
        return '%H:%M'
    if bucket_seconds < 24 * 60 * 60:
        return '%m-%d %H:00'
    return '%m-%d'


def _rule_key(entry):
    rule_id = entry.get('RuleID') or 'unknown'
    attack = entry.get('Attack') or entry.get('AttackType') or rule_id
    if rule_id != 'unknown':
        return f'{attack} (#{rule_id})'
    return attack


def aggregate_waf_logs(logs, quick_range, total_from_api=None, now=None):
    """Aggregate a list of WAF log entries (as returned by WaasClient.get_logs)
    into dashboard summary data: headline counters, a bucketed timeline for the
    trend sparkline, and top-5 rules/IPs/URLs.

    now: injectable for tests; defaults to the current UTC time.
    """
    now = now or datetime.utcnow()
    num_buckets, bucket_seconds = BUCKET_CONFIG.get(quick_range, DEFAULT_BUCKETS)
    window_start = now - timedelta(seconds=num_buckets * bucket_seconds)
    bucket_counts = [0] * num_buckets
    bucket_starts = [window_start + timedelta(seconds=i * bucket_seconds) for i in range(num_buckets)]

    blocked_count = 0
    ip_counter = Counter()
    url_counter = Counter()
    rule_counter = Counter()

    for entry in logs:
        if entry.get('Action') == 'DENY':
            blocked_count += 1

        ip = entry.get('ClientIP')
        if ip:
            ip_counter[ip] += 1

        url = entry.get('URL')
        if url:
            url_counter[url] += 1

        rule_counter[_rule_key(entry)] += 1

        ts = entry.get('EpochTime')
        if not ts:
            continue
        try:
            entry_time = datetime.utcfromtimestamp(int(ts) / 1000.0)
        except (ValueError, TypeError, OSError):
            continue
        if entry_time < window_start:
            continue
        idx = int((entry_time - window_start).total_seconds() // bucket_seconds)
        if 0 <= idx < num_buckets:
            bucket_counts[idx] += 1

    label_fmt = _bucket_label_format(bucket_seconds)
    timeline = [
        {'bucket_label': bucket_starts[i].strftime(label_fmt), 'count': bucket_counts[i]}
        for i in range(num_buckets)
    ]

    def top_n(counter):
        return [{'key': key, 'count': count} for key, count in counter.most_common(TOP_N)]

    total_events = len(logs)

    return {
        'total_events': total_events,
        'total_from_api': total_from_api if total_from_api is not None else total_events,
        'blocked_count': blocked_count,
        'unique_ip_count': len(ip_counter),
        'unique_rule_count': len(rule_counter),
        'timeline': timeline,
        'top_rules': top_n(rule_counter),
        'top_ips': top_n(ip_counter),
        'top_urls': top_n(url_counter),
        'truncated': bool(total_from_api) and total_from_api > total_events,
    }
