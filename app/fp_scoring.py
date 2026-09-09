"""
Heuristic scoring for WAF false-positive analysis groups.

Pure functions only — no network calls. Operates on the group dicts built by
`app.routes.logs.fp_analysis()` (keys: count, deny_count, log_count,
unique_ip_count, unique_url_count, owasp_risk_score, ...).

`fn_flag` is a proxy for "this application may be under-protected," not a
true false-negative detector — a real false negative (an attack the WAF
never logged at all) leaves no data for us to score.
"""

from collections import Counter

MIN_SAMPLE_SIZE = 5


def _parse_risk_score(value):
    """Coerce owasp_risk_score (may be '—', None, str, int) to an int or None."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if not text or text == '—':
        return None
    try:
        return int(float(text))
    except ValueError:
        return None


def score_group(group):
    """Score one fp_analysis attack group for false-positive confidence and
    a false-negative-exposure proxy flag.

    Returns a dict with fp_confidence (0-100), fp_flag (bool), fp_reasons
    (list of str), fn_flag (bool), fn_reasons (list of str).
    """
    count = group.get('count', 0) or 0
    unique_ip_count = group.get('unique_ip_count', 0) or 0
    unique_url_count = group.get('unique_url_count', 0) or 0
    deny_count = group.get('deny_count', 0) or 0
    log_count = group.get('log_count', 0) or 0
    risk_score = _parse_risk_score(group.get('owasp_risk_score'))

    confidence = 0
    reasons = []

    if risk_score is not None:
        if risk_score <= 20:
            confidence += 30
            reasons.append(f'Low OWASP risk score ({risk_score})')
        elif risk_score <= 50:
            confidence += 15
            reasons.append(f'Moderate OWASP risk score ({risk_score})')

    if count >= MIN_SAMPLE_SIZE:
        ip_ratio = unique_ip_count / count
        if ip_ratio >= 0.5:
            confidence += 30
            reasons.append(
                f'Wide IP spread ({unique_ip_count} unique IPs across {count} events) '
                '— looks like distinct legitimate users rather than a targeted attack'
            )
        elif ip_ratio >= 0.25:
            confidence += 15
            reasons.append(f'Moderate IP spread ({unique_ip_count} unique IPs across {count} events)')

        url_ratio = unique_url_count / count
        if url_ratio >= 0.5:
            confidence += 20
            reasons.append(
                f'Wide URL spread ({unique_url_count} unique URLs) '
                '— rule may be matching generic legitimate content'
            )
        elif url_ratio >= 0.25:
            confidence += 10
            reasons.append(f'Moderate URL spread ({unique_url_count} unique URLs)')

    if count >= 3 and log_count == count:
        confidence += 10
        reasons.append('All events are LOG-only (not blocked)')

    confidence = min(100, confidence)

    fn_flag = False
    fn_reasons = []
    if (
        risk_score is not None and risk_score >= 70
        and deny_count == 0 and log_count > 0
        and count >= MIN_SAMPLE_SIZE
    ):
        fn_flag = True
        fn_reasons.append(
            f'High-risk rule (score {risk_score}) fired {count} times but was never blocked '
            '(Action=LOG only) — this application may be under-protected against this attack type'
        )

    return {
        'fp_confidence': confidence,
        'fp_flag': confidence >= 50,
        'fp_reasons': reasons,
        'fn_flag': fn_flag,
        'fn_reasons': fn_reasons,
    }


def group_waf_logs(logs):
    """Group WAF log entries by AttackType+RuleID and score each group.

    Shared by logs.fp_analysis() and config_advisor.advise() so both work
    from the same grouping/scoring logic. Returns an unsorted list of group
    dicts (count, deny_count, log_count, unique_ip_count, unique_url_count,
    samples, top_sample_url, plus score_group()'s
    fp_confidence/fp_reasons/fn_flag/fn_reasons).
    """
    attack_groups = {}
    for entry in logs or []:
        attack_type = entry.get('AttackType', entry.get('Attack', 'Unknown'))
        rule_id = entry.get('RuleID', 'unknown')
        group_key = f'{attack_type}|{rule_id}'

        if group_key not in attack_groups:
            attack_groups[group_key] = {
                'attack_type': attack_type,
                'attack_name': entry.get('Attack', attack_type),
                'attack_group': entry.get('AttackGroup', '—'),
                'rule_id': rule_id,
                'rule_type': entry.get('RuleType', '—'),
                'owasp': entry.get('owasp', '—'),
                'cwe': entry.get('cwe', '—'),
                'owasp_api': entry.get('owasp_api_top_ten', '—'),
                'owasp_risk_score': entry.get('owasp_risk_score', '—'),
                'count': 0,
                'deny_count': 0,
                'log_count': 0,
                'samples': [],
                'unique_ips': set(),
                'unique_urls': set(),
                'url_counts': Counter(),
            }

        group = attack_groups[group_key]
        group['count'] += 1
        action = entry.get('Action', '')
        if action == 'DENY':
            group['deny_count'] += 1
        else:
            group['log_count'] += 1
        if len(group['samples']) < 5:
            group['samples'].append(entry)
        group['unique_ips'].add(entry.get('ClientIP', 'unknown'))
        url = entry.get('URL', 'unknown')
        group['unique_urls'].add(url)
        group['url_counts'][url] += 1

    groups = list(attack_groups.values())
    for group in groups:
        group['unique_ip_count'] = len(group['unique_ips'])
        group['unique_url_count'] = len(group['unique_urls'])
        top_urls = group['url_counts'].most_common(1)
        group['top_sample_url'] = top_urls[0][0] if top_urls else None
        del group['unique_ips']
        del group['unique_urls']
        del group['url_counts']
        group.update(score_group(group))

    return groups
