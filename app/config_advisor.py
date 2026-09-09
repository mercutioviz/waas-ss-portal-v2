"""
Config-vs-traffic recommendation engine.

Pure functions only — no network calls. Mirrors the profiler's `_field()`
rationale pattern (app/profiler/recommender.py) but applied to a *live*
account's current security config + observed traffic instead of a
pre-onboarding probe.

Note on request limits: the WaaS `request_limits` section only exposes
length caps (max_request_length, max_url_length, ...) — there is no
requests/sec rate threshold on this API. The traffic-vs-config heuristic
below compares max_url_length against the longest URL actually observed
in traffic, which is the honest length-based analogue available today.
"""
from app.fp_scoring import _parse_risk_score

HIGH_RISK_THRESHOLD = 60
FP_LOW_CONFIDENCE_THRESHOLD = 30
MIN_GROUP_SAMPLE = 5


def compute_traffic_stats(access_logs):
    """Summarize access-log (LogType=TR) entries for use by advise().

    Caller is responsible for fetching the logs and filtering to access
    entries — this is a pure aggregation step.
    """
    access_logs = access_logs or []
    urls = [e.get('URL', '') for e in access_logs if e.get('URL')]
    unique_ips = {e.get('ClientIP') for e in access_logs if e.get('ClientIP')}

    return {
        'total_requests': len(access_logs),
        'unique_ip_count': len(unique_ips),
        'max_url_length_observed': max((len(u) for u in urls), default=0),
    }


def _recommendation(field, current_value, suggested_value, rationale, severity):
    return {
        'field': field,
        'current_value': current_value,
        'suggested_value': suggested_value,
        'rationale': rationale,
        'severity': severity,
    }


def _advise_protection_mode(security_config, fp_groups):
    protection_mode = security_config.get('protection_mode', security_config.get('mode'))
    if protection_mode != 'Passive':
        return None

    risky_low_fp = [
        g for g in (fp_groups or [])
        if g.get('count', 0) >= MIN_GROUP_SAMPLE
        and (_parse_risk_score(g.get('owasp_risk_score')) or 0) >= HIGH_RISK_THRESHOLD
        and g.get('fp_confidence', 0) <= FP_LOW_CONFIDENCE_THRESHOLD
    ]
    if not risky_low_fp:
        return None

    names = ', '.join(g.get('attack_name', g.get('attack_type', 'unknown')) for g in risky_low_fp[:5])
    return _recommendation(
        'protection_mode', 'Passive', 'Active',
        f'{len(risky_low_fp)} high-risk attack group(s) ({names}) are firing repeatedly with low '
        'false-positive confidence, but the app is in Passive mode so nothing is actually blocked. '
        'Switch to Active once you have reviewed these groups.',
        'warning',
    )


def _advise_max_url_length(security_config, traffic_stats):
    request_limits = security_config.get('request_limits', {}) or {}
    observed_max = (traffic_stats or {}).get('max_url_length_observed')
    try:
        max_url_length = int(request_limits.get('max_url_length'))
    except (TypeError, ValueError):
        return None
    if not observed_max:
        return None

    if observed_max > max_url_length:
        return _recommendation(
            'request_limits.max_url_length', max_url_length, observed_max,
            f'Observed traffic includes a URL {observed_max} characters long, longer than the '
            f'configured Max URL Length ({max_url_length}). Legitimate requests may be getting '
            'rejected — raise the limit, or confirm the long URLs are not themselves suspicious.',
            'warning',
        )
    if max_url_length > observed_max * 4 and max_url_length > 2048:
        return _recommendation(
            'request_limits.max_url_length', max_url_length, observed_max,
            f'Configured Max URL Length ({max_url_length}) is far larger than the longest URL '
            f'actually seen in traffic ({observed_max} characters). Tightening this reduces the '
            'attack surface for URL-based overflow attempts without affecting real users.',
            'info',
        )
    return None


def _advise_clickjacking(security_config, site_profile_signal):
    clickjacking = security_config.get('clickjacking_protection', {}) or {}
    if clickjacking.get('enable_clickjack_prevention') is not False:
        return None

    has_client_side = bool((site_profile_signal or {}).get('x_frame_options_present'))
    if has_client_side:
        rationale = (
            'Clickjacking protection is disabled at the WAF. The origin already sends '
            'X-Frame-Options (per the most recent site profile), so this is defense-in-depth '
            'rather than a gap.'
        )
        severity = 'info'
    else:
        rationale = (
            'Clickjacking protection is disabled at the WAF and no X-Frame-Options header was '
            'seen from the origin — pages can be framed by third-party sites.'
        )
        severity = 'warning'

    return _recommendation(
        'clickjacking_protection.enable_clickjack_prevention', False, True, rationale, severity,
    )


def _advise_data_theft(security_config):
    data_theft = security_config.get('data_theft_protection', {}) or {}
    if data_theft.get('enabled') is not False:
        return None

    return _recommendation(
        'data_theft_protection.enabled', False, True,
        'Data theft protection is disabled — the WAF will not mask credit-card or SSN-shaped '
        'patterns that leak into responses. Enable unless this application never returns that '
        'kind of data.',
        'info',
    )


def advise(security_config, fp_groups=None, traffic_stats=None, site_profile_signal=None):
    """Return a list of recommendation dicts for the security_config view.

    security_config: dict as returned by WaasClient.get_security_config()
    fp_groups: scored fp_analysis groups (see app.fp_scoring.score_group)
    traffic_stats: dict as returned by compute_traffic_stats()
    site_profile_signal: optional dict derived from a matching SiteProfile,
        e.g. {'x_frame_options_present': bool}
    """
    security_config = security_config or {}
    checks = (
        _advise_protection_mode(security_config, fp_groups),
        _advise_max_url_length(security_config, traffic_stats),
        _advise_clickjacking(security_config, site_profile_signal),
        _advise_data_theft(security_config),
    )
    return [c for c in checks if c]
