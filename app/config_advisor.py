"""
Config-vs-traffic recommendation engine.

Pure functions only — no network calls. Mirrors the profiler's `_field()`
rationale pattern (app/profiler/recommender.py) but applied to a *live*
account's current security config + observed traffic instead of a
pre-onboarding probe.

Note on request limits: the WaaS `request_limits` section only exposes
length caps (max_request_length, max_url_length, ...) — there is no
requests/sec rate threshold on this API. So the traffic-vs-config
heuristics below compare each configured cap against the longest value
actually observed in traffic, which is the honest length-based analogue.

**Truncation matters here.** The logs API caps text fields at 255
characters: on a real 229k-row sample, 219,503 rows had `QueryString` at
exactly 255. Any maximum derived from a truncated field is a *lower
bound*, which supports only one of the two directions:

- "your cap is too tight" stays valid — if an already-truncated sample
  exceeds the cap, the real value exceeds it by even more.
- "your cap is too loose, tighten it" does not — the real maximum may be
  far above what the logs show, and acting on it would start rejecting
  legitimate traffic.

`FIELD_SPECS` therefore declares, per field, which directions its
observation can honestly support. `max_number_of_headers` is absent from
that table on purpose: the access log records no header count, so there
is nothing to compare it against.
"""
from collections import namedtuple

from app.fp_scoring import _parse_risk_score

HIGH_RISK_THRESHOLD = 60
FP_LOW_CONFIDENCE_THRESHOLD = 30
MIN_GROUP_SAMPLE = 5

# The logs API truncates text fields at this length.
LOG_FIELD_TRUNCATION = 255
# Don't advise on request limits from a handful of requests.
MIN_TRAFFIC_SAMPLE = 50
# Cookies are absent from most requests on many apps; gate them separately.
MIN_COOKIE_SAMPLE = 20
# A cap this many times the observed maximum (and above the floor) is loose.
LOOSE_FACTOR = 4
LOOSE_FLOOR = 2048

# Headers the access log actually records. Any "max header value length"
# observation is a lower bound over these four, not over every header sent.
LOGGED_HEADERS = ('UserAgent', 'Referer', 'Cookie', 'Host')


def _unset(value):
    """True if a log field is absent.

    The API renders empty fields as the literal string `"-"` — including
    the surrounding double quotes — so a plain falsiness check isn't
    enough, and `len()` on one of those yields a misleading 3.
    """
    if value is None:
        return True
    return str(value).strip().strip('"').strip() in ('', '-')


def _text(value):
    return '' if _unset(value) else str(value)


def _new_observation():
    return {'max': 0, 'saturated': False, 'sample': 0}


def _observe(observation, length, source_length=None):
    """Record one observed length.

    `source_length` is the length of the raw field the value came from; when
    it has hit the API's truncation cap the recorded maximum is a lower
    bound, and the observation is marked saturated.
    """
    observation['sample'] += 1
    if length > observation['max']:
        observation['max'] = length
    if (source_length if source_length is not None else length) >= LOG_FIELD_TRUNCATION:
        observation['saturated'] = True


def _observe_cookies(entry, name_obs, value_obs):
    raw = _text(entry.get('Cookie'))
    if not raw:
        return
    truncated = len(raw)
    for pair in raw.split(';'):
        pair = pair.strip()
        if not pair:
            continue
        name, _, value = pair.partition('=')
        _observe(name_obs, len(name.strip()), source_length=truncated)
        _observe(value_obs, len(value.strip()), source_length=truncated)


def compute_traffic_stats(access_logs):
    """Summarize access-log (LogType=TR) entries for use by advise().

    Caller is responsible for fetching the logs and filtering to access
    entries — this is a pure aggregation step.

    Returns the original three top-level counters plus an `observed` map of
    per-field maxima. Each entry carries `sample` (how many values backed
    it) and `saturated` (whether the API's 255-character truncation means
    the maximum is only a lower bound). See the module docstring for why
    that flag decides which recommendations are safe to emit.
    """
    access_logs = access_logs or []
    unique_ips = {e.get('ClientIP') for e in access_logs if not _unset(e.get('ClientIP'))}

    observed = {key: _new_observation() for key in (
        'url_length', 'request_line_length', 'header_value_length',
        'cookie_name_length', 'cookie_value_length', 'request_bytes',
    )}

    for entry in access_logs:
        url = _text(entry.get('URL'))
        if url:
            _observe(observed['url_length'], len(url))

        query = _text(entry.get('QueryString'))
        method = _text(entry.get('Method'))
        version = _text(entry.get('Version'))
        if url and method:
            # "GET /path?query HTTP/1.1"
            line_length = len(method) + 1 + len(url) + (1 + len(query) if query else 0)
            if version:
                line_length += 1 + len(version)
            # The query is the only truncated component, so it decides
            # whether this whole measurement is a lower bound.
            _observe(observed['request_line_length'], line_length, source_length=len(query))

        for header in LOGGED_HEADERS:
            value = _text(entry.get(header))
            if value:
                _observe(observed['header_value_length'], len(value))

        _observe_cookies(entry, observed['cookie_name_length'], observed['cookie_value_length'])

        bytes_received = entry.get('BytesReceived')
        if isinstance(bytes_received, int) and not isinstance(bytes_received, bool):
            _observe(observed['request_bytes'], bytes_received, source_length=0)

    return {
        'total_requests': len(access_logs),
        'unique_ip_count': len(unique_ips),
        # Retained as a top-level key for backward compatibility; the same
        # number now also lives in observed['url_length']['max'].
        'max_url_length_observed': observed['url_length']['max'],
        'observed': observed,
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


_FieldSpec = namedtuple(
    '_FieldSpec',
    'config_key observation label unit allow_too_tight allow_too_loose min_sample',
)

# Which directions each observation can honestly support. See the module
# docstring: a truncated field is a lower bound, and a field that
# over-states what it measures is an upper bound. Neither supports both.
#
# `max_number_of_headers` is intentionally missing — the access log records
# no header count, so there is nothing to compare it against.
FIELD_SPECS = (
    # Exact when under the truncation cap, so both directions are usable.
    _FieldSpec('max_url_length', 'url_length', 'URL', 'characters',
               True, True, MIN_TRAFFIC_SAMPLE),
    # Contains the truncated query string → lower bound.
    _FieldSpec('max_request_line_length', 'request_line_length', 'request line', 'characters',
               True, False, MIN_TRAFFIC_SAMPLE),
    # We only see four of the headers actually sent → lower bound.
    _FieldSpec('max_header_value_length', 'header_value_length', 'header value', 'characters',
               True, False, MIN_TRAFFIC_SAMPLE),
    # Parsed out of the truncated Cookie field → lower bound.
    _FieldSpec('max_cookie_name_length', 'cookie_name_length', 'cookie name', 'characters',
               True, False, MIN_COOKIE_SAMPLE),
    _FieldSpec('max_cookie_value_length', 'cookie_value_length', 'cookie value', 'characters',
               True, False, MIN_COOKIE_SAMPLE),
    # BytesReceived counts headers as well as the body, so it over-states
    # the body length this cap applies to → upper bound only.
    _FieldSpec('max_request_length', 'request_bytes', 'request', 'bytes',
               False, True, MIN_TRAFFIC_SAMPLE),
)


def _advise_one_limit(spec, configured, observation):
    observed_max = observation['max']
    sample = observation['sample']
    field = f'request_limits.{spec.config_key}'

    if spec.allow_too_tight and observed_max > configured:
        qualifier = (
            ' (and the log field is truncated at '
            f'{LOG_FIELD_TRUNCATION} {spec.unit}, so the real value is longer still)'
            if observation['saturated'] else ''
        )
        return _recommendation(
            field, configured, observed_max,
            f'Across {sample} observed requests the longest {spec.label} was {observed_max} '
            f'{spec.unit}, above the configured limit of {configured}{qualifier}. Legitimate '
            'requests may be getting rejected — raise the limit, or confirm the oversized '
            'requests are not themselves suspicious.',
            'warning',
        )

    if (spec.allow_too_loose and not observation['saturated']
            and configured > observed_max * LOOSE_FACTOR and configured > LOOSE_FLOOR):
        caveat = (
            ' Note that this is measured from total bytes received, which includes headers, '
            'so the real request bodies are smaller still.'
            if spec.observation == 'request_bytes' else ''
        )
        return _recommendation(
            field, configured, observed_max,
            f'The configured limit ({configured} {spec.unit}) is far above the largest '
            f'{spec.label} seen across {sample} observed requests ({observed_max}). Tightening '
            'it shrinks the overflow attack surface without affecting real '
            f'users.{caveat}',
            'info',
        )

    return None


def _advise_request_limits(security_config, traffic_stats):
    """Compare every checkable request_limits cap against observed traffic."""
    request_limits = security_config.get('request_limits', {}) or {}
    observed_map = (traffic_stats or {}).get('observed') or {}

    recommendations = []
    for spec in FIELD_SPECS:
        observation = observed_map.get(spec.observation)
        if not observation or not observation.get('max'):
            continue
        if observation.get('sample', 0) < spec.min_sample:
            continue
        try:
            configured = int(request_limits.get(spec.config_key))
        except (TypeError, ValueError):
            continue

        recommendation = _advise_one_limit(spec, configured, observation)
        if recommendation:
            recommendations.append(recommendation)

    return recommendations


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
    single_checks = (
        _advise_protection_mode(security_config, fp_groups),
        _advise_clickjacking(security_config, site_profile_signal),
        _advise_data_theft(security_config),
    )
    recommendations = [c for c in single_checks if c]
    recommendations.extend(_advise_request_limits(security_config, traffic_stats))
    return recommendations
