"""Tests for app/config_advisor.py — config-vs-traffic recommendation engine —
and for the security_config() route that wires it into the security page."""

import pytest

from app.config_advisor import advise, compute_traffic_stats
from app.models import User, WaasAccount


def _observation(max_value, sample=100, saturated=False):
    """One entry of compute_traffic_stats()['observed']."""
    return {'max': max_value, 'sample': sample, 'saturated': saturated}


def _stats(**observations):
    """A traffic_stats dict carrying only the observations a test cares about."""
    return {
        'total_requests': 100,
        'unique_ip_count': 10,
        'max_url_length_observed': observations.get('url_length', {}).get('max', 0),
        'observed': observations,
    }


def _scored_group(count=10, fp_confidence=0, owasp_risk_score=90, attack_name='SQLi'):
    return {
        'attack_name': attack_name,
        'attack_type': attack_name,
        'count': count,
        'fp_confidence': fp_confidence,
        'owasp_risk_score': owasp_risk_score,
    }


class TestComputeTrafficStats:
    def test_empty_logs(self):
        stats = compute_traffic_stats([])
        assert stats['total_requests'] == 0
        assert stats['unique_ip_count'] == 0
        assert stats['max_url_length_observed'] == 0
        assert all(o == {'max': 0, 'saturated': False, 'sample': 0}
                   for o in stats['observed'].values())

    def test_counts_and_max_url_length(self):
        logs = [
            {'URL': '/short', 'ClientIP': '1.1.1.1'},
            {'URL': '/a-much-longer-path-here', 'ClientIP': '1.1.1.2'},
            {'URL': '/short', 'ClientIP': '1.1.1.1'},
        ]
        stats = compute_traffic_stats(logs)
        assert stats['total_requests'] == 3
        assert stats['unique_ip_count'] == 2
        assert stats['max_url_length_observed'] == len('/a-much-longer-path-here')
        assert stats['observed']['url_length']['max'] == len('/a-much-longer-path-here')

    def test_none_is_safe(self):
        assert compute_traffic_stats(None)['total_requests'] == 0

    def test_absent_fields_use_the_quoted_dash_sentinel(self):
        """The API renders empty fields as the literal 3-char string `"-"`.

        A naive len() would record 3 for every absent cookie and referer.
        """
        logs = [{'URL': '/a', 'ClientIP': '"-"', 'Cookie': '"-"', 'Referer': '"-"',
                 'UserAgent': '"-"', 'Host': '"-"'}]
        stats = compute_traffic_stats(logs)
        assert stats['unique_ip_count'] == 0
        assert stats['observed']['cookie_value_length']['sample'] == 0
        assert stats['observed']['header_value_length']['max'] == 0

    def test_cookie_names_and_values_parsed_separately(self):
        logs = [{'URL': '/a', 'Cookie': 'sid=abcdef; theme=dark'}]
        observed = compute_traffic_stats(logs)['observed']
        assert observed['cookie_name_length']['max'] == len('theme')
        assert observed['cookie_value_length']['max'] == len('abcdef')
        assert observed['cookie_value_length']['sample'] == 2

    def test_request_line_length_includes_method_query_and_version(self):
        logs = [{'URL': '/p', 'Method': 'GET', 'QueryString': 'a=1', 'Version': 'HTTP/1.1'}]
        observed = compute_traffic_stats(logs)['observed']
        assert observed['request_line_length']['max'] == len('GET /p?a=1 HTTP/1.1')

    def test_truncated_field_marks_observation_saturated(self):
        """255-char fields are truncated by the API, so the max is a lower bound."""
        logs = [{'URL': '/p', 'Method': 'GET', 'QueryString': 'x' * 255, 'Version': 'HTTP/1.1'}]
        observed = compute_traffic_stats(logs)['observed']
        assert observed['request_line_length']['saturated'] is True
        # The URL itself is well under the cap, so it is not a lower bound.
        assert observed['url_length']['saturated'] is False

    def test_bytes_received_is_never_saturated(self):
        """BytesReceived is a number, not a truncated string."""
        logs = [{'URL': '/p', 'BytesReceived': 4096}]
        observed = compute_traffic_stats(logs)['observed']
        assert observed['request_bytes']['max'] == 4096
        assert observed['request_bytes']['saturated'] is False


class TestAdviseProtectionMode:
    def test_passive_with_risky_low_fp_group_suggests_active(self):
        security_config = {'protection_mode': 'Passive'}
        fp_groups = [_scored_group(count=10, fp_confidence=10, owasp_risk_score=90)]
        recs = advise(security_config, fp_groups, {})
        matches = [r for r in recs if r['field'] == 'protection_mode']
        assert len(matches) == 1
        assert matches[0]['current_value'] == 'Passive'
        assert matches[0]['suggested_value'] == 'Active'
        assert matches[0]['severity'] == 'warning'

    def test_active_mode_never_flagged(self):
        security_config = {'protection_mode': 'Active'}
        fp_groups = [_scored_group(count=10, fp_confidence=10, owasp_risk_score=90)]
        recs = advise(security_config, fp_groups, {})
        assert not [r for r in recs if r['field'] == 'protection_mode']

    def test_passive_with_only_high_fp_confidence_groups_not_flagged(self):
        # High risk but ALSO high fp_confidence -> likely a real false positive, not a gap
        security_config = {'protection_mode': 'Passive'}
        fp_groups = [_scored_group(count=10, fp_confidence=80, owasp_risk_score=90)]
        recs = advise(security_config, fp_groups, {})
        assert not [r for r in recs if r['field'] == 'protection_mode']

    def test_passive_with_small_sample_not_flagged(self):
        security_config = {'protection_mode': 'Passive'}
        fp_groups = [_scored_group(count=2, fp_confidence=0, owasp_risk_score=90)]
        recs = advise(security_config, fp_groups, {})
        assert not [r for r in recs if r['field'] == 'protection_mode']

    def test_no_fp_groups_not_flagged(self):
        security_config = {'protection_mode': 'Passive'}
        recs = advise(security_config, [], {})
        assert not [r for r in recs if r['field'] == 'protection_mode']


class TestAdviseMaxUrlLength:
    def test_observed_exceeds_configured_limit_warns(self):
        security_config = {'request_limits': {'max_url_length': 100}}
        recs = advise(security_config, [], _stats(url_length=_observation(250)))
        matches = [r for r in recs if r['field'] == 'request_limits.max_url_length']
        assert len(matches) == 1
        assert matches[0]['severity'] == 'warning'
        assert matches[0]['current_value'] == 100
        assert matches[0]['suggested_value'] == 250

    def test_configured_limit_far_larger_than_observed_suggests_tightening(self):
        security_config = {'request_limits': {'max_url_length': 8192}}
        recs = advise(security_config, [], _stats(url_length=_observation(50)))
        matches = [r for r in recs if r['field'] == 'request_limits.max_url_length']
        assert len(matches) == 1
        assert matches[0]['severity'] == 'info'

    def test_reasonable_limit_not_flagged(self):
        security_config = {'request_limits': {'max_url_length': 2048}}
        recs = advise(security_config, [], _stats(url_length=_observation(600)))
        assert not [r for r in recs if r['field'] == 'request_limits.max_url_length']

    def test_missing_config_value_not_flagged(self):
        security_config = {'request_limits': {}}
        recs = advise(security_config, [], _stats(url_length=_observation(600)))
        assert not [r for r in recs if r['field'] == 'request_limits.max_url_length']

    def test_no_observed_traffic_not_flagged(self):
        security_config = {'request_limits': {'max_url_length': 100}}
        recs = advise(security_config, [], _stats(url_length=_observation(0)))
        assert not [r for r in recs if r['field'] == 'request_limits.max_url_length']

    def test_small_sample_not_flagged(self):
        """Don't advise on request limits from a handful of requests."""
        security_config = {'request_limits': {'max_url_length': 100}}
        recs = advise(security_config, [], _stats(url_length=_observation(250, sample=5)))
        assert not [r for r in recs if r['field'] == 'request_limits.max_url_length']


class TestRequestLimitDirectionPolicy:
    """The logs API truncates text fields at 255 chars, so an observed maximum
    from one of them is a lower bound. That supports 'your cap is too tight'
    but never 'your cap is too loose'."""

    def test_saturated_field_still_warns_when_cap_is_too_tight(self):
        security_config = {'request_limits': {'max_request_line_length': 200}}
        recs = advise(security_config, [], _stats(
            request_line_length=_observation(300, saturated=True)))
        matches = [r for r in recs if r['field'] == 'request_limits.max_request_line_length']
        assert len(matches) == 1
        assert matches[0]['severity'] == 'warning'
        assert 'truncated' in matches[0]['rationale']

    def test_saturated_field_never_suggests_tightening(self):
        security_config = {'request_limits': {'max_request_line_length': 8192}}
        recs = advise(security_config, [], _stats(
            request_line_length=_observation(255, saturated=True)))
        assert not [r for r in recs if r['field'] == 'request_limits.max_request_line_length']

    def test_cookie_fields_never_suggest_tightening(self):
        security_config = {'request_limits': {
            'max_cookie_name_length': 8192, 'max_cookie_value_length': 8192}}
        recs = advise(security_config, [], _stats(
            cookie_name_length=_observation(12, sample=50),
            cookie_value_length=_observation(40, sample=50)))
        assert not [r for r in recs if r['field'].startswith('request_limits.max_cookie')]

    def test_cookie_fields_warn_when_cap_is_too_tight(self):
        security_config = {'request_limits': {'max_cookie_value_length': 32}}
        recs = advise(security_config, [], _stats(
            cookie_value_length=_observation(200, sample=50)))
        matches = [r for r in recs if r['field'] == 'request_limits.max_cookie_value_length']
        assert len(matches) == 1
        assert matches[0]['severity'] == 'warning'

    def test_cookie_fields_respect_their_own_sample_floor(self):
        """Most requests carry no cookie at all, so cookies gate separately."""
        security_config = {'request_limits': {'max_cookie_value_length': 32}}
        recs = advise(security_config, [], _stats(
            cookie_value_length=_observation(200, sample=3)))
        assert not [r for r in recs if r['field'] == 'request_limits.max_cookie_value_length']

    def test_header_value_length_never_suggests_tightening(self):
        """We only see four of the headers actually sent — it's a lower bound."""
        security_config = {'request_limits': {'max_header_value_length': 8192}}
        recs = advise(security_config, [], _stats(header_value_length=_observation(120)))
        assert not [r for r in recs if r['field'] == 'request_limits.max_header_value_length']

    def test_request_length_never_warns_about_being_too_tight(self):
        """BytesReceived counts headers too, so it over-states the body size
        this cap applies to — it can't prove the cap is too tight."""
        security_config = {'request_limits': {'max_request_length': 1000}}
        recs = advise(security_config, [], _stats(request_bytes=_observation(4000)))
        assert not [r for r in recs if r['field'] == 'request_limits.max_request_length']

    def test_request_length_may_suggest_tightening(self):
        security_config = {'request_limits': {'max_request_length': 65536}}
        recs = advise(security_config, [], _stats(request_bytes=_observation(1400)))
        matches = [r for r in recs if r['field'] == 'request_limits.max_request_length']
        assert len(matches) == 1
        assert matches[0]['severity'] == 'info'

    def test_max_number_of_headers_is_never_advised_on(self):
        """The access log records no header count — nothing to compare against."""
        security_config = {'request_limits': {'max_number_of_headers': 8192}}
        recs = advise(security_config, [], _stats(header_value_length=_observation(120)))
        assert not [r for r in recs if 'max_number_of_headers' in r['field']]


class TestAdviseClickjacking:
    def test_disabled_with_no_client_side_signal_warns(self):
        security_config = {'clickjacking_protection': {'enable_clickjack_prevention': False}}
        recs = advise(security_config, [], {})
        matches = [r for r in recs if r['field'] == 'clickjacking_protection.enable_clickjack_prevention']
        assert len(matches) == 1
        assert matches[0]['severity'] == 'warning'

    def test_disabled_with_client_side_signal_downgrades_to_info(self):
        security_config = {'clickjacking_protection': {'enable_clickjack_prevention': False}}
        recs = advise(security_config, [], {}, site_profile_signal={'x_frame_options_present': True})
        matches = [r for r in recs if r['field'] == 'clickjacking_protection.enable_clickjack_prevention']
        assert len(matches) == 1
        assert matches[0]['severity'] == 'info'

    def test_enabled_not_flagged(self):
        security_config = {'clickjacking_protection': {'enable_clickjack_prevention': True}}
        recs = advise(security_config, [], {})
        assert not [r for r in recs if r['field'] == 'clickjacking_protection.enable_clickjack_prevention']


class TestAdviseDataTheft:
    def test_disabled_flagged_info(self):
        security_config = {'data_theft_protection': {'enabled': False}}
        recs = advise(security_config, [], {})
        matches = [r for r in recs if r['field'] == 'data_theft_protection.enabled']
        assert len(matches) == 1
        assert matches[0]['severity'] == 'info'

    def test_enabled_not_flagged(self):
        security_config = {'data_theft_protection': {'enabled': True}}
        recs = advise(security_config, [], {})
        assert not [r for r in recs if r['field'] == 'data_theft_protection.enabled']


class StubWaasClient:
    """Minimal stub standing in for WaasClient in the security_config() route."""

    def __init__(self, security=None, waf_logs=None, access_logs=None):
        self.security = security or {'protection_mode': 'Active'}
        self.waf_logs = waf_logs or []
        self.access_logs = access_logs or []

    def get_application(self, app_id):
        return {'name': app_id, 'endpoints': {'domains': []}}

    def get_security_config(self, app_id):
        return self.security

    def generate_curl_command(self, method, path):
        return f'curl {method} {path}'

    def get_logs(self, app_id, quick_range='r_7d', page=1, items_per_page=1000, filter_fields=None):
        log_type = (filter_fields or {}).get('LogType', [{}])[0].get('value')
        results = self.waf_logs if log_type == 'WF' else self.access_logs
        return {'results': results, 'count': len(results)}


def _waf_entry(rule_id, attack, action='LOG', ip='1.1.1.1', url='/', risk_score=90):
    return {
        'EpochTime': 1756000000000,
        'Action': action,
        'ClientIP': ip,
        'URL': url,
        'RuleID': rule_id,
        'AttackType': attack,
        'Attack': attack,
        'owasp_risk_score': risk_score,
    }


@pytest.fixture
def user(app, db):
    u = User(username='advisor-tester', email='advisor@example.com', role='user', is_active=True)
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


class TestSecurityConfigRoute:
    def test_page_renders_with_recommendation(self, logged_in_client, account, monkeypatch):
        # Passive mode + a sustained, high-risk, low-FP-confidence attack group
        # -> should surface the protection_mode recommendation.
        waf_logs = [_waf_entry('r1', 'SQLi', ip='2.2.2.2', url='/admin', risk_score=90) for i in range(10)]
        stub = StubWaasClient(security={'protection_mode': 'Passive'}, waf_logs=waf_logs)
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/applications/{account.id}/app1.example.com/security')
        assert resp.status_code == 200
        assert b'Recommendations' in resp.data
        assert b'protection_mode' in resp.data

    def test_page_renders_without_recommendations_when_config_is_healthy(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient(security={
            'protection_mode': 'Active',
            'clickjacking_protection': {'enable_clickjack_prevention': True},
            'data_theft_protection': {'enabled': True},
            'request_limits': {'max_url_length': 2048},
        })
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/applications/{account.id}/app1.example.com/security')
        assert resp.status_code == 200
        assert b'Recommendations' not in resp.data

    def test_page_still_renders_if_log_fetch_fails(self, logged_in_client, account, monkeypatch):
        class FailingLogsStub(StubWaasClient):
            def get_logs(self, *args, **kwargs):
                from app.waas_client import WaasApiError
                raise WaasApiError('boom')

        stub = FailingLogsStub(security={'protection_mode': 'Active'})
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/applications/{account.id}/app1.example.com/security')
        assert resp.status_code == 200
