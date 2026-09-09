"""Tests for app/fp_scoring.py — heuristic FP-confidence / FN-exposure scoring
for fp_analysis() attack groups — and for the fp_analysis() route that wires
scoring, sorting, and min-confidence filtering into the view."""

import pytest

from app.fp_scoring import score_group, group_waf_logs, _parse_risk_score
from app.models import User, WaasAccount


def _group(count=10, deny_count=0, log_count=10, unique_ip_count=1,
           unique_url_count=1, owasp_risk_score='—'):
    return {
        'count': count,
        'deny_count': deny_count,
        'log_count': log_count,
        'unique_ip_count': unique_ip_count,
        'unique_url_count': unique_url_count,
        'owasp_risk_score': owasp_risk_score,
    }


class TestParseRiskScore:
    def test_dash_is_none(self):
        assert _parse_risk_score('—') is None

    def test_none_is_none(self):
        assert _parse_risk_score(None) is None

    def test_empty_string_is_none(self):
        assert _parse_risk_score('') is None

    def test_numeric_string(self):
        assert _parse_risk_score('42') == 42

    def test_float_string(self):
        assert _parse_risk_score('42.0') == 42

    def test_int(self):
        assert _parse_risk_score(75) == 75

    def test_garbage_is_none(self):
        assert _parse_risk_score('n/a') is None


class TestScoreGroupFpConfidence:
    def test_narrow_high_risk_targeted_attack_scores_low(self):
        # 1 IP, 1 URL, high risk, mostly blocked -> looks like a real attack
        group = _group(count=20, deny_count=20, log_count=0,
                        unique_ip_count=1, unique_url_count=1,
                        owasp_risk_score=95)
        result = score_group(group)
        assert result['fp_confidence'] < 40
        assert result['fp_flag'] is False

    def test_wide_ip_and_url_spread_low_risk_scores_high(self):
        # many distinct IPs/URLs, low risk score, all log-only -> classic FP shape
        group = _group(count=20, deny_count=0, log_count=20,
                        unique_ip_count=18, unique_url_count=15,
                        owasp_risk_score=10)
        result = score_group(group)
        assert result['fp_confidence'] >= 70
        assert result['fp_flag'] is True
        assert result['fp_reasons']

    def test_small_sample_size_does_not_trigger_spread_bonus(self):
        # below MIN_SAMPLE_SIZE, IP/URL spread heuristics should not fire
        group = _group(count=2, deny_count=0, log_count=2,
                        unique_ip_count=2, unique_url_count=2,
                        owasp_risk_score=None)
        result = score_group(group)
        assert result['fp_confidence'] == 0

    def test_unknown_risk_score_contributes_nothing(self):
        group = _group(count=10, deny_count=10, log_count=0,
                        unique_ip_count=1, unique_url_count=1,
                        owasp_risk_score='—')
        result = score_group(group)
        assert not any('risk score' in r.lower() for r in result['fp_reasons'])

    def test_confidence_capped_at_100(self):
        group = _group(count=50, deny_count=0, log_count=50,
                        unique_ip_count=50, unique_url_count=50,
                        owasp_risk_score=0)
        result = score_group(group)
        assert result['fp_confidence'] <= 100


class TestScoreGroupFnFlag:
    def test_high_risk_log_only_sustained_flags_gap(self):
        group = _group(count=10, deny_count=0, log_count=10,
                        unique_ip_count=3, unique_url_count=2,
                        owasp_risk_score=85)
        result = score_group(group)
        assert result['fn_flag'] is True
        assert result['fn_reasons']

    def test_high_risk_but_blocked_does_not_flag_gap(self):
        group = _group(count=10, deny_count=10, log_count=0,
                        unique_ip_count=3, unique_url_count=2,
                        owasp_risk_score=85)
        result = score_group(group)
        assert result['fn_flag'] is False

    def test_high_risk_but_small_sample_does_not_flag_gap(self):
        group = _group(count=2, deny_count=0, log_count=2,
                        unique_ip_count=1, unique_url_count=1,
                        owasp_risk_score=85)
        result = score_group(group)
        assert result['fn_flag'] is False

    def test_low_risk_log_only_does_not_flag_gap(self):
        group = _group(count=10, deny_count=0, log_count=10,
                        unique_ip_count=3, unique_url_count=2,
                        owasp_risk_score=20)
        result = score_group(group)
        assert result['fn_flag'] is False


class TestGroupWafLogsTopSampleUrl:
    def test_most_common_url_wins(self):
        logs = (
            [{'AttackType': 'SQLi', 'RuleID': 'r1', 'Action': 'LOG', 'ClientIP': '1.1.1.1', 'URL': '/checkout'}] * 3
            + [{'AttackType': 'SQLi', 'RuleID': 'r1', 'Action': 'LOG', 'ClientIP': '1.1.1.2', 'URL': '/cart'}]
        )
        groups = group_waf_logs(logs)
        assert len(groups) == 1
        assert groups[0]['top_sample_url'] == '/checkout'

    def test_empty_logs_yields_no_groups(self):
        assert group_waf_logs([]) == []

    def test_single_entry_url_is_top(self):
        logs = [{'AttackType': 'XSS', 'RuleID': 'r2', 'Action': 'DENY', 'ClientIP': '1.1.1.1', 'URL': '/search'}]
        groups = group_waf_logs(logs)
        assert groups[0]['top_sample_url'] == '/search'


class StubWaasClient:
    """Minimal stub standing in for WaasClient.get_logs()."""

    def __init__(self, logs=None, count=None):
        self.logs = logs or []
        self.count = count if count is not None else len(self.logs)
        self.last_call = None

    def get_logs(self, app_id, quick_range='r_7d', page=1, items_per_page=1000, filter_fields=None):
        self.last_call = {'app_id': app_id, 'quick_range': quick_range, 'filter_fields': filter_fields}
        return {'results': self.logs, 'count': self.count}


def _waf_entry(rule_id, attack, action='LOG', ip='1.1.1.1', url='/', risk_score='—'):
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
    u = User(username='fp-tester', email='fp@example.com', role='user', is_active=True)
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


class TestFpAnalysisRoute:
    def _widespread_fp_logs(self):
        # 20 entries, 18 unique IPs, 15 unique URLs, low risk score, all log-only -> high FP confidence
        logs = []
        for i in range(20):
            logs.append(_waf_entry('r1', 'SQLi', ip=f'10.0.0.{i % 18}', url=f'/page{i % 15}', risk_score=15))
        return logs

    def test_page_renders_with_scored_groups(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient(logs=self._widespread_fp_logs())
        monkeypatch.setattr('app.routes.logs.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/logs/{account.id}/app1.example.com/fp-analysis?quick_range=r_30d')
        assert resp.status_code == 200
        assert b'Likely FP' in resp.data

    def test_min_confidence_filters_out_low_confidence_groups(self, logged_in_client, account, monkeypatch):
        logs = self._widespread_fp_logs() + [
            _waf_entry('r2', 'XSS', action='DENY', ip='2.2.2.2', url='/admin', risk_score=95),
        ]
        stub = StubWaasClient(logs=logs)
        monkeypatch.setattr('app.routes.logs.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(
            f'/logs/{account.id}/app1.example.com/fp-analysis?min_confidence=70'
        )
        assert resp.status_code == 200
        assert b'SQLi' in resp.data
        assert b'XSS' not in resp.data

    def test_sort_by_fp_confidence(self, logged_in_client, account, monkeypatch):
        logs = self._widespread_fp_logs() + [
            _waf_entry('r2', 'XSS', action='DENY', ip='2.2.2.2', url='/admin', risk_score=95),
        ]
        stub = StubWaasClient(logs=logs)
        monkeypatch.setattr('app.routes.logs.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(
            f'/logs/{account.id}/app1.example.com/fp-analysis?sort=fp_confidence'
        )
        assert resp.status_code == 200
        sqli_pos = resp.data.index(b'SQLi')
        xss_pos = resp.data.index(b'XSS')
        assert sqli_pos < xss_pos
