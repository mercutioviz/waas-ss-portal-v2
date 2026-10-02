"""Tests for app/review_service.py — the Phase 6 aggregation layer that
synthesizes phases 1-4 into the Account/Config Review report — and for the
review.report() route that wires real data sources into it. Aggregation
tests use synthetic dicts only (no WaasClient/DB); route tests use a stub
client, matching test_config_advisor.py's conventions."""

import pytest

from app.review_service import build_review, _summarize_config, _summarize_fp, _summarize_history, _summarize_trend, _summarize_baseline
from app.models import ConfigSnapshot, ConfigTemplate, SecurityMetricSnapshot, TemplateApplication, User, WaasAccount, db


def _scored_group(count=10, fp_confidence=0, fn_flag=False, attack_name='SQLi'):
    return {
        'attack_name': attack_name,
        'attack_type': attack_name,
        'count': count,
        'fp_confidence': fp_confidence,
        'fn_flag': fn_flag,
        'fn_reasons': ['sustained high-risk log-only traffic'] if fn_flag else [],
    }


class TestSummarizeConfig:
    def test_extracts_protection_mode_and_flags(self):
        summary = _summarize_config({
            'protection_mode': 'Active',
            'clickjacking_protection': {'enable_clickjack_prevention': True},
            'data_theft_protection': {'enabled': False},
        })
        assert summary == {
            'protection_mode': 'Active',
            'clickjacking_enabled': True,
            'data_theft_enabled': False,
        }

    def test_none_config_is_safe(self):
        summary = _summarize_config(None)
        assert summary['protection_mode'] is None
        assert summary['clickjacking_enabled'] is False
        assert summary['data_theft_enabled'] is False


class TestSummarizeFp:
    def test_buckets_by_confidence_and_gap_flag(self):
        groups = [
            _scored_group(fp_confidence=80, attack_name='XSS'),
            _scored_group(fp_confidence=50, attack_name='SQLi'),
            _scored_group(fp_confidence=10, fn_flag=True, attack_name='RCE'),
        ]
        summary = _summarize_fp(groups)
        assert summary['total_groups'] == 3
        assert summary['likely_fp_count'] == 1
        assert summary['possible_fp_count'] == 1
        assert summary['possible_gap_count'] == 1
        assert summary['top_gaps'][0]['attack_name'] == 'RCE'

    def test_empty_groups(self):
        summary = _summarize_fp([])
        assert summary['total_groups'] == 0
        assert summary['top_likely_fp'] == []
        assert summary['top_gaps'] == []

    def test_none_is_safe(self):
        summary = _summarize_fp(None)
        assert summary['total_groups'] == 0


class TestSummarizeHistory:
    def test_caps_recent_at_ten(self):
        snapshots = [{'id': i} for i in range(15)]
        summary = _summarize_history(snapshots)
        assert summary['total_count'] == 15
        assert len(summary['recent']) == 10

    def test_empty_is_safe(self):
        assert _summarize_history(None) == {'total_count': 0, 'recent': []}


class TestSummarizeTrend:
    def test_no_history_returns_none(self):
        assert _summarize_trend([]) is None
        assert _summarize_trend(None) is None

    def test_computes_delta_between_first_and_last(self):
        rows = [
            {'captured_at': '2026-08-01T00:00:00', 'blocked_count': 10, 'unique_ip_count': 3},
            {'captured_at': '2026-08-15T00:00:00', 'blocked_count': 40, 'unique_ip_count': 9},
        ]
        summary = _summarize_trend(rows)
        assert summary['sample_count'] == 2
        assert summary['latest_blocked_count'] == 40
        assert summary['latest_unique_ip_count'] == 9
        assert summary['blocked_count_delta'] == 30

    def test_single_sample_has_zero_delta(self):
        rows = [{'captured_at': '2026-08-01T00:00:00', 'blocked_count': 5, 'unique_ip_count': 2}]
        summary = _summarize_trend(rows)
        assert summary['blocked_count_delta'] == 0


class TestSummarizeBaseline:
    def test_no_baseline_returns_none(self):
        assert _summarize_baseline({'protection_mode': 'Active'}, None) is None

    def test_identical_configs_yield_no_gaps(self):
        config = {'protection_mode': 'Active', 'request_limits': {'max_url_length': 2048}}
        summary = _summarize_baseline(config, {'name': 'Baseline A', 'config': config})
        assert summary['gap_count'] == 0
        assert summary['gaps'] == []

    def test_protection_mode_mismatch_is_a_gap(self):
        live = {'protection_mode': 'Passive'}
        baseline = {'name': 'Baseline A', 'config': {'protection_mode': 'Active'}}
        summary = _summarize_baseline(live, baseline)
        matches = [g for g in summary['gaps'] if g['field'] == 'protection_mode']
        assert len(matches) == 1
        assert matches[0]['live_value'] == 'Passive'
        assert matches[0]['baseline_value'] == 'Active'

    def test_request_limit_mismatch_is_a_gap(self):
        live = {'request_limits': {'max_url_length': 100}}
        baseline = {'name': 'Baseline A', 'config': {'request_limits': {'max_url_length': 2048}}}
        summary = _summarize_baseline(live, baseline)
        matches = [g for g in summary['gaps'] if g['field'] == 'request_limits.max_url_length']
        assert len(matches) == 1

    def test_clickjacking_key_only_on_one_side_is_a_gap(self):
        live = {'clickjacking_protection': {'enable_clickjack_prevention': True}}
        baseline = {'name': 'Baseline A', 'config': {'clickjacking_protection': {}}}
        summary = _summarize_baseline(live, baseline)
        matches = [g for g in summary['gaps'] if g['field'] == 'clickjacking_protection.enable_clickjack_prevention']
        assert len(matches) == 1
        assert matches[0]['baseline_value'] is None


class TestBuildReview:
    def test_combines_all_sections(self):
        review = build_review(
            {'protection_mode': 'Passive'},
            fp_groups=[_scored_group(count=10, fp_confidence=10)],
            traffic_stats={},
            snapshots=[{'id': 1, 'resource_type': 'template_apply'}],
            metric_snapshots=[{'captured_at': 't1', 'blocked_count': 5, 'unique_ip_count': 1}],
            baseline={'name': 'Baseline A', 'config': {'protection_mode': 'Active'}},
        )
        assert review['config_summary']['protection_mode'] == 'Passive'
        assert review['fp_summary']['total_groups'] == 1
        assert isinstance(review['recommendations'], list)
        assert review['history_summary']['total_count'] == 1
        assert review['trend_summary']['sample_count'] == 1
        assert review['baseline_summary']['name'] == 'Baseline A'

    def test_missing_optional_sources_degrade_gracefully(self):
        review = build_review({'protection_mode': 'Active'})
        assert review['history_summary'] == {'total_count': 0, 'recent': []}
        assert review['trend_summary'] is None
        assert review['baseline_summary'] is None
        assert review['performance'] is None

    def test_performance_report_is_passed_through_untouched(self):
        perf = {'sample': {'rows': 1}, 'findings': []}
        review = build_review({'protection_mode': 'Active'}, perf_report=perf)
        assert review['performance'] is perf


class StubWaasClient:
    """Minimal stub standing in for WaasClient in the review.report() route."""

    def __init__(self, security=None, waf_logs=None, access_logs=None):
        self.security = security or {'protection_mode': 'Active'}
        self.waf_logs = waf_logs or []
        self.access_logs = access_logs or []
        self.quick_ranges_used = []

    def get_application(self, app_id):
        return {'name': app_id, 'endpoints': {'domains': []}}

    def get_security_config(self, app_id):
        return self.security

    def get_logs(self, app_id, quick_range='r_7d', page=1, items_per_page=1000, filter_fields=None):
        self.quick_ranges_used.append(quick_range)
        log_type = (filter_fields or {}).get('LogType', [{}])[0].get('value')
        results = self.waf_logs if log_type == 'WF' else self.access_logs
        return {'results': results, 'count': len(results)}


@pytest.fixture
def user(app, db):
    u = User(username='review-tester', email='review@example.com', role='user', is_active=True)
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


class TestReviewReportRoute:
    def test_page_renders_for_account_with_no_history(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient(security={'protection_mode': 'Active'})
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/review/{account.id}/app1.example.com')
        assert resp.status_code == 200
        assert b'Account/Config Review' in resp.data
        assert b'No trend history yet' in resp.data
        assert b'No baseline template selected' in resp.data

    def test_page_shows_history_and_uses_most_recently_applied_template_as_baseline(
        self, app, db, logged_in_client, user, account, monkeypatch
    ):
        stub = StubWaasClient(security={'protection_mode': 'Passive'})
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        ConfigSnapshot.record(
            user_id=user.id, account_id=account.id, app_id='app1.example.com',
            resource_type='template_apply', resource_label='My Template',
            payload_before={}, payload_applied={},
        )

        template = ConfigTemplate(user_id=user.id, name='Gold Standard')
        template.config_dict = {'protection_mode': 'Active'}
        db.session.add(template)
        db.session.commit()
        db.session.add(TemplateApplication(
            template_id=template.id, account_id=account.id,
            app_name='app1.example.com', applied_by=user.id,
        ))
        db.session.commit()

        resp = logged_in_client.get(f'/review/{account.id}/app1.example.com')
        assert resp.status_code == 200
        assert b'Gold Standard' in resp.data
        assert b'My Template' in resp.data
        assert b'protection_mode' in resp.data

    def test_page_shows_trend_when_metric_snapshots_exist(self, app, db, logged_in_client, account, monkeypatch):
        stub = StubWaasClient(security={'protection_mode': 'Active'})
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        snap = SecurityMetricSnapshot(
            account_id=account.id, app_id='app1.example.com', app_name='app1.example.com',
            quick_range='r_24h', blocked_count=42, unique_ip_count=7, unique_rule_count=3,
        )
        db.session.add(snap)
        db.session.commit()

        resp = logged_in_client.get(f'/review/{account.id}/app1.example.com')
        assert resp.status_code == 200
        assert b'42' in resp.data

    def test_unowned_account_redirects_without_error(self, app, db, client, monkeypatch):
        other = User(username='review-other', email='review-other@example.com', role='user', is_active=True)
        other.set_password('x')
        db.session.add(other)
        db.session.commit()
        other_acc = WaasAccount(user_id=other.id, account_name='Not Yours', is_active=True)
        other_acc.api_key = 'k'
        db.session.add(other_acc)
        db.session.commit()

        requester = User(username='review-requester', email='review-requester@example.com', role='user', is_active=True)
        requester.set_password('x')
        db.session.add(requester)
        db.session.commit()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(requester.id)
            sess['_fresh'] = True

        resp = client.get(f'/review/{other_acc.id}/app1.example.com')
        assert resp.status_code == 302

    def test_page_still_renders_if_log_fetch_fails(self, logged_in_client, account, monkeypatch):
        class FailingLogsStub(StubWaasClient):
            def get_logs(self, *args, **kwargs):
                from app.waas_client import WaasApiError
                raise WaasApiError('boom')

        stub = FailingLogsStub(security={'protection_mode': 'Active'})
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/review/{account.id}/app1.example.com')
        assert resp.status_code == 200
        assert b'Some data could not be loaded' in resp.data

    def test_defaults_to_7_day_window(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient(security={'protection_mode': 'Active'})
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/review/{account.id}/app1.example.com')
        assert resp.status_code == 200
        assert stub.quick_ranges_used == ['r_7d', 'r_7d']
        assert b'Last 7 Days' in resp.data

    def test_quick_range_query_param_is_passed_through_to_log_fetch(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient(security={'protection_mode': 'Active'})
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/review/{account.id}/app1.example.com?quick_range=r_30d')
        assert resp.status_code == 200
        assert stub.quick_ranges_used == ['r_30d', 'r_30d']
        assert b'Last 30 Days' in resp.data

    def test_invalid_quick_range_falls_back_to_default(self, logged_in_client, account, monkeypatch):
        stub = StubWaasClient(security={'protection_mode': 'Active'})
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/review/{account.id}/app1.example.com?quick_range=not_a_real_range')
        assert resp.status_code == 200
        assert stub.quick_ranges_used == ['r_7d', 'r_7d']


# Jinja's i18n extension marks _() output safe, so the literal '&' in the
# heading reaches the response unescaped.
PERF_CARD_HEADING = b'Performance & Traffic Health'


def _access_row(url='/page', status=200, cache_hit=0, time_taken=100, server_time=80):
    return {
        'LogType': 'TR', 'URL': url, 'HTTPStatus': status, 'CacheHit': cache_hit,
        'TimeTaken': time_taken, 'ServerTime': server_time,
    }


class TestReviewReportPerformanceCard:
    def test_card_renders_with_findings(self, logged_in_client, account, monkeypatch):
        # 60 uncached static assets -> cache_static_miss, plus origin-bound latency.
        access_logs = [_access_row(url='/static/app.js', time_taken=900, server_time=850)
                       for _ in range(60)]
        stub = StubWaasClient(security={'protection_mode': 'Active'}, access_logs=access_logs)
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/review/{account.id}/app1.example.com')
        assert resp.status_code == 200
        assert PERF_CARD_HEADING in resp.data
        assert b'Static assets are mostly missing the edge cache' in resp.data
        assert b'dominated by the origin' in resp.data

    def test_healthy_static_cache_is_not_flagged_on_a_dynamic_heavy_app(
            self, logged_in_client, account, monkeypatch):
        """The false positive the static/dynamic split exists to prevent."""
        access_logs = [_access_row(url='/api/search', cache_hit=0) for _ in range(200)]
        access_logs += [_access_row(url='/static/app.js', cache_hit=1) for _ in range(40)]
        access_logs += [_access_row(url='/static/app.js', cache_hit=0) for _ in range(10)]
        stub = StubWaasClient(security={'protection_mode': 'Active'}, access_logs=access_logs)
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/review/{account.id}/app1.example.com')
        assert resp.status_code == 200
        assert b'Static assets are mostly missing the edge cache' not in resp.data

    def test_low_traffic_app_shows_insufficient_sample_state(
            self, logged_in_client, account, monkeypatch):
        access_logs = [_access_row(status=500) for _ in range(5)]
        stub = StubWaasClient(security={'protection_mode': 'Active'}, access_logs=access_logs)
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/review/{account.id}/app1.example.com')
        assert resp.status_code == 200
        assert b'Not enough traffic to draw conclusions' in resp.data
        assert b'Origin is returning server errors' not in resp.data

    def test_card_is_omitted_when_the_log_fetch_fails(self, logged_in_client, account, monkeypatch):
        class FailingLogsStub(StubWaasClient):
            def get_logs(self, *args, **kwargs):
                from app.waas_client import WaasApiError
                raise WaasApiError('boom')

        stub = FailingLogsStub(security={'protection_mode': 'Active'})
        monkeypatch.setattr('app.routes.applications.WaasClient.from_account', lambda acc: stub)

        resp = logged_in_client.get(f'/review/{account.id}/app1.example.com')
        assert resp.status_code == 200
        assert PERF_CARD_HEADING not in resp.data
