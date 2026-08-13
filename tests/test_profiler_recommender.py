"""Tests for the recommender — pure function of a SiteProfile."""

import pytest

from app.profiler.recommender import ALLOWED_FORM_FIELDS, recommend
from app.profiler.schemas import DnsResult, HttpResult, SiteProfile, TechDetection, TlsResult


def _profile(
    target_url=None,
    hostname='acme.example.com',
    addresses=('93.184.216.34',),
    tls_ok=True,
    tls_version='TLSv1.3',
    http_status=None,
    http_redirect_target=None,
    https_status=200,
    https_headers=None,
    https_body='',
    https_cookies=None,
    tech_stack=(),
    cdn=None,
    confidence='high',
):
    if target_url is None:
        target_url = f'https://{hostname}/'
    return SiteProfile(
        target_url=target_url,
        dns=DnsResult(hostname=hostname, addresses=list(addresses)),
        tls=TlsResult(
            handshake_ok=tls_ok,
            tls_version=tls_version if tls_ok else None,
            cert_subject='CN=acme.example.com' if tls_ok else None,
        ),
        http_root=HttpResult(status=http_status, redirect_target=http_redirect_target),
        https_root=HttpResult(
            status=https_status,
            headers=dict(https_headers or {}),
            cookies=dict(https_cookies or {}),
            body_snippet=https_body,
        ),
        tech_stack=[
            t if isinstance(t, TechDetection) else TechDetection(name=t, category='', source='test')
            for t in tech_stack
        ],
        cdn=cdn,
        confidence=confidence,
    )


class TestFormFieldPreFill:
    def test_all_declared_fields_are_present(self):
        result = recommend(_profile())
        assert set(result['form_fields']) == ALLOWED_FORM_FIELDS

    def test_application_name_slug_strips_www(self):
        result = recommend(_profile(target_url='https://www.acme.com/', hostname='www.acme.com'))
        assert result['form_fields']['application_name']['value'] == 'acme'

    def test_hostname_is_the_probed_host(self):
        result = recommend(_profile(hostname='shop.example.com'))
        assert result['form_fields']['hostname']['value'] == 'shop.example.com'

    def test_backend_ip_is_blank_and_calls_out_that_user_must_supply(self):
        result = recommend(_profile())
        assert result['form_fields']['backend_ip']['value'] == ''
        assert 'origin' in result['form_fields']['backend_ip']['rationale'].lower()

    def test_backend_type_is_https_when_tls_works(self):
        result = recommend(_profile(tls_ok=True))
        assert result['form_fields']['backend_type']['value'] == 'HTTPS'
        assert result['form_fields']['backend_port']['value'] == 443

    def test_backend_type_falls_back_to_http_when_tls_broken(self):
        result = recommend(_profile(tls_ok=False))
        assert result['form_fields']['backend_type']['value'] == 'HTTP'
        assert result['form_fields']['backend_port']['value'] == 80

    def test_protection_mode_defaults_to_passive(self):
        result = recommend(_profile())
        assert result['form_fields']['malicious_traffic']['value'] == 'Passive'

    def test_redirect_http_when_site_already_redirects(self):
        result = recommend(_profile(
            http_status=301,
            http_redirect_target='https://acme.example.com/',
        ))
        assert result['form_fields']['redirect_http']['value'] is True
        assert 'already redirects' in result['form_fields']['redirect_http']['rationale']


class TestAdvisories:
    def test_wordpress_advisory_when_detected(self):
        result = recommend(_profile(tech_stack=('WordPress',)))
        titles = [a['title'] for a in result['advisories']]
        assert 'WordPress detected' in titles

    def test_cdn_advisory_flags_backend_gap(self):
        result = recommend(_profile(cdn='Cloudflare'))
        cdn_adv = [a for a in result['advisories'] if 'Cloudflare' in a['title']]
        assert cdn_adv, 'expected a Cloudflare advisory'
        assert 'origin' in cdn_adv[0]['body'].lower()

    def test_tls_failure_produces_warning(self):
        result = recommend(_profile(tls_ok=False, confidence='low'))
        titles = [a['title'] for a in result['advisories']]
        assert 'TLS handshake failed' in titles

    def test_low_confidence_produces_advisory(self):
        result = recommend(_profile(confidence='low'))
        titles = [a['title'] for a in result['advisories']]
        assert 'Low-confidence result' in titles

    def test_clean_site_has_no_warnings(self):
        result = recommend(_profile())
        severities = [a['severity'] for a in result['advisories']]
        assert 'warning' not in severities


class TestAllowlistValidation:
    def test_recommender_output_is_form_field_allowlisted(self):
        # No unknown keys leak into the output — this is the guardrail against
        # silently-dropped defaults when field names drift.
        result = recommend(_profile())
        assert set(result['form_fields']) <= ALLOWED_FORM_FIELDS
