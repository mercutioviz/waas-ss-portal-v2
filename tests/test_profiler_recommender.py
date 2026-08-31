"""Tests for the recommender — pure function of a SiteProfile."""

import pytest

from app.profiler.recommender import ALLOWED_FORM_FIELDS, recommend
from app.profiler.schemas import (
    ApexWwwCheck,
    CookieAnalysis,
    DnsResult,
    DnsSecurityReport,
    HttpResult,
    SecurityHeadersReport,
    SiteProfile,
    SubresourceReport,
    TechDetection,
    TlsResult,
)


# A "clean" site fixture — set enough of the new fields that the
# recommender doesn't fire generic advisories (missing HSTS, missing CAA,
# etc.). Individual tests override the pieces they care about.
def _clean_security_headers() -> SecurityHeadersReport:
    return SecurityHeadersReport(
        hsts={'max_age': 63072000, 'include_subdomains': True, 'preload': True},
        csp={'directive_count': 5, 'has_unsafe_inline': False, 'has_unsafe_eval': False, 'raw': "default-src 'self'"},
        x_frame_options='DENY',
        x_content_type_options='nosniff',
        referrer_policy='strict-origin-when-cross-origin',
    )


def _clean_dns_security() -> DnsSecurityReport:
    return DnsSecurityReport(
        spf='v=spf1 -all',
        dmarc='v=DMARC1; p=reject',
        caa=['0 issue "letsencrypt.org"'],
        mx_present=True,
    )


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
    security_headers=None,
    cookies=None,
    subresources=None,
    dns_security=None,
    bot_management=None,
    apex_www=None,
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
        security_headers=security_headers if security_headers is not None else _clean_security_headers(),
        cookies=list(cookies) if cookies is not None else [],
        subresources=subresources if subresources is not None else SubresourceReport(),
        dns_security=dns_security if dns_security is not None else _clean_dns_security(),
        bot_management=list(bot_management) if bot_management is not None else [],
        apex_www=apex_www if apex_www is not None else ApexWwwCheck(),
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


class TestFieldDescriptions:
    def test_every_field_has_a_description(self):
        result = recommend(_profile())
        for key, entry in result['form_fields'].items():
            assert entry.get('description'), f'field {key!r} has empty description'

    def test_description_is_static_across_probes(self):
        # Same field → same description regardless of probe details.
        r1 = recommend(_profile(tls_ok=True))
        r2 = recommend(_profile(tls_ok=False))
        assert r1['form_fields']['backend_type']['description'] == r2['form_fields']['backend_type']['description']


def _titles(result):
    return [a['title'] for a in result['advisories']]


class TestSecurityHeaderAdvisories:
    def test_missing_hsts_on_https_flags_warning(self):
        headers = _clean_security_headers()
        headers.hsts = None
        result = recommend(_profile(security_headers=headers))
        assert 'HSTS missing' in _titles(result)

    def test_missing_csp_flags_info(self):
        headers = _clean_security_headers()
        headers.csp = None
        result = recommend(_profile(security_headers=headers))
        assert 'No Content-Security-Policy' in _titles(result)

    def test_csp_with_unsafe_inline_flags(self):
        headers = _clean_security_headers()
        headers.csp = {
            'directive_count': 3, 'has_unsafe_inline': True,
            'has_unsafe_eval': False, 'raw': "script-src 'unsafe-inline'",
        }
        result = recommend(_profile(security_headers=headers))
        assert any("unsafe-inline" in t for t in _titles(result))

    def test_missing_xfo_flags(self):
        headers = _clean_security_headers()
        headers.x_frame_options = None
        result = recommend(_profile(security_headers=headers))
        assert 'X-Frame-Options missing' in _titles(result)


class TestCookieAdvisories:
    def _cookie(self, name, secure=True, http_only=True, same_site='Lax'):
        return CookieAnalysis(
            name=name, value_preview='x',
            secure=secure, http_only=http_only, same_site=same_site,
        )

    def test_insecure_cookie_on_https_flags(self):
        cookies = [self._cookie('pref', secure=False)]
        result = recommend(_profile(cookies=cookies))
        assert any('missing Secure on HTTPS' in t for t in _titles(result))

    def test_session_cookie_without_httponly_flags(self):
        cookies = [self._cookie('SESSIONID', http_only=False)]
        result = recommend(_profile(cookies=cookies))
        assert any('missing HttpOnly' in t for t in _titles(result))

    def test_clean_cookie_produces_no_cookie_advisory(self):
        cookies = [self._cookie('pref', secure=True, http_only=True, same_site='Lax')]
        result = recommend(_profile(cookies=cookies))
        assert not any('cookie' in t.lower() for t in _titles(result))


class TestDnsSecurityAdvisories:
    def test_missing_spf_flags(self):
        dns_sec = _clean_dns_security()
        dns_sec.spf = None
        result = recommend(_profile(dns_security=dns_sec))
        assert 'No SPF record' in _titles(result)

    def test_missing_dmarc_flags(self):
        dns_sec = _clean_dns_security()
        dns_sec.dmarc = None
        result = recommend(_profile(dns_security=dns_sec))
        assert 'No DMARC record' in _titles(result)

    def test_missing_caa_flags(self):
        dns_sec = _clean_dns_security()
        dns_sec.caa = []
        result = recommend(_profile(dns_security=dns_sec))
        assert 'No CAA record' in _titles(result)

    def test_spf_not_flagged_when_no_mx(self):
        # No email → SPF absence is not our business
        dns_sec = _clean_dns_security()
        dns_sec.spf = None
        dns_sec.mx_present = False
        result = recommend(_profile(dns_security=dns_sec))
        assert 'No SPF record' not in _titles(result)


class TestBotManagementAdvisories:
    def test_vendor_detected_produces_advisory(self):
        from app.profiler.schemas import BotVendor
        result = recommend(_profile(bot_management=[BotVendor(name='hCaptcha', evidence='hcaptcha.com')]))
        assert any('hCaptcha' in t for t in _titles(result))


class TestWafHeaderAdvisories:
    def test_cf_ray_produces_cloudflare_edge_advisory(self):
        result = recommend(_profile(https_headers={'cf-ray': 'abc123-DFW'}))
        assert any('Cloudflare' in t and 'edge' in t.lower() for t in _titles(result))

    def test_fastly_served_by_produces_fastly_edge_advisory(self):
        result = recommend(_profile(https_headers={'x-served-by': 'cache-dfw1234'}))
        assert any('Fastly' in t and 'edge' in t.lower() for t in _titles(result))


class TestSubresourceAdvisories:
    def _sub_report(self, third_party_hosts: int = 0, total_bytes: int = 0):
        r = SubresourceReport(total_bytes_estimate=total_bytes)
        for i in range(third_party_hosts):
            r.by_third_party_host[f'thirdparty{i}.example.net'] = {'count': 1, 'bytes': 0}
        return r

    def test_many_third_parties_flags_info(self):
        result = recommend(_profile(subresources=self._sub_report(third_party_hosts=25)))
        assert any('third-party hosts' in t for t in _titles(result))

    def test_heavy_landing_page_flags_info(self):
        result = recommend(_profile(subresources=self._sub_report(total_bytes=3 * 1024 * 1024)))
        assert any('heavy' in t.lower() for t in _titles(result))

    def test_light_page_no_traffic_advisory(self):
        result = recommend(_profile(subresources=self._sub_report(total_bytes=200_000)))
        assert not any('heavy' in t.lower() for t in _titles(result))


class TestApexWwwAdvisories:
    def test_bad_direction_produces_warning(self):
        aw = ApexWwwCheck(
            apex='eesforjobs.com', www_host='www.eesforjobs.com', applicable=True,
            www_status=301, www_redirects_to_apex=True, verdict='warning',
            message='WARNING - must be changed',
        )
        result = recommend(_profile(apex_www=aw))
        titles = _titles(result)
        assert any(t.startswith('WARNING - must be changed') for t in titles)
        severities = {a['severity'] for a in result['advisories'] if a['title'].startswith('WARNING - must be changed')}
        assert severities == {'warning'}

    def test_good_direction_produces_info(self):
        aw = ApexWwwCheck(
            apex='acme.com', www_host='www.acme.com', applicable=True,
            apex_status=301, apex_redirects_to_www=True, verdict='good',
            message='Redirect is good',
        )
        result = recommend(_profile(apex_www=aw))
        assert any(t.startswith('Redirect is good') for t in _titles(result))

    def test_not_applicable_produces_no_advisory(self):
        result = recommend(_profile(apex_www=ApexWwwCheck(applicable=False)))
        assert not any('redirect is good' in t.lower() or 'must be changed' in t.lower() for t in _titles(result))

    def test_neither_direction_produces_no_advisory(self):
        aw = ApexWwwCheck(apex='acme.com', www_host='www.acme.com', applicable=True, verdict='none')
        result = recommend(_profile(apex_www=aw))
        assert not any('redirect is good' in t.lower() or 'must be changed' in t.lower() for t in _titles(result))
