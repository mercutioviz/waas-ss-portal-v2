"""Tests for the probe pipeline. Network I/O is mocked at three seams:
- `_resolve` for DNS
- `_do_tls_handshake` for TLS
- `requests_mock` fixture for outbound HTTP
"""

import pytest
import requests
import requests_mock

from app.profiler import probe as probe_mod
from app.profiler.probe import (
    SsrfRejected,
    _is_public_ip,
    run_probe,
)
from app.profiler.schemas import TlsResult


@pytest.fixture
def stub_dns(monkeypatch):
    """Return a helper that fixes _resolve() to a chosen set of addresses."""
    def _install(addresses):
        monkeypatch.setattr(probe_mod, '_resolve', lambda host: list(addresses))
    return _install


@pytest.fixture
def stub_tls(monkeypatch):
    """Return a helper that fixes _do_tls_handshake() to a chosen TlsResult."""
    def _install(result):
        monkeypatch.setattr(probe_mod, '_do_tls_handshake', lambda *a, **kw: result)
    return _install


@pytest.fixture
def http():
    with requests_mock.Mocker() as m:
        yield m


class TestSsrfGate:
    @pytest.mark.parametrize('ip,expected', [
        ('93.184.216.34', True),   # example.com
        ('8.8.8.8', True),
        ('127.0.0.1', False),
        ('10.0.0.1', False),
        ('172.20.1.1', False),
        ('192.168.1.1', False),
        ('169.254.169.254', False),  # AWS/GCP metadata service
        ('::1', False),
        ('fd00::1', False),          # ULA
        ('fe80::1', False),          # link-local v6
    ])
    def test_public_ip_classification(self, ip, expected):
        assert _is_public_ip(ip) is expected

    def test_probe_rejects_private_address(self, stub_dns):
        stub_dns(['10.0.0.1'])
        with pytest.raises(SsrfRejected):
            run_probe('https://internal.example.com/')

    def test_probe_rejects_loopback(self, stub_dns):
        stub_dns(['127.0.0.1'])
        with pytest.raises(SsrfRejected):
            run_probe('http://127.0.0.1:5000/admin')

    def test_probe_rejects_link_local(self, stub_dns):
        stub_dns(['169.254.169.254'])
        with pytest.raises(SsrfRejected):
            run_probe('https://metadata.internal/')

    def test_probe_rejects_mix_of_public_and_private(self, stub_dns):
        # DNS rebinding defense: even one private IP in the set = reject
        stub_dns(['93.184.216.34', '10.0.0.1'])
        with pytest.raises(SsrfRejected):
            run_probe('https://sneaky.example.com/')


class TestDnsFailure:
    def test_returns_early_with_dns_error(self, monkeypatch):
        def _raise(*a, **kw):
            raise OSError('nodename nor servname provided')
        monkeypatch.setattr(probe_mod, '_resolve', _raise)
        profile = run_probe('https://no-such-host.example.invalid/')
        assert profile.dns.error is not None
        assert profile.confidence == 'low'
        # No downstream steps ran
        assert profile.https_root.status is None


class TestHappyPath:
    def test_clean_https_site_produces_high_confidence_profile(
        self, stub_dns, stub_tls, http,
    ):
        stub_dns(['93.184.216.34'])
        stub_tls(TlsResult(
            handshake_ok=True,
            tls_version='TLSv1.3',
            cipher='TLS_AES_256_GCM_SHA384',
            cert_subject='CN=example.com',
            cert_not_after='Jan  1 12:00:00 2027 GMT',
        ))
        http.get('http://example.com/', status_code=301, headers={'Location': 'https://example.com/'})
        http.get('https://example.com/', status_code=200, headers={
            'Server': 'nginx/1.24.0',
            'Content-Type': 'text/html; charset=utf-8',
        }, text='<html><body>Hello</body></html>')
        http.get('https://www.example.com/', status_code=200)
        http.get('https://example.com/robots.txt', status_code=200,
                 headers={'Content-Type': 'text/plain'},
                 text='User-agent: *\nDisallow:\n')

        profile = run_probe('https://example.com/')

        assert profile.tls.handshake_ok
        assert profile.tls.tls_version == 'TLSv1.3'
        assert profile.http_root.status == 301
        assert profile.http_root.redirect_target == 'https://example.com/'
        assert profile.https_root.status == 200
        assert 'nginx' in profile.tech_names
        assert profile.robots_txt.startswith('User-agent:')
        assert profile.robots.present is True
        assert profile.confidence == 'high'
        assert profile.apex_www.verdict == 'none'

    def test_wordpress_body_is_fingerprinted(self, stub_dns, stub_tls, http):
        stub_dns(['93.184.216.34'])
        stub_tls(TlsResult(handshake_ok=True, tls_version='TLSv1.3'))
        http.get('http://example.com/', status_code=301, headers={'Location': 'https://example.com/'})
        http.get('https://example.com/', status_code=200, headers={'Server': 'nginx'},
                 text='<link href="/wp-content/themes/x.css"><input type="password">')
        http.get('https://www.example.com/', status_code=200)
        http.get('https://example.com/robots.txt', status_code=404)

        profile = run_probe('https://example.com/')
        assert 'WordPress' in profile.tech_names


class TestApexWwwIntegration:
    def test_www_to_apex_redirect_surfaces_as_warning(self, stub_dns, stub_tls, http):
        stub_dns(['93.184.216.34'])
        stub_tls(TlsResult(handshake_ok=True, tls_version='TLSv1.3'))
        http.get('http://example.com/', status_code=301, headers={'Location': 'https://example.com/'})
        http.get('https://example.com/', status_code=200, text='')
        http.get('https://www.example.com/', status_code=301, headers={'Location': 'https://example.com/'})
        http.get('https://example.com/robots.txt', status_code=404)

        profile = run_probe('https://example.com/')

        assert profile.apex_www.applicable is True
        assert profile.apex_www.verdict == 'warning'
        assert profile.apex_www.message == 'WARNING - must be changed'


class TestLowConfidenceOutcomes:
    def test_tls_failure_flags_low_confidence(self, stub_dns, stub_tls, http):
        stub_dns(['93.184.216.34'])
        stub_tls(TlsResult(handshake_ok=False, error='cert expired'))
        http.get('http://example.com/', status_code=200)
        http.get('https://example.com/', status_code=200, text='')
        http.get('https://www.example.com/', status_code=200)
        http.get('https://example.com/robots.txt', status_code=404)

        profile = run_probe('https://example.com/')
        assert profile.confidence == 'low'
        assert profile.tls.error == 'cert expired'

    def test_auth_walled_site_flags_low_confidence(self, stub_dns, stub_tls, http):
        stub_dns(['93.184.216.34'])
        stub_tls(TlsResult(handshake_ok=True, tls_version='TLSv1.3'))
        http.get('http://example.com/', status_code=200)
        http.get('https://example.com/', status_code=401, text='Unauthorized')
        http.get('https://www.example.com/', status_code=200)
        http.get('https://example.com/robots.txt', status_code=404)

        profile = run_probe('https://example.com/')
        assert profile.confidence == 'low'
        assert any('auth-walled' in s for s in profile.auth_surface)


class TestCdnDetection:
    def test_cloudflare_ip_populates_cdn_field(self, stub_dns, stub_tls, http):
        stub_dns(['104.16.132.229'])
        stub_tls(TlsResult(handshake_ok=True, tls_version='TLSv1.3'))
        http.get('http://acme.com/', status_code=200)
        http.get('https://acme.com/', status_code=200, text='')
        http.get('https://www.acme.com/', status_code=200)
        http.get('https://acme.com/robots.txt', status_code=404)

        profile = run_probe('https://acme.com/')
        assert profile.cdn == 'Cloudflare'
        assert 'Cloudflare' in profile.tech_names


class TestRobotsFetch:
    """The robots.txt step used to require a bare 200 on the originally-typed
    host over hardcoded https, which silently missed real files."""

    def _base(self, stub_dns, stub_tls, http, host='example.com'):
        stub_dns(['93.184.216.34'])
        stub_tls(TlsResult(handshake_ok=True, tls_version='TLSv1.3'))
        http.get(f'http://{host}/', status_code=301,
                 headers={'Location': f'https://{host}/'})
        http.get(f'https://www.{host}/', status_code=404)

    def test_redirected_robots_is_followed(self, stub_dns, stub_tls, http):
        self._base(stub_dns, stub_tls, http)
        http.get('https://example.com/', status_code=200, text='')
        http.get('https://example.com/robots.txt', status_code=301,
                 headers={'Location': 'https://example.com/static/robots.txt'})
        http.get('https://example.com/static/robots.txt', status_code=200,
                 headers={'Content-Type': 'text/plain'},
                 text='User-agent: *\nDisallow: /admin/\n')

        profile = run_probe('https://example.com/')
        assert profile.robots.present is True
        assert profile.robots.sensitive_paths == ['/admin/']

    def test_robots_is_read_from_the_post_redirect_host(self, stub_dns, stub_tls, http):
        """Landing page redirects apex → www, so www's robots.txt is the one
        that governs the traffic we care about."""
        stub_dns(['93.184.216.34'])
        stub_tls(TlsResult(handshake_ok=True, tls_version='TLSv1.3'))
        http.get('http://example.com/', status_code=301,
                 headers={'Location': 'https://example.com/'})
        # allow_redirects=True on the landing page → ends up on www.
        http.get('https://example.com/', status_code=301,
                 headers={'Location': 'https://www.example.com/'})
        http.get('https://www.example.com/', status_code=200, text='')
        http.get('https://example.com/robots.txt', status_code=200,
                 headers={'Content-Type': 'text/plain'},
                 text='User-agent: *\nDisallow: /apex-only/\n')
        http.get('https://www.example.com/robots.txt', status_code=200,
                 headers={'Content-Type': 'text/plain'},
                 text='User-agent: *\nDisallow: /wp-admin/\n')

        profile = run_probe('https://example.com/')
        assert profile.robots.sensitive_paths == ['/wp-admin/']

    def test_html_catch_all_is_not_treated_as_robots(self, stub_dns, stub_tls, http):
        self._base(stub_dns, stub_tls, http)
        http.get('https://example.com/', status_code=200, text='')
        http.get('https://example.com/robots.txt', status_code=200,
                 headers={'Content-Type': 'text/html'},
                 text='<!doctype html><html><body>Not found</body></html>')

        profile = run_probe('https://example.com/')
        assert profile.robots.present is False
        assert profile.robots.fetch_reason == 'not_text'
        assert profile.robots_txt is None

    def test_html_body_without_content_type_is_rejected(self, stub_dns, stub_tls, http):
        self._base(stub_dns, stub_tls, http)
        http.get('https://example.com/', status_code=200, text='')
        http.get('https://example.com/robots.txt', status_code=200,
                 text='<html><body>SPA shell</body></html>')

        profile = run_probe('https://example.com/')
        assert profile.robots.fetch_reason == 'not_text'

    def test_missing_content_type_on_real_robots_is_accepted(self, stub_dns, stub_tls, http):
        """Plenty of servers send robots.txt with no Content-Type; rejecting
        those would lose genuine files."""
        self._base(stub_dns, stub_tls, http)
        http.get('https://example.com/', status_code=200, text='')
        http.get('https://example.com/robots.txt', status_code=200,
                 text='User-agent: *\nDisallow: /backup/\n')

        profile = run_probe('https://example.com/')
        assert profile.robots.present is True
        assert profile.robots.sensitive_paths == ['/backup/']

    def test_404_records_not_found(self, stub_dns, stub_tls, http):
        self._base(stub_dns, stub_tls, http)
        http.get('https://example.com/', status_code=200, text='')
        http.get('https://example.com/robots.txt', status_code=404)

        profile = run_probe('https://example.com/')
        assert profile.robots.present is False
        assert profile.robots.fetch_reason == 'not_found'
        assert profile.robots.fetch_status == 404

    def test_oversized_robots_is_flagged_but_fully_parsed(self, stub_dns, stub_tls, http):
        self._base(stub_dns, stub_tls, http)
        http.get('https://example.com/', status_code=200, text='')
        # Long paths so we clear the 4 KB display cap well before the
        # parser's own MAX_RULES_PER_GROUP limit.
        filler = '\n'.join(f'Disallow: /padding-segment-number-{i}/' for i in range(120))
        body = 'User-agent: *\n' + filler + '\nDisallow: /admin/\n'
        assert len(body) > probe_mod.ROBOTS_RAW_DISPLAY_CHARS
        http.get('https://example.com/robots.txt', status_code=200,
                 headers={'Content-Type': 'text/plain'}, text=body)

        profile = run_probe('https://example.com/')
        assert profile.robots.truncated is True
        assert len(profile.robots_txt) == probe_mod.ROBOTS_RAW_DISPLAY_CHARS
        # The /admin/ rule lives past the display cap — parsing saw it anyway.
        assert '/admin/' in profile.robots.sensitive_paths

    def test_http_target_falls_back_to_http_robots(self, stub_dns, stub_tls, http):
        """When HTTPS is unreachable there is no final_url to inherit, so the
        origin falls back to the scheme the user actually gave us."""
        stub_dns(['93.184.216.34'])
        stub_tls(TlsResult(handshake_ok=False, error='no TLS'))
        http.get('http://example.com/', status_code=200, text='')
        http.get('https://example.com/', exc=requests.exceptions.ConnectionError)
        http.get('https://www.example.com/', status_code=404)
        http.get('http://example.com/robots.txt', status_code=200,
                 headers={'Content-Type': 'text/plain'},
                 text='User-agent: *\nDisallow: /admin/\n')

        profile = run_probe('http://example.com/')
        assert profile.robots.present is True
        assert profile.robots.sensitive_paths == ['/admin/']

    def test_fallback_origin_keeps_a_non_default_port(self, stub_dns, stub_tls, http):
        stub_dns(['93.184.216.34'])
        stub_tls(TlsResult(handshake_ok=True, tls_version='TLSv1.3'))
        http.get('http://example.com/', status_code=200)
        http.get('https://example.com/', exc=requests.exceptions.ConnectionError)
        http.get('https://www.example.com/', status_code=404)
        http.get('https://example.com:8443/robots.txt', status_code=200,
                 headers={'Content-Type': 'text/plain'},
                 text='User-agent: *\nDisallow: /admin/\n')

        profile = run_probe('https://example.com:8443/')
        assert profile.robots.present is True


class TestUrlNormalization:
    def test_bare_hostname_gets_https_scheme(self, stub_dns, stub_tls, http):
        stub_dns(['93.184.216.34'])
        stub_tls(TlsResult(handshake_ok=True, tls_version='TLSv1.3'))
        http.get('http://example.com/', status_code=200)
        http.get('https://example.com/', status_code=200, text='')
        http.get('https://www.example.com/', status_code=200)
        http.get('https://example.com/robots.txt', status_code=404)

        profile = run_probe('example.com')
        assert profile.target_url == 'https://example.com/'
