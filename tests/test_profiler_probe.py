"""Tests for the probe pipeline. Network I/O is mocked at three seams:
- `_resolve` for DNS
- `_do_tls_handshake` for TLS
- `requests_mock` fixture for outbound HTTP
"""

import pytest
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
        http.get('https://example.com/robots.txt', status_code=200, text='User-agent: *\nDisallow:\n')

        profile = run_probe('https://example.com/')

        assert profile.tls.handshake_ok
        assert profile.tls.tls_version == 'TLSv1.3'
        assert profile.http_root.status == 301
        assert profile.http_root.redirect_target == 'https://example.com/'
        assert profile.https_root.status == 200
        assert 'nginx' in profile.tech_stack
        assert profile.robots_txt.startswith('User-agent:')
        assert profile.confidence == 'high'

    def test_wordpress_body_is_fingerprinted(self, stub_dns, stub_tls, http):
        stub_dns(['93.184.216.34'])
        stub_tls(TlsResult(handshake_ok=True, tls_version='TLSv1.3'))
        http.get('http://example.com/', status_code=301, headers={'Location': 'https://example.com/'})
        http.get('https://example.com/', status_code=200, headers={'Server': 'nginx'},
                 text='<link href="/wp-content/themes/x.css"><input type="password">')
        http.get('https://example.com/robots.txt', status_code=404)

        profile = run_probe('https://example.com/')
        assert 'WordPress' in profile.tech_stack


class TestLowConfidenceOutcomes:
    def test_tls_failure_flags_low_confidence(self, stub_dns, stub_tls, http):
        stub_dns(['93.184.216.34'])
        stub_tls(TlsResult(handshake_ok=False, error='cert expired'))
        http.get('http://example.com/', status_code=200)
        http.get('https://example.com/', status_code=200, text='')
        http.get('https://example.com/robots.txt', status_code=404)

        profile = run_probe('https://example.com/')
        assert profile.confidence == 'low'
        assert profile.tls.error == 'cert expired'

    def test_auth_walled_site_flags_low_confidence(self, stub_dns, stub_tls, http):
        stub_dns(['93.184.216.34'])
        stub_tls(TlsResult(handshake_ok=True, tls_version='TLSv1.3'))
        http.get('http://example.com/', status_code=200)
        http.get('https://example.com/', status_code=401, text='Unauthorized')
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
        http.get('https://acme.com/robots.txt', status_code=404)

        profile = run_probe('https://acme.com/')
        assert profile.cdn == 'Cloudflare'
        assert 'Cloudflare' in profile.tech_stack


class TestUrlNormalization:
    def test_bare_hostname_gets_https_scheme(self, stub_dns, stub_tls, http):
        stub_dns(['93.184.216.34'])
        stub_tls(TlsResult(handshake_ok=True, tls_version='TLSv1.3'))
        http.get('http://example.com/', status_code=200)
        http.get('https://example.com/', status_code=200, text='')
        http.get('https://example.com/robots.txt', status_code=404)

        profile = run_probe('example.com')
        assert profile.target_url == 'https://example.com/'
