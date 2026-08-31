"""Tests for the apex/www redirect-direction check.

`resolve`/`is_public_ip` are passed in directly (matching the real
signature `probe.py` injects) rather than monkeypatched — this module has
no module-level DNS/SSRF functions of its own.
"""

import pytest
import requests_mock

from app.profiler.apex_www import analyze


def _resolver(table):
    """table: {hostname: [addrs]} — missing hosts raise OSError, matching
    the real `probe._resolve` contract."""
    def _resolve(hostname):
        if hostname not in table:
            raise OSError(f'no such host: {hostname}')
        return table[hostname]
    return _resolve


def _always_public(ip):
    return True


@pytest.fixture
def http():
    with requests_mock.Mocker() as m:
        yield m


class TestApplicability:
    def test_non_www_subdomain_not_applicable(self):
        result = analyze('shop.example.com', resolve=_resolver({}), is_public_ip=_always_public)
        assert result.applicable is False

    def test_bare_ip_not_applicable(self):
        result = analyze('203.0.113.5', resolve=_resolver({}), is_public_ip=_always_public)
        assert result.applicable is False

    def test_apex_is_applicable(self):
        result = analyze(
            'eesforjobs.com',
            resolve=_resolver({'eesforjobs.com': ['1.2.3.4'], 'www.eesforjobs.com': ['1.2.3.4']}),
            is_public_ip=_always_public,
        )
        assert result.applicable is True
        assert result.apex == 'eesforjobs.com'
        assert result.www_host == 'www.eesforjobs.com'

    def test_www_target_is_applicable(self, http):
        http.get('https://eesforjobs.com/', status_code=200)
        http.get('https://www.eesforjobs.com/', status_code=301, headers={'Location': 'https://eesforjobs.com/'})
        result = analyze(
            'www.eesforjobs.com',
            resolve=_resolver({'eesforjobs.com': ['1.2.3.4'], 'www.eesforjobs.com': ['1.2.3.4']}),
            is_public_ip=_always_public,
        )
        assert result.applicable is True
        assert result.apex == 'eesforjobs.com'
        assert result.www_host == 'www.eesforjobs.com'


class TestBadDirection:
    def test_www_redirects_to_apex_is_a_warning(self, http):
        http.get('https://eesforjobs.com/', status_code=200)
        http.get('https://www.eesforjobs.com/', status_code=301, headers={'Location': 'https://eesforjobs.com/'})
        resolve = _resolver({'eesforjobs.com': ['1.2.3.4'], 'www.eesforjobs.com': ['1.2.3.4']})

        result = analyze('eesforjobs.com', resolve=resolve, is_public_ip=_always_public)

        assert result.www_redirects_to_apex is True
        assert result.apex_redirects_to_www is False
        assert result.verdict == 'warning'
        assert result.message == 'WARNING - must be changed'

    def test_caught_when_profiling_the_www_fqdn_directly(self, http):
        http.get('https://eesforjobs.com/', status_code=200)
        http.get('https://www.eesforjobs.com/', status_code=301, headers={'Location': 'https://eesforjobs.com/'})
        resolve = _resolver({'eesforjobs.com': ['1.2.3.4'], 'www.eesforjobs.com': ['1.2.3.4']})

        result = analyze('www.eesforjobs.com', resolve=resolve, is_public_ip=_always_public)

        assert result.verdict == 'warning'
        assert result.message == 'WARNING - must be changed'


class TestGoodDirection:
    def test_apex_redirects_to_www_is_good(self, http):
        http.get('https://acme.com/', status_code=301, headers={'Location': 'https://www.acme.com/'})
        http.get('https://www.acme.com/', status_code=200)
        resolve = _resolver({'acme.com': ['1.2.3.4'], 'www.acme.com': ['1.2.3.4']})

        result = analyze('acme.com', resolve=resolve, is_public_ip=_always_public)

        assert result.apex_redirects_to_www is True
        assert result.www_redirects_to_apex is False
        assert result.verdict == 'good'
        assert result.message == 'Redirect is good'


class TestNeitherDirection:
    def test_both_serve_directly_is_no_advisory(self, http):
        http.get('https://acme.com/', status_code=200)
        http.get('https://www.acme.com/', status_code=200)
        resolve = _resolver({'acme.com': ['1.2.3.4'], 'www.acme.com': ['1.2.3.4']})

        result = analyze('acme.com', resolve=resolve, is_public_ip=_always_public)

        assert result.verdict == 'none'
        assert result.message is None


class TestDnsAndSsrfGuards:
    def test_www_dns_missing_skips_fetch_without_crashing(self, http):
        http.get('https://acme.com/', status_code=200)
        resolve = _resolver({'acme.com': ['1.2.3.4']})  # www.acme.com absent -> OSError

        result = analyze('acme.com', resolve=resolve, is_public_ip=_always_public)

        assert result.apex_dns_found is True
        assert result.www_dns_found is False
        assert result.www_status is None
        assert result.verdict == 'none'

    def test_private_ip_counterpart_skips_fetch_without_crashing(self, http):
        http.get('https://acme.com/', status_code=200)
        resolve = _resolver({'acme.com': ['1.2.3.4'], 'www.acme.com': ['10.0.0.1']})
        is_public = lambda ip: ip != '10.0.0.1'

        result = analyze('acme.com', resolve=resolve, is_public_ip=is_public)

        # DNS did resolve, but we never issued the request to the non-public address.
        assert result.www_dns_found is True
        assert result.www_status is None
        assert result.apex_status == 200
        assert all('www.acme.com' not in r.url for r in http.request_history)
