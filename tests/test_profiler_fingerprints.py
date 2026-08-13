"""Tests for tech-stack + CDN fingerprinting. Pure functions, no fixtures."""

import pytest

from app.profiler.fingerprints import identify_tech, is_cdn_ip


class TestIdentifyTech:
    def test_nginx_via_server_header(self):
        result = identify_tech({'Server': 'nginx/1.24.0'}, {}, '')
        assert 'nginx' in result

    def test_apache_via_server_header_case_insensitive(self):
        result = identify_tech({'server': 'Apache/2.4.58'}, {}, '')
        assert 'Apache' in result

    def test_php_via_x_powered_by(self):
        result = identify_tech({'X-Powered-By': 'PHP/8.2'}, {}, '')
        assert 'PHP' in result

    def test_wordpress_via_body(self):
        body = '<link rel="stylesheet" href="/wp-content/themes/twenty/style.css">'
        result = identify_tech({}, {}, body)
        assert 'WordPress' in result

    def test_wordpress_via_cookie_prefix(self):
        cookies = {'wordpress_logged_in_abcd1234': 'value'}
        result = identify_tech({}, cookies, '')
        assert 'WordPress' in result

    def test_next_js_via_body(self):
        body = '<script id="__NEXT_DATA__">{"props":{}}</script>'
        result = identify_tech({}, {}, body)
        assert 'Next.js' in result

    def test_cloudflare_via_server_and_cookie(self):
        result = identify_tech(
            {'Server': 'cloudflare'}, {'__cf_bm': 'x'}, '',
        )
        assert 'Cloudflare' in result

    def test_dedup(self):
        # WordPress signalled in both header and body → appears once
        result = identify_tech(
            {'X-Generator': 'WordPress 6.4'},
            {},
            'wp-content/themes/',
        )
        assert result.count('WordPress') == 1

    def test_multiple_stacks(self):
        result = identify_tech(
            {'Server': 'nginx', 'X-Powered-By': 'PHP/8.2'},
            {'PHPSESSID': 'x'},
            'wp-content/',
        )
        assert 'nginx' in result
        assert 'PHP' in result
        assert 'WordPress' in result

    def test_empty_input(self):
        assert identify_tech({}, {}, '') == []

    def test_none_inputs_are_safe(self):
        # Guard against accidental None from HttpResult defaults
        assert identify_tech(None, None, '') == []


class TestIsCdnIp:
    def test_cloudflare_range(self):
        assert is_cdn_ip('104.16.132.229') == 'Cloudflare'

    def test_fastly_range(self):
        assert is_cdn_ip('151.101.1.1') == 'Fastly'

    def test_akamai_range(self):
        assert is_cdn_ip('23.32.0.5') == 'Akamai'

    def test_public_non_cdn_returns_none(self):
        # Google DNS — not in any CDN range we ship
        assert is_cdn_ip('8.8.8.8') is None

    def test_private_ip_returns_none(self):
        assert is_cdn_ip('10.0.0.1') is None

    def test_garbage_returns_none(self):
        assert is_cdn_ip('not-an-ip') is None
        assert is_cdn_ip('') is None
