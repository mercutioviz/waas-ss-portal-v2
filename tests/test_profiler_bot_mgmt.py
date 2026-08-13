"""Tests for bot_mgmt.classify — subresource host → vendor label."""

from app.profiler.bot_mgmt import classify


def _pair(host, url=None):
    return (host, url or f'https://{host}/anything.js')


class TestClassify:
    def test_recaptcha_detected_via_host(self):
        result = classify([_pair('www.google.com', 'https://www.google.com/recaptcha/api.js')])
        assert any(v.name == 'reCAPTCHA' for v in result)

    def test_hcaptcha_detected(self):
        result = classify([_pair('newassets.hcaptcha.com')])
        assert any(v.name == 'hCaptcha' for v in result)

    def test_cloudflare_turnstile_detected(self):
        result = classify([_pair('challenges.cloudflare.com')])
        assert any(v.name == 'Cloudflare Turnstile' for v in result)

    def test_datadome_detected(self):
        result = classify([_pair('js.datadome.co')])
        assert any(v.name == 'DataDome' for v in result)

    def test_no_match_returns_empty(self):
        assert classify([_pair('cdn.example.com')]) == []

    def test_dedup_by_vendor(self):
        # Two hCaptcha hits → one vendor entry
        result = classify([
            _pair('newassets.hcaptcha.com'),
            _pair('hcaptcha.com'),
        ])
        assert sum(1 for v in result if v.name == 'hCaptcha') == 1

    def test_empty_input(self):
        assert classify([]) == []
