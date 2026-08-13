"""Tests for security_headers.analyze — pure function of the header dict."""

from app.profiler.security_headers import analyze


class TestHsts:
    def test_absent_returns_none(self):
        assert analyze({}).hsts is None

    def test_parses_max_age(self):
        r = analyze({'Strict-Transport-Security': 'max-age=31536000'})
        assert r.hsts is not None
        assert r.hsts['max_age'] == 31536000
        assert r.hsts['include_subdomains'] is False
        assert r.hsts['preload'] is False

    def test_parses_include_subdomains_and_preload(self):
        r = analyze({'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload'})
        assert r.hsts['max_age'] == 63072000
        assert r.hsts['include_subdomains'] is True
        assert r.hsts['preload'] is True

    def test_malformed_max_age_is_none(self):
        r = analyze({'Strict-Transport-Security': 'max-age=notanumber; preload'})
        assert r.hsts['max_age'] is None
        assert r.hsts['preload'] is True


class TestCsp:
    def test_absent_returns_none(self):
        assert analyze({}).csp is None

    def test_counts_directives_and_flags_unsafe_inline(self):
        r = analyze({
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src *",
        })
        assert r.csp['directive_count'] == 3
        assert r.csp['has_unsafe_inline'] is True
        assert r.csp['has_unsafe_eval'] is False

    def test_flags_unsafe_eval(self):
        r = analyze({'Content-Security-Policy': "script-src 'unsafe-eval'"})
        assert r.csp['has_unsafe_eval'] is True

    def test_raw_is_truncated(self):
        long = 'default-src *; ' + 'foo-src bar; ' * 500
        r = analyze({'Content-Security-Policy': long})
        assert len(r.csp['raw']) <= 4096


class TestOtherHeaders:
    def test_x_frame_options(self):
        assert analyze({'X-Frame-Options': 'DENY'}).x_frame_options == 'DENY'
        assert analyze({}).x_frame_options is None

    def test_x_content_type_options(self):
        assert analyze({'X-Content-Type-Options': 'nosniff'}).x_content_type_options == 'nosniff'

    def test_referrer_policy(self):
        assert analyze({'Referrer-Policy': 'no-referrer'}).referrer_policy == 'no-referrer'

    def test_case_insensitive_lookup(self):
        # Real servers send in various casings — lookup must be CI.
        r = analyze({'strict-transport-security': 'max-age=100'})
        assert r.hsts is not None

    def test_coop_coep_corp(self):
        r = analyze({
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Embedder-Policy': 'require-corp',
            'Cross-Origin-Resource-Policy': 'same-site',
        })
        assert r.coop == 'same-origin'
        assert r.coep == 'require-corp'
        assert r.corp == 'same-site'
