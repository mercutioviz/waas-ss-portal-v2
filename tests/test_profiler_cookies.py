"""Tests for cookie_analysis.analyze — Set-Cookie flag parsing."""

from app.profiler.cookie_analysis import analyze


class TestFlags:
    def test_secure_httponly_samesite_parsed(self):
        result = analyze(
            ['session=abc123; Secure; HttpOnly; SameSite=Lax'],
            is_https=True,
        )
        assert len(result) == 1
        c = result[0]
        assert c.name == 'session'
        assert c.secure is True
        assert c.http_only is True
        assert c.same_site == 'Lax'

    def test_absent_flags_default_false(self):
        result = analyze(['plain=x'], is_https=True)
        c = result[0]
        assert c.secure is False
        assert c.http_only is False
        assert c.same_site is None

    def test_samesite_case_insensitive_input(self):
        result = analyze(['s=1; SameSite=strict'], is_https=True)
        assert result[0].same_site == 'Strict'


class TestPersistence:
    def test_session_cookie_when_no_expiry(self):
        result = analyze(['s=1'], is_https=True)
        assert result[0].is_session is True

    def test_persistent_when_max_age(self):
        result = analyze(['pref=en; Max-Age=3600'], is_https=True)
        assert result[0].is_session is False
        assert result[0].max_age == 3600

    def test_persistent_when_expires(self):
        result = analyze(['pref=en; Expires=Wed, 09 Jun 2027 10:18:14 GMT'], is_https=True)
        assert result[0].is_session is False
        assert result[0].expires


class TestThirdParty:
    def test_first_party_when_domain_matches(self):
        result = analyze(
            ['x=1; Domain=example.com'],
            is_https=True,
            primary_domain='example.com',
        )
        assert result[0].third_party is False

    def test_first_party_when_subdomain(self):
        result = analyze(
            ['x=1; Domain=api.example.com'],
            is_https=True,
            primary_domain='example.com',
        )
        assert result[0].third_party is False

    def test_third_party_when_different_registrable_domain(self):
        result = analyze(
            ['x=1; Domain=partner.com'],
            is_https=True,
            primary_domain='example.com',
        )
        assert result[0].third_party is True


class TestInputShapes:
    def test_accepts_list(self):
        result = analyze(['a=1', 'b=2'], is_https=True)
        assert [c.name for c in result] == ['a', 'b']

    def test_empty_input_returns_empty(self):
        assert analyze(None, is_https=True) == []
        assert analyze([], is_https=True) == []

    def test_malformed_entry_skipped(self):
        # No `=` before `;` → not a cookie
        result = analyze(['not-a-cookie; Path=/', 'valid=v'], is_https=True)
        assert [c.name for c in result] == ['valid']
