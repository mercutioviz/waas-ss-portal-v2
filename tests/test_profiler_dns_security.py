"""Tests for dns_security._find_spf / _find_dmarc — the string-parsing side.

The `analyze()` function is left to end-to-end verification because it
performs live DNS queries; the parsers are where the regression risk lives.
"""

from app.profiler.dns_security import _find_spf, _find_dmarc


class TestFindSpf:
    def test_finds_spf_among_txt_records(self):
        txts = [
            '"google-site-verification=abc"',
            '"v=spf1 include:_spf.example.com -all"',
        ]
        assert _find_spf(txts) == 'v=spf1 include:_spf.example.com -all'

    def test_none_when_absent(self):
        assert _find_spf(['"random text"', '"foo=bar"']) is None

    def test_join_fragmented_txt(self):
        # dnspython returns long TXT as `"chunk1" "chunk2"` — join those.
        txts = ['"v=spf1 " "include:one.example.com -all"']
        assert _find_spf(txts) == 'v=spf1 include:one.example.com -all'

    def test_empty_list(self):
        assert _find_spf([]) is None


class TestFindDmarc:
    def test_finds_dmarc(self):
        txts = ['"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"']
        assert _find_dmarc(txts) is not None
        assert _find_dmarc(txts).startswith('v=DMARC1')

    def test_none_when_absent(self):
        assert _find_dmarc(['"v=spf1 -all"']) is None
