"""Tests for subresources.discover — HTML → absolute URL list.

fetch_all is left to end-to-end verification because it involves network
concurrency; the discover pass is where the regression risk lives.
"""

from app.profiler.subresources import discover


BASE = 'https://acme.example.com/'


def _find(pairs, url):
    for u, k in pairs:
        if u == url:
            return k
    return None


class TestDiscoverBasic:
    def test_finds_script_src(self):
        html = '<script src="/js/app.js"></script>'
        pairs = discover(html, BASE)
        assert (BASE + 'js/app.js', 'script') in pairs

    def test_finds_stylesheet_link(self):
        html = '<link rel="stylesheet" href="/css/main.css">'
        pairs = discover(html, BASE)
        assert _find(pairs, BASE + 'css/main.css') == 'style'

    def test_finds_img_src(self):
        html = '<img src="/img/logo.png">'
        pairs = discover(html, BASE)
        assert _find(pairs, BASE + 'img/logo.png') == 'image'

    def test_finds_iframe_src(self):
        html = '<iframe src="https://player.vimeo.com/video/1"></iframe>'
        pairs = discover(html, BASE)
        assert _find(pairs, 'https://player.vimeo.com/video/1') == 'iframe'


class TestDiscoverEdgeCases:
    def test_srcset_yields_first_url(self):
        html = '<img srcset="/a.png 1x, /b.png 2x">'
        pairs = discover(html, BASE)
        urls = [u for u, _ in pairs]
        assert BASE + 'a.png' in urls
        assert BASE + 'b.png' in urls

    def test_data_src_lazy_loaded(self):
        html = '<img data-src="/lazy.png">'
        pairs = discover(html, BASE)
        assert _find(pairs, BASE + 'lazy.png') == 'image'

    def test_absolute_urls_kept_as_is(self):
        html = '<script src="https://cdn.example.net/js/a.js"></script>'
        pairs = discover(html, BASE)
        assert 'https://cdn.example.net/js/a.js' in [u for u, _ in pairs]

    def test_data_and_javascript_urls_skipped(self):
        html = (
            '<img src="data:image/png;base64,AAA">'
            '<a href="javascript:void(0)"></a>'
            '<img src="blob:1234">'
        )
        pairs = discover(html, BASE)
        assert pairs == []

    def test_dedup_within_html(self):
        html = '<script src="/a.js"></script><script src="/a.js"></script>'
        pairs = discover(html, BASE)
        urls = [u for u, _ in pairs]
        assert urls.count(BASE + 'a.js') == 1

    def test_inline_style_url_extracted(self):
        html = '<style>.hero { background: url("/img/hero.jpg"); }</style>'
        pairs = discover(html, BASE)
        assert BASE + 'img/hero.jpg' in [u for u, _ in pairs]

    def test_empty_html(self):
        assert discover('', BASE) == []
        assert discover(None, BASE) == []
