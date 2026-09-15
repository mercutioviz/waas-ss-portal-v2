"""Tests for cache_analysis — pure functions over headers / subresource hits."""

from app.profiler.cache_analysis import analyze, parse_cache_control, summarize_assets
from app.profiler.schemas import SubresourceHit


class TestParseCacheControl:
    def test_absent_returns_none(self):
        assert parse_cache_control(None) is None
        assert parse_cache_control('') is None

    def test_no_store(self):
        assert parse_cache_control('no-store')['no_store'] is True

    def test_public_and_max_age(self):
        r = parse_cache_control('public, max-age=3600')
        assert r['public'] is True
        assert r['max_age'] == 3600
        assert r['no_store'] is False

    def test_private_no_cache_must_revalidate(self):
        r = parse_cache_control('private, no-cache, must-revalidate')
        assert r['private'] is True
        assert r['no_cache'] is True
        assert r['must_revalidate'] is True

    def test_immutable_and_stale_while_revalidate(self):
        r = parse_cache_control('max-age=31536000, immutable, stale-while-revalidate=60')
        assert r['immutable'] is True
        assert r['stale_while_revalidate'] == 60

    def test_s_maxage_and_proxy_revalidate(self):
        r = parse_cache_control('s-maxage=120, proxy-revalidate')
        assert r['s_maxage'] == 120
        assert r['proxy_revalidate'] is True

    def test_malformed_max_age_is_none(self):
        r = parse_cache_control('max-age=notanumber')
        assert r['max_age'] is None

    def test_case_insensitive_directives(self):
        r = parse_cache_control('NO-STORE, Max-Age=10')
        assert r['no_store'] is True
        assert r['max_age'] == 10


class TestAnalyzePage:
    def test_all_absent(self):
        r = analyze({})
        assert r.cache_control is None
        assert r.etag is False
        assert r.last_modified is False
        assert r.vary is None
        assert r.age is None
        assert r.edge_hit is False

    def test_etag_and_last_modified_present(self):
        r = analyze({'ETag': '"abc123"', 'Last-Modified': 'Tue, 01 Jan 2026 00:00:00 GMT'})
        assert r.etag is True
        assert r.last_modified is True

    def test_vary_and_age(self):
        r = analyze({'Vary': 'Accept-Encoding', 'Age': '42'})
        assert r.vary == 'Accept-Encoding'
        assert r.age == 42

    def test_edge_hit_from_cf_cache_status(self):
        assert analyze({'CF-Cache-Status': 'HIT'}).edge_hit is True

    def test_edge_hit_from_x_cache(self):
        assert analyze({'X-Cache': 'cache-lax1234 HIT'}).edge_hit is True

    def test_edge_miss_is_not_hit(self):
        assert analyze({'X-Cache': 'MISS'}).edge_hit is False

    def test_case_insensitive_header_lookup(self):
        r = analyze({'cache-control': 'no-store', 'etag': '"x"'})
        assert r.cache_control['no_store'] is True
        assert r.etag is True


class TestSummarizeAssets:
    def _hit(self, kind='script', cache_control=None, etag=False, max_age=None, error=None):
        return SubresourceHit(
            url=f'https://acme.example.com/{kind}.file', host='acme.example.com', kind=kind,
            cache_control=cache_control, etag=etag, max_age=max_age, error=error,
        )

    def test_empty_hits(self):
        s = summarize_assets([])
        assert s.analyzed == 0

    def test_non_static_kinds_ignored(self):
        s = summarize_assets([self._hit(kind='iframe'), self._hit(kind='other')])
        assert s.analyzed == 0

    def test_errored_hits_ignored(self):
        s = summarize_assets([self._hit(error='timeout')])
        assert s.analyzed == 0

    def test_cacheable_asset_counted(self):
        s = summarize_assets([self._hit(cache_control='public, max-age=86400', max_age=86400)])
        assert s.analyzed == 1
        assert s.cacheable == 1
        assert s.long_lived == 1

    def test_no_store_asset_counted(self):
        s = summarize_assets([self._hit(cache_control='no-store')])
        assert s.no_store == 1
        assert s.cacheable == 0

    def test_missing_validators_when_no_etag_and_no_max_age(self):
        s = summarize_assets([self._hit()])
        assert s.missing_validators == 1
        assert 'script.file' in s.examples[0]

    def test_etag_present_with_no_lifetime_is_revalidate_only(self):
        s = summarize_assets([self._hit(etag=True)])
        assert s.missing_validators == 0
        assert s.revalidate_only == 1
        assert 'script.file' in s.revalidate_examples[0]

    def test_etag_present_with_lifetime_is_cacheable_not_revalidate_only(self):
        s = summarize_assets([self._hit(cache_control='max-age=3600', max_age=3600, etag=True)])
        assert s.cacheable == 1
        assert s.revalidate_only == 0

    def test_no_store_takes_priority_over_etag(self):
        s = summarize_assets([self._hit(cache_control='no-store', etag=True)])
        assert s.no_store == 1
        assert s.revalidate_only == 0
        assert s.cacheable == 0

    def test_examples_capped_at_five(self):
        hits = [self._hit(kind='script') for _ in range(8)]
        s = summarize_assets(hits)
        assert s.missing_validators == 8
        assert len(s.examples) == 5

    def test_revalidate_examples_capped_at_five(self):
        hits = [self._hit(kind='script', etag=True) for _ in range(8)]
        s = summarize_assets(hits)
        assert s.revalidate_only == 8
        assert len(s.revalidate_examples) == 5

    def test_short_max_age_is_not_long_lived(self):
        s = summarize_assets([self._hit(cache_control='max-age=60', max_age=60)])
        assert s.long_lived == 0
        assert s.cacheable == 1

    def test_buckets_are_mutually_exclusive_and_exhaustive(self):
        hits = [
            self._hit(cache_control='no-store'),
            self._hit(cache_control='max-age=86400', max_age=86400),
            self._hit(etag=True),
            self._hit(),
        ]
        s = summarize_assets(hits)
        assert s.no_store == 1
        assert s.cacheable == 1
        assert s.revalidate_only == 1
        assert s.missing_validators == 1
        assert s.no_store + s.cacheable + s.revalidate_only + s.missing_validators == s.analyzed == 4
