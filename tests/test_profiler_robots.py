"""Tests for the robots.txt parser — a pure function over the fetched text."""

from app.profiler.robots import (
    MAX_GROUPS,
    MAX_SENSITIVE,
    absent,
    parse,
)


class TestBasicParsing:
    def test_empty_text_is_present_but_bare(self):
        r = parse('')
        assert r.present is True
        assert r.groups == []
        assert r.total_disallow_count == 0

    def test_single_group(self):
        r = parse('User-agent: *\nDisallow: /admin/\nDisallow: /tmp/\n')
        assert len(r.groups) == 1
        assert r.groups[0].user_agents == ['*']
        assert r.groups[0].disallow == ['/admin/', '/tmp/']
        assert r.total_disallow_count == 2

    def test_allow_and_disallow(self):
        r = parse('User-agent: *\nDisallow: /files/\nAllow: /files/public/\n')
        assert r.groups[0].disallow == ['/files/']
        assert r.groups[0].allow == ['/files/public/']

    def test_consecutive_user_agents_share_one_group(self):
        r = parse('User-agent: Googlebot\nUser-agent: Bingbot\nDisallow: /x/\n')
        assert len(r.groups) == 1
        assert r.groups[0].user_agents == ['Googlebot', 'Bingbot']
        assert r.groups[0].disallow == ['/x/']

    def test_rule_line_closes_the_group_header(self):
        r = parse(
            'User-agent: Googlebot\n'
            'Disallow: /a/\n'
            'User-agent: Bingbot\n'
            'Disallow: /b/\n'
        )
        assert len(r.groups) == 2
        assert r.groups[0].user_agents == ['Googlebot']
        assert r.groups[1].user_agents == ['Bingbot']
        assert r.groups[1].disallow == ['/b/']

    def test_directive_names_are_case_insensitive(self):
        r = parse('USER-AGENT: *\nDISALLOW: /admin/\nSITEMAP: https://x.test/s.xml\n')
        assert r.groups[0].user_agents == ['*']
        assert r.groups[0].disallow == ['/admin/']
        assert r.sitemaps == ['https://x.test/s.xml']

    def test_rules_before_any_user_agent_get_an_implicit_wildcard_group(self):
        r = parse('Disallow: /admin/\n')
        assert r.groups[0].user_agents == ['*']
        assert r.groups[0].disallow == ['/admin/']


class TestMessyInput:
    def test_comments_are_stripped(self):
        r = parse('# leading comment\nUser-agent: *  # inline\nDisallow: /admin/ # why\n')
        assert r.groups[0].user_agents == ['*']
        assert r.groups[0].disallow == ['/admin/']

    def test_full_line_comment_does_not_create_a_group(self):
        r = parse('#User-agent: *\n')
        assert r.groups == []

    def test_crlf_line_endings(self):
        r = parse('User-agent: *\r\nDisallow: /admin/\r\n')
        assert r.groups[0].disallow == ['/admin/']

    def test_utf8_bom_is_stripped(self):
        r = parse('﻿User-agent: *\nDisallow: /admin/\n')
        assert r.groups[0].user_agents == ['*']

    def test_blank_and_colonless_lines_are_skipped(self):
        r = parse('User-agent: *\n\n   \ngarbage line\nDisallow: /a/\n')
        assert r.groups[0].disallow == ['/a/']

    def test_bare_disallow_records_nothing(self):
        """`Disallow:` with no path means "allow everything"."""
        r = parse('User-agent: *\nDisallow:\n')
        assert r.groups[0].disallow == []
        assert r.total_disallow_count == 0
        assert r.disallows_everything is False

    def test_empty_user_agent_value_is_ignored(self):
        r = parse('User-agent:\nDisallow: /a/\n')
        assert r.groups[0].user_agents == ['*']

    def test_unknown_directives_are_collected_not_raised(self):
        r = parse('User-agent: *\nRequest-rate: 1/10\nVisit-time: 0600-0845\n')
        assert 'request-rate' in r.unknown_directives
        assert 'visit-time' in r.unknown_directives

    def test_unknown_directives_are_deduplicated(self):
        r = parse('Request-rate: 1/10\nRequest-rate: 2/10\n')
        assert r.unknown_directives == ['request-rate']


class TestCrawlDelay:
    def test_wildcard_crawl_delay_is_surfaced(self):
        r = parse('User-agent: *\nCrawl-delay: 10\nDisallow: /a/\n')
        assert r.wildcard_crawl_delay == 10.0
        assert r.groups[0].crawl_delay == 10.0

    def test_fractional_crawl_delay(self):
        r = parse('User-agent: *\nCrawl-delay: 0.5\n')
        assert r.wildcard_crawl_delay == 0.5

    def test_non_wildcard_crawl_delay_is_not_promoted(self):
        r = parse('User-agent: Bingbot\nCrawl-delay: 10\n')
        assert r.wildcard_crawl_delay is None
        assert r.groups[0].crawl_delay == 10.0

    def test_malformed_crawl_delay_is_none(self):
        r = parse('User-agent: *\nCrawl-delay: soon\n')
        assert r.wildcard_crawl_delay is None


class TestDisallowsEverything:
    def test_wildcard_root_disallow_is_flagged(self):
        r = parse('User-agent: *\nDisallow: /\n')
        assert r.disallows_everything is True

    def test_named_agent_root_disallow_is_not_flagged(self):
        r = parse('User-agent: BadBot\nDisallow: /\n')
        assert r.disallows_everything is False

    def test_subpath_disallow_is_not_flagged(self):
        r = parse('User-agent: *\nDisallow: /private/\n')
        assert r.disallows_everything is False


class TestSensitivePaths:
    def test_admin_paths_are_flagged(self):
        r = parse('User-agent: *\nDisallow: /admin/\nDisallow: /wp-admin/\n')
        assert '/admin/' in r.sensitive_paths
        assert '/wp-admin/' in r.sensitive_paths

    def test_vcs_and_config_leakage_is_flagged(self):
        r = parse('User-agent: *\nDisallow: /.git/\nDisallow: /.env\nDisallow: /config/\n')
        assert set(r.sensitive_paths) == {'/.git/', '/.env', '/config/'}

    def test_backups_are_flagged(self):
        r = parse('User-agent: *\nDisallow: /backup/\nDisallow: /db-dump/\n')
        assert set(r.sensitive_paths) == {'/backup/', '/db-dump/'}

    def test_routine_paths_are_not_flagged(self):
        """These are disallowed for crawl budget, not secrecy — flagging them
        would bury the real findings."""
        r = parse(
            'User-agent: *\n'
            'Disallow: /login\n'
            'Disallow: /search\n'
            'Disallow: /cart\n'
            'Disallow: /checkout\n'
            'Disallow: /account/\n'
            'Disallow: /api/\n'
        )
        assert r.sensitive_paths == []

    def test_marker_must_sit_on_a_path_boundary(self):
        """Plain substring matching would flag /badminton/ for the 'admin'
        marker — 'badminton'[1:6] is literally 'admin'."""
        r = parse('User-agent: *\nDisallow: /badminton/\n')
        assert r.sensitive_paths == []

    def test_sensitive_paths_are_deduplicated_across_groups(self):
        r = parse(
            'User-agent: Googlebot\nDisallow: /admin/\n'
            'User-agent: Bingbot\nDisallow: /admin/\n'
        )
        assert r.sensitive_paths == ['/admin/']
        assert r.total_disallow_count == 2

    def test_sensitive_path_list_is_capped(self):
        lines = ['User-agent: *']
        lines += [f'Disallow: /admin-{i}/' for i in range(MAX_SENSITIVE + 10)]
        r = parse('\n'.join(lines))
        assert len(r.sensitive_paths) == MAX_SENSITIVE


class TestSitemaps:
    def test_sitemaps_are_global_not_per_group(self):
        r = parse(
            'Sitemap: https://x.test/sitemap.xml\n'
            'User-agent: *\n'
            'Disallow: /a/\n'
            'Sitemap: https://x.test/news.xml\n'
        )
        assert r.sitemaps == ['https://x.test/sitemap.xml', 'https://x.test/news.xml']
        assert len(r.groups) == 1


class TestCaps:
    def test_group_count_is_capped(self):
        text = '\n'.join(f'User-agent: bot{i}\nDisallow: /{i}/' for i in range(MAX_GROUPS + 20))
        r = parse(text)
        assert len(r.groups) <= MAX_GROUPS


class TestTruncationAndAbsence:
    def test_truncated_flag_is_carried_through(self):
        assert parse('User-agent: *\n', truncated=True).truncated is True
        assert parse('User-agent: *\n').truncated is False

    def test_absent_report(self):
        r = absent('not_found', 404)
        assert r.present is False
        assert r.fetch_reason == 'not_found'
        assert r.fetch_status == 404
        assert r.groups == []
