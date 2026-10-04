"""Tests for the customer-facing report assembly.

This module measures nothing, so there is no arithmetic to check. What there
is to check is everything a report can get wrong without printing a false
number, and each test below guards one of those:

- A finding reaching the wrong owner's section sends the ticket to the wrong
  team, which is the specific failure the three-way split exists to prevent.
- A section that did not run must render as *missing*, never as empty. An
  empty section reads as a clean bill of health, and that is the one thing
  this report must never accidentally say.
- The layers measure overlapping traffic. Nothing may present a combined
  total, and the overlap must be stated rather than left for the reader to
  infer.
- The known-limits list has to be generated from this pull. A fixed
  disclaimer paragraph is the kind of thing that stays correct forever by
  never saying anything.
- The standalone export has to open on a laptop with no network. Any
  external reference is a section that renders blank for the person the file
  was sent to.
"""
import uuid
from pathlib import Path

import pytest

from app.logpull import report
from app.logpull.analysis import CATEGORY_ORIGIN, CATEGORY_ROBOTS, CATEGORY_WAAS
from app.logpull.windows import MODE_SAMPLE
from app.models import LogPull, User, WaasAccount

HOST = 'www.example.com'

META = {
    'pull_id': 1,
    'app_name': HOST,
    'account_name': 'Acme WaaS',
    'mode': MODE_SAMPLE,
    'window_days': 7,
    'raw_deleted': False,
}


def finding(code, severity, category, **kwargs):
    base = {
        'code': code,
        'severity': severity,
        'category': category,
        'title': f'Title for {code}',
        'detail': f'Detail for {code}.',
        'evidence': {},
        'impact': None,
    }
    base.update(kwargs)
    return base


def analysis(findings=(), **kwargs):
    """A log-analysis result with just enough shape for the report."""
    data = {
        'sample': {'rows': 2000, 'scale': 1.0, 'mode': MODE_SAMPLE,
                   'truncated_windows': 0},
        'findings': list(findings),
        'hosts': [],
        'caps': {},
        'edge_cache': {},
        'revalidation': {},
        'repeat_fetch': {},
        'crawlers': {},
    }
    data.update(kwargs)
    return data


def audit(findings=(), **kwargs):
    data = {
        'generated_at': '2026-02-01T10:00:00',
        'probed': 2, 'requested': 2, 'budget_exceeded': False,
        'verdicts': {}, 'assets': [], 'findings': list(findings),
    }
    data.update(kwargs)
    return data


def robots(findings=(), **kwargs):
    data = {
        'host': HOST,
        'file': 'User-agent: *\nDisallow: /search\n',
        'proposal': {'host': HOST, 'rules': []},
        'measurement': {'crawler_requests': 1000,
                        'current': {'requests': 5, 'request_share': 0.005},
                        'net': {'requests': 400, 'bytes': 2_000_000_000}},
        'findings': list(findings),
        'served': None,
        'current_text_source': None,
    }
    data.update(kwargs)
    return data


def codes(section):
    return [f['code'] for f in section['findings']]


def section(doc, key):
    return next(s for s in doc['sections'] if s['key'] == key)


class TestOwnerSplit:
    """Who acts is the report's organising question."""

    def test_each_finding_lands_in_its_own_owner_section(self):
        doc = report.build(
            META,
            analysis=analysis([finding('c1', 'warning', CATEGORY_WAAS)]),
            header_audit=audit([finding('o1', 'warning', CATEGORY_ORIGIN)]),
            robots=robots([finding('r1', 'info', CATEGORY_ROBOTS)]),
        )
        assert codes(section(doc, CATEGORY_WAAS)) == ['c1']
        assert codes(section(doc, CATEGORY_ORIGIN)) == ['o1']
        assert codes(section(doc, CATEGORY_ROBOTS)) == ['r1']

    def test_a_finding_from_the_audit_can_be_a_waas_finding(self):
        """The producing layer does not decide the owner — the category does.

        The header audit is the thing that discovers WaaS is stripping
        Accept-Encoding, and that is a WaaS setting, not an origin one.
        """
        doc = report.build(
            META,
            analysis=analysis(),
            header_audit=audit([finding('waas_compression_absent', 'info',
                                        CATEGORY_WAAS)]),
        )
        assert codes(section(doc, CATEGORY_WAAS)) == ['waas_compression_absent']
        assert codes(section(doc, CATEGORY_ORIGIN)) == []

    def test_every_section_is_present_even_with_no_findings(self):
        """A reader has to be able to see that a category was considered."""
        doc = report.build(META, analysis=analysis())
        assert [s['key'] for s in doc['sections']] == [
            CATEGORY_WAAS, CATEGORY_ORIGIN, CATEGORY_ROBOTS]
        assert all(s['findings'] == [] for s in doc['sections'])

    def test_each_section_names_who_changes_it(self):
        doc = report.build(META, analysis=analysis())
        owners = [s['owner'] for s in doc['sections']]
        assert all(owners)
        assert len(set(owners)) == 3

    def test_an_unknown_category_is_still_carried(self):
        """A new producer must not be able to make a finding disappear."""
        doc = report.build(
            META, analysis=analysis([finding('x', 'warning', 'something_new')]))
        assert 'x' in [f['code'] for f in doc['summary']]


class TestRanking:
    def test_warnings_come_before_information(self):
        doc = report.build(META, analysis=analysis([
            finding('info-1', 'info', CATEGORY_WAAS),
            finding('warn-1', 'warning', CATEGORY_ROBOTS),
        ]))
        assert [f['code'] for f in doc['summary']] == ['warn-1', 'info-1']

    def test_within_a_severity_the_order_is_by_owner(self):
        """Grouping by owner inside a severity band means a team reading the
        summary table finds its own rows together."""
        doc = report.build(
            META,
            analysis=analysis([finding('w', 'warning', CATEGORY_WAAS)]),
            header_audit=audit([finding('o', 'warning', CATEGORY_ORIGIN)]),
            robots=robots([finding('r', 'warning', CATEGORY_ROBOTS)]),
        )
        assert [f['code'] for f in doc['summary']] == ['w', 'o', 'r']

    def test_producer_order_breaks_the_remaining_tie(self):
        """Each layer already orders its own findings by what it thinks
        matters; that judgement is kept rather than re-litigated here."""
        doc = report.build(META, analysis=analysis([
            finding('first', 'warning', CATEGORY_WAAS),
            finding('second', 'warning', CATEGORY_WAAS),
        ]))
        assert [f['code'] for f in doc['summary']] == ['first', 'second']

    def test_the_summary_and_the_sections_hold_the_same_findings(self):
        doc = report.build(
            META,
            analysis=analysis([finding('a', 'warning', CATEGORY_WAAS)]),
            robots=robots([finding('b', 'info', CATEGORY_ROBOTS)]),
        )
        in_sections = {f['code'] for s in doc['sections'] for f in s['findings']}
        assert in_sections == {f['code'] for f in doc['summary']} == {'a', 'b'}

    def test_counts_are_per_severity_and_total(self):
        doc = report.build(META, analysis=analysis([
            finding('a', 'warning', CATEGORY_WAAS),
            finding('b', 'warning', CATEGORY_ORIGIN),
            finding('c', 'info', CATEGORY_WAAS),
        ]))
        assert doc['counts'] == {'warning': 2, 'info': 1, 'total': 3}

    def test_only_two_severities_are_labelled(self):
        """A four-rung critical/high/medium/low ladder would be inventing a
        judgement no producer made."""
        assert set(report.SEVERITY_LABELS) == {'warning', 'info'}


class TestSource:
    def test_each_finding_records_which_instrument_produced_it(self):
        doc = report.build(
            META,
            analysis=analysis([finding('a', 'warning', CATEGORY_WAAS)]),
            header_audit=audit([finding('b', 'warning', CATEGORY_ORIGIN)]),
            robots=robots([finding('c', 'warning', CATEGORY_ROBOTS)]),
        )
        assert [f['source'] for f in doc['summary']] == [
            'log analysis', 'live header audit', 'robots.txt replay']

    def test_the_producers_impact_figure_is_carried_through_untouched(self):
        """`impact` is built where the evidence is. The report does not
        recompute it, so what the customer reads is what was measured."""
        doc = report.build(META, analysis=analysis([
            finding('a', 'warning', CATEGORY_WAAS,
                    impact='0 of 61,400,000 static requests cached at the edge'),
        ]))
        assert doc['summary'][0]['impact'] == (
            '0 of 61,400,000 static requests cached at the edge')

    def test_a_finding_without_an_impact_gets_a_blank_not_a_guess(self):
        """Not every finding has one honest number; an invented one is worse
        than an empty cell."""
        f = dict(finding('a', 'info', CATEGORY_WAAS))
        del f['impact']
        doc = report.build(META, analysis=analysis([f]))
        assert doc['summary'][0]['impact'] is None

    def test_building_does_not_mutate_the_producers_findings(self):
        """The analysis dict is read back out of the DB and rendered on the
        results page too."""
        original = finding('a', 'warning', CATEGORY_WAAS)
        data = analysis([original])
        report.build(META, analysis=data)
        assert 'source' not in original
        assert 'order' not in original


class TestNoCombinedTotal:
    """The cache layer counts a crawler fetching an uncacheable asset; so does
    the robots layer. One request, two instruments."""

    def test_the_overlap_is_stated_on_every_report(self):
        doc = report.build(META, analysis=analysis(), robots=robots())
        assert any('must not be added together' in limit
                   for limit in doc['limits'])

    def test_the_overlap_warning_survives_a_report_with_no_findings(self):
        doc = report.build(META)
        assert any('must not be added together' in limit
                   for limit in doc['limits'])

    def test_no_headline_figure_combines_the_layers(self):
        """Each KPI is one measured ratio. A blended KPI is the same
        double-counting in smaller type."""
        doc = report.build(
            META,
            analysis=analysis(edge_cache={'static_total': 100,
                                          'static_hit_rate': 0.0},
                              crawlers={'crawler_requests': 500,
                                        'crawler_request_share': 0.3,
                                        'crawler_byte_share': 0.4}),
            robots=robots(),
        )
        labels = ' '.join(k['label'].lower() for k in doc['headline'])
        for word in ('total', 'combined', 'overall', 'recoverable'):
            assert word not in labels

    def test_counts_never_claim_a_recoverable_volume(self):
        doc = report.build(META, analysis=analysis())
        assert set(doc['counts']) == {'warning', 'info', 'total'}


class TestMissingAnalyses:
    def test_an_unrun_audit_is_reported_as_missing(self):
        doc = report.build(META, analysis=analysis(), robots=robots())
        assert [m['what'] for m in doc['missing']] == ['Live header audit']

    def test_an_unrun_robots_pass_is_reported_as_missing(self):
        doc = report.build(META, analysis=analysis(), header_audit=audit())
        assert [m['what'] for m in doc['missing']] == ['robots.txt proposal']

    def test_an_analysis_that_ran_and_found_nothing_is_not_missing(self):
        """This is the distinction the whole block exists for: ran-and-clean
        must not be rendered the same way as never-ran."""
        doc = report.build(META, analysis=analysis(),
                           header_audit=audit(), robots=robots())
        assert doc['missing'] == []
        assert doc['summary'] == []

    def test_a_failed_audit_is_missing_with_its_error(self):
        """A crashed probe produces no findings, which looks exactly like a
        healthy origin unless the failure is surfaced."""
        doc = report.build(META, analysis=analysis(),
                           header_audit=audit(error='Connection refused'),
                           robots=robots())
        entry = next(m for m in doc['missing'] if m['what'] == 'Live header audit')
        assert 'Connection refused' in entry['how']

    def test_a_failed_robots_pass_is_missing_with_its_error(self):
        doc = report.build(META, analysis=analysis(), header_audit=audit(),
                           robots=robots(error='no rows on disk'))
        entry = next(m for m in doc['missing'] if m['what'] == 'robots.txt proposal')
        assert 'no rows on disk' in entry['how']

    def test_every_missing_entry_says_how_to_run_it(self):
        doc = report.build(META)
        assert all(m['how'] and m['why'] for m in doc['missing'])

    def test_an_expired_pull_says_so_instead_of_offering_a_rerun(self):
        """Telling someone to press a button that cannot work is worse than
        telling them nothing."""
        doc = report.build({**META, 'raw_deleted': True})
        hows = ' '.join(m['how'] for m in doc['missing'])
        assert 'retention window' in hows
        assert '"Analyze"' not in hows


class TestMissingEntriesNameRealButtons:
    """A "how" line is the only navigation the reader gets, so the labels it
    quotes have to be the labels on the results page. These drifted once: the
    report said to run "Audit origin headers" against a button that reads
    "Probe N assets", and the reader could not find the control at all.
    """
    @staticmethod
    def results_template():
        path = (Path(__file__).resolve().parent.parent / 'app' / 'templates'
                / 'traffic' / 'results.html')
        return path.read_text()

    @staticmethod
    def how_for(doc, what):
        return next(m['how'] for m in doc['missing'] if m['what'] == what)

    def test_the_analysis_entry_names_the_analyze_button(self):
        doc = report.build(META)
        assert '"Analyze"' in self.how_for(doc, 'Log analysis')
        assert "_('Analyze')" in self.results_template()

    def test_the_audit_entry_names_the_card_and_counts_the_targets(self):
        doc = report.build(META, analysis=analysis(audit_targets=[{}, {}, {}]),
                           robots=robots())
        how = self.how_for(doc, 'Live header audit')
        assert '"Origin cache headers"' in how
        assert '"Probe 3 assets"' in how
        source = self.results_template()
        assert "_('Origin cache headers')" in source
        assert "_('Probe %(n)s assets'" in source

    def test_the_robots_entry_names_the_card_and_button(self):
        doc = report.build(META, analysis=analysis(), header_audit=audit())
        how = self.how_for(doc, 'robots.txt proposal')
        assert '"robots.txt proposal"' in how
        assert '"Generate"' in how
        source = self.results_template()
        assert "_('robots.txt proposal')" in source
        assert "_('Generate')" in source

    def test_an_audit_with_no_eligible_assets_offers_no_button(self):
        """The button is not rendered when there is nothing to probe, so
        naming it would send the reader looking for a control that is absent.
        """
        doc = report.build(META, analysis=analysis(), robots=robots())
        how = self.how_for(doc, 'Live header audit')
        assert 'Probe' not in how
        assert 'no successful static requests' in how

    def test_an_unanalyzed_pull_is_sent_to_the_analysis_first(self):
        """With no analysis there are no targets, which is not the same as
        having looked and found none."""
        doc = report.build(META)
        how = self.how_for(doc, 'Live header audit')
        assert 'analysis first' in how
        assert 'Probe' not in how


class TestGeneratedLimits:
    def test_a_full_collection_says_there_is_no_extrapolation(self):
        doc = report.build(META, analysis=analysis(
            sample={'rows': 2000, 'scale': 1.0, 'truncated_windows': 0}))
        assert any('no extrapolation' in limit for limit in doc['limits'])

    def test_a_sampled_collection_names_its_factor(self):
        doc = report.build(META, analysis=analysis(
            sample={'rows': 2000, 'scale': 24.0, 'truncated_windows': 0,
                    'rows_total_exact': 48_000}))
        text = ' '.join(doc['limits'])
        assert '×24.0' in text
        assert '48,000' in text

    def test_truncated_windows_are_named_with_their_cause(self):
        """The 10,000-row cap flattens busy periods rather than dropping
        them, and that asymmetry changes how a peak should be read."""
        doc = report.build(META, analysis=analysis(
            sample={'rows': 2000, 'scale': 1.0, 'truncated_windows': 3}))
        entry = next(limit for limit in doc['limits'] if '10,000' in limit)
        assert '3 collection window(s)' in entry
        assert 'under-represented' in entry

    def test_capped_tables_are_listed(self):
        doc = report.build(META, analysis=analysis(
            caps={'hosts': True, 'extensions': False, 'assets': True}))
        entry = next(limit for limit in doc['limits'] if 'size cap' in limit)
        assert 'hosts, individual URLs' in entry
        assert 'file types' not in entry

    def test_cap_names_are_in_english_not_counter_names(self):
        """These flags are named for the counter they guard, which is the
        right name in the aggregator and the wrong one in a customer's hands."""
        doc = report.build(META, analysis=analysis(
            caps={}, crawlers={'caps': {'crawler_prefixes_trimmed': True}}))
        entry = next(limit for limit in doc['limits'] if 'size cap' in limit)
        assert 'site areas per crawler' in entry
        assert 'trimmed' not in entry

    def test_the_crawler_layers_own_caps_are_read_too(self):
        """The crawler pass keeps a separate caps dict; reading only the cache
        pass's would let a capped crawler table go unmentioned."""
        doc = report.build(META, analysis=analysis(
            caps={}, crawlers={'caps': {'url_space_trimmed': True}}))
        assert any('cross-tab' in limit for limit in doc['limits'])

    def test_an_unmapped_cap_flag_still_appears(self):
        """A new counter must produce an awkward limit, never a silent one."""
        doc = report.build(META, analysis=analysis(caps={'something_new': True}))
        assert any('something_new' in limit for limit in doc['limits'])

    def test_unavailable_crawler_ranges_are_called_unverifiable_not_fake(self):
        """An unreachable published list is not evidence about the traffic."""
        doc = report.build(META, analysis=analysis(crawlers={
            'ranges': {'googlebot': {'available': True},
                       'bingbot': {'available': False}}}))
        entry = next(limit for limit in doc['limits'] if 'bingbot' in limit)
        assert 'googlebot' not in entry
        assert 'not as impostors' in entry

    def test_the_audits_scope_and_date_are_stated(self):
        """The probe happens after the collection window, so it can describe a
        configuration the logged traffic never saw."""
        doc = report.build(META, analysis=analysis(), header_audit=audit(
            assets=[{'verdict': 'conditional_ok'}, {'verdict': 'error'}],
            generated_at='2026-02-01T10:00:00'))
        entry = next(limit for limit in doc['limits'] if 'probed 2' in limit)
        assert '2026-02-01' in entry

    def test_an_exhausted_audit_budget_is_disclosed(self):
        doc = report.build(META, analysis=analysis(), header_audit=audit(
            assets=[{'verdict': 'conditional_ok'}], probed=1, requested=40,
            budget_exceeded=True))
        assert any('time budget' in limit and '40' in limit
                   for limit in doc['limits'])

    def test_challenged_probes_are_excluded_and_said_to_be(self):
        """Headers read off a CAPTCHA page describe the CAPTCHA page."""
        doc = report.build(META, analysis=analysis(), header_audit=audit(
            assets=[{'verdict': 'challenged'}, {'verdict': 'conditional_ok'}]))
        entry = next(limit for limit in doc['limits'] if 'challenge' in limit)
        assert 'excluded' in entry

    def test_a_pasted_baseline_is_recorded_as_better_evidence(self):
        """A live fetch of robots.txt passes through WaaS, which rewrites it."""
        doc = report.build(META, analysis=analysis(),
                           robots=robots(current_text_source='pasted'))
        assert any('file you supplied' in limit for limit in doc['limits'])

    def test_a_failed_robots_fetch_says_the_baseline_is_empty(self):
        doc = report.build(META, analysis=analysis(),
                           robots=robots(fetch_error='403 Forbidden'))
        entry = next(limit for limit in doc['limits'] if '403 Forbidden' in limit)
        assert 'understates' in entry

    def test_robots_served_as_html_points_at_the_captcha_before_the_file(self):
        """The file is usually fine; the fetch was challenged. Telling a
        customer their robots.txt is broken when it is not burns credibility."""
        doc = report.build(META, analysis=analysis(),
                           robots=robots(served={'served_as_html': True}))
        entry = next(limit for limit in doc['limits'] if 'HTML body' in limit)
        assert 'CaptchaState' in entry

    def test_a_null_served_block_does_not_crash_the_limits(self):
        """`served` is present-but-None whenever nothing was fetched, which is
        the normal path when the current file was pasted."""
        doc = report.build(META, analysis=analysis(), robots=robots(served=None))
        assert doc['limits']

    def test_the_ceiling_is_stated_as_the_limit_of_the_lever(self):
        doc = report.build(META, analysis=analysis(), robots=robots(
            measurement={'crawler_requests': 1000,
                         'ceiling': {'request_share': 0.0379}}))
        entry = next(limit for limit in doc['limits'] if 'voluntarily' in limit)
        assert '3.8%' in entry

    def test_a_deleted_corpus_is_disclosed(self):
        doc = report.build({**META, 'raw_deleted': True}, analysis=analysis())
        assert any('retention window' in limit and 'deleted' in limit
                   for limit in doc['limits'])

    def test_limits_do_not_mention_what_did_not_happen(self):
        """Generated, not boilerplate — a clean pull should produce a short
        list, because a long one that is always the same stops being read."""
        doc = report.build(META, analysis=analysis(), header_audit=audit(),
                           robots=robots())
        text = ' '.join(doc['limits'])
        assert 'time budget' not in text
        assert 'challenge' not in text
        assert '10,000' not in text


class TestHeadline:
    def test_a_sampled_pull_labels_its_row_count_as_a_sample(self):
        doc = report.build(META, analysis=analysis(
            sample={'rows': 2000, 'scale': 24.0}))
        kpi = next(k for k in doc['headline'] if k['label'] == 'Requests analysed')
        assert 'sample' in kpi['note']

    def test_a_full_pull_says_so(self):
        doc = report.build(META, analysis=analysis(
            sample={'rows': 2000, 'scale': 1.0}))
        kpi = next(k for k in doc['headline'] if k['label'] == 'Requests analysed')
        assert kpi['note'] == 'full collection'

    def test_a_dead_edge_cache_reads_as_bad(self):
        doc = report.build(META, analysis=analysis(
            edge_cache={'static_total': 1000, 'static_hit_rate': 0.0}))
        kpi = next(k for k in doc['headline'] if 'edge cache' in k['label'])
        assert kpi['value'] == '0.0%'
        assert kpi['tone'] == 'bad'

    def test_a_healthy_edge_cache_reads_as_good(self):
        doc = report.build(META, analysis=analysis(
            edge_cache={'static_total': 1000, 'static_hit_rate': 0.82}))
        kpi = next(k for k in doc['headline'] if 'edge cache' in k['label'])
        assert kpi['tone'] == 'good'

    def test_an_unmeasured_layer_contributes_no_kpi(self):
        """A zero printed for something never measured is a false statement
        in the largest type on the page."""
        doc = report.build(META, analysis=analysis())
        labels = [k['label'] for k in doc['headline']]
        assert not any('edge cache' in label for label in labels)
        assert not any('crawler' in label.lower() for label in labels)

    def test_the_robots_saving_is_shown_in_bytes_with_its_request_count(self):
        doc = report.build(META, analysis=analysis(), robots=robots())
        kpi = next(k for k in doc['headline'] if 'proposed robots' in k['label'])
        assert kpi['value'] == '2.00 GB'
        assert '400' in kpi['note']


class TestFormatting:
    @pytest.mark.parametrize('value,expected', [
        (0, '0 B'),
        (999, '999 B'),
        (2_000_000, '2.0 MB'),
        (4_990_000_000, '4.99 GB'),
        (1_200_000_000_000, '1.20 TB'),
    ])
    def test_byte_scales(self, value, expected):
        assert report._fmt_bytes(value) == expected

    def test_a_missing_byte_count_is_zero_not_a_crash(self):
        assert report._fmt_bytes(None) == '0 B'

    def test_percentages_keep_one_decimal(self):
        assert report._fmt_pct(0.0379) == '3.8%'
        assert report._fmt_pct(None) == '0.0%'


# --- fixtures --------------------------------------------------------------


@pytest.fixture
def user(app, db):
    u = User(username='report-tester', email='report@example.com', role='user',
             is_active=True)
    u.set_password('x')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def account(app, db, user):
    acc = WaasAccount(user_id=user.id, account_name='Acme WaaS', is_active=True)
    acc.api_key = 'v4-key'
    db.session.add(acc)
    db.session.commit()
    return acc


@pytest.fixture
def logged_in_client(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True
    return client


def make_pull(db, user, account, **kwargs):
    defaults = dict(
        user_id=user.id, account_id=account.id,
        app_id=HOST, app_name=HOST,
        mode=MODE_SAMPLE, window_days=7,
        range_start=1_767_225_600, range_end=1_767_398_400,
        session_id=str(uuid.uuid4()),
        status=LogPull.STATUS_COMPLETE, phase=LogPull.PHASE_DONE,
    )
    defaults.update(kwargs)
    pull = LogPull(**defaults)
    db.session.add(pull)
    db.session.commit()
    return pull


def real_analysis(tmp_path, pull_id):
    """A genuine `analyze_pull` result over a handful of rows."""
    from app.logpull.analysis import analyze_pull
    from app.logpull.store import PullStore

    rows = [{
        'Host': HOST, 'URL': '/assets/app.js', 'QueryString': '"-"',
        'ClientIP': '198.51.100.7', 'HTTPStatus': 200, 'BytesSent': '1024',
        'CacheHit': '0', 'EpochTime': '1767225600000',
        'UserAgent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    } for _ in range(20)]
    store = PullStore(str(tmp_path), pull_id)
    with store.open_day('2026-01-01') as writer:
        writer.write(rows)
    return analyze_pull(store, {'scale': 1.0, 'mode': MODE_SAMPLE},
                        check_host=lambda h: False)


def populated(db, user, account):
    pull = make_pull(db, user, account)
    pull.result = {'analysis': analysis([
        finding('edge_cache_inactive', 'warning', CATEGORY_WAAS,
                title='CDN caching is not active',
                impact='0 of 2,000 static requests cached at the edge'),
    ])}
    pull.report = {
        'header_audit': audit([
            finding('origin_etag_suppresses_last_modified', 'warning',
                    CATEGORY_ORIGIN,
                    title='A broken ETag is cancelling a working Last-Modified',
                    impact='4 of 12 probed assets')],
            assets=[{'host': HOST, 'url': '/a.js', 'verdict': 'etag_rejected',
                     'cache_control': 'public', 'etag': '"abc-gzip"'}]),
        'robots': robots([
            finding('robots_measured_reduction', 'info', CATEGORY_ROBOTS,
                    title='A measured crawl reduction',
                    impact='400 sampled requests, 2.00 GB')]),
    }
    db.session.commit()
    return pull


class TestReportView:
    def test_the_page_renders_the_three_owner_sections(
            self, logged_in_client, db, user, account):
        pull = populated(db, user, account)
        body = logged_in_client.get(f'/traffic/{pull.id}/report').get_data(as_text=True)
        assert 'WaaS configuration' in body
        assert 'Origin / backend' in body
        assert 'Crawl control' in body

    def test_the_summary_table_shows_the_measured_impact(
            self, logged_in_client, db, user, account):
        pull = populated(db, user, account)
        body = logged_in_client.get(f'/traffic/{pull.id}/report').get_data(as_text=True)
        assert '0 of 2,000 static requests cached at the edge' in body
        assert '4 of 12 probed assets' in body

    def test_the_proposed_file_is_shown_in_the_robots_section(
            self, logged_in_client, db, user, account):
        pull = populated(db, user, account)
        body = logged_in_client.get(f'/traffic/{pull.id}/report').get_data(as_text=True)
        assert 'Disallow: /search' in body

    def test_an_unrun_analysis_is_announced_not_left_blank(
            self, logged_in_client, db, user, account):
        pull = make_pull(db, user, account)
        body = logged_in_client.get(f'/traffic/{pull.id}/report').get_data(as_text=True)
        assert 'Not everything was measured' in body
        assert 'Live header audit' in body

    def test_the_results_page_links_to_the_report(
            self, logged_in_client, db, user, account, tmp_path):
        """Built from a real analysis rather than the stub above, because the
        results page reads far more of the result than the report does."""
        pull = make_pull(db, user, account)
        pull.result = {'analysis': real_analysis(tmp_path, pull.id)}
        db.session.commit()
        body = logged_in_client.get(f'/traffic/{pull.id}/results').get_data(as_text=True)
        assert f'/traffic/{pull.id}/report' in body

    def test_the_results_page_offers_no_report_before_an_analysis(
            self, logged_in_client, db, user, account):
        pull = make_pull(db, user, account)
        body = logged_in_client.get(f'/traffic/{pull.id}/results').get_data(as_text=True)
        assert f'/traffic/{pull.id}/report' not in body


class TestStandaloneExport:
    def test_it_downloads_as_an_attachment(
            self, logged_in_client, db, user, account):
        pull = populated(db, user, account)
        resp = logged_in_client.get(f'/traffic/{pull.id}/report.html')
        assert resp.status_code == 200
        assert 'attachment' in resp.headers['Content-Disposition']
        assert 'traffic-analysis' in resp.headers['Content-Disposition']

    def test_the_filename_cannot_carry_a_path(
            self, logged_in_client, db, user, account):
        """The application name comes from the WaaS API, not from us."""
        pull = populated(db, user, account)
        pull.app_name = '../../etc/passwd"x'
        db.session.commit()
        disposition = logged_in_client.get(
            f'/traffic/{pull.id}/report.html').headers['Content-Disposition']
        assert '/' not in disposition.split('filename=')[1]
        assert disposition.count('"') == 2

    def test_it_loads_nothing_from_the_network(
            self, logged_in_client, db, user, account):
        """The file is emailed, forwarded and printed. Anything fetched at
        render time is a section that is blank for whoever opens it."""
        pull = populated(db, user, account)
        body = logged_in_client.get(
            f'/traffic/{pull.id}/report.html').get_data(as_text=True)
        for ref in ('<script', '<link', ' src=', '@import', 'cdn.jsdelivr',
                    'url(http'):
            assert ref not in body

    def test_it_is_a_whole_document(self, logged_in_client, db, user, account):
        pull = populated(db, user, account)
        body = logged_in_client.get(
            f'/traffic/{pull.id}/report.html').get_data(as_text=True)
        assert body.lstrip().startswith('<!DOCTYPE html>')
        assert '<style>' in body
        assert body.rstrip().endswith('</html>')

    def test_it_carries_the_proposed_file_inline(
            self, logged_in_client, db, user, account):
        """A report that says "see the attached robots.txt" is two files, and
        the second one gets lost."""
        pull = populated(db, user, account)
        body = logged_in_client.get(
            f'/traffic/{pull.id}/report.html').get_data(as_text=True)
        assert 'Disallow: /search' in body

    def test_it_states_the_overlap_between_sections(
            self, logged_in_client, db, user, account):
        pull = populated(db, user, account)
        body = logged_in_client.get(
            f'/traffic/{pull.id}/report.html').get_data(as_text=True)
        assert 'must not be added together' in body

    def test_it_prints_the_period_and_provenance(
            self, logged_in_client, db, user, account):
        """A report with no date on it gets quoted back a year later."""
        pull = populated(db, user, account)
        body = logged_in_client.get(
            f'/traffic/{pull.id}/report.html').get_data(as_text=True)
        assert '2026-01-01' in body
        assert 'Acme WaaS' in body
        assert f'#{pull.id}' in body

    def test_the_audit_verdicts_are_shown_in_english(
            self, logged_in_client, db, user, account):
        pull = populated(db, user, account)
        body = logged_in_client.get(
            f'/traffic/{pull.id}/report.html').get_data(as_text=True)
        assert 'Own ETag not accepted' in body
        assert 'etag_rejected' not in body

    def test_an_empty_pull_still_renders(
            self, logged_in_client, db, user, account):
        """The export must survive the worst input it will ever get: a pull
        where nothing was analysed at all."""
        pull = make_pull(db, user, account)
        resp = logged_in_client.get(f'/traffic/{pull.id}/report.html')
        assert resp.status_code == 200
        assert 'Not everything was measured' in resp.get_data(as_text=True)


class TestReportAccess:
    def test_another_users_pull_is_not_reachable(
            self, logged_in_client, db, user, account):
        """A pull holds a customer's traffic; the report summarises it."""
        other = User(username='someone-else', email='else@example.com',
                     role='user', is_active=True)
        other.set_password('x')
        db.session.add(other)
        db.session.commit()
        pull = make_pull(db, other, account, user_id=other.id)
        assert logged_in_client.get(
            f'/traffic/{pull.id}/report').status_code == 404
        assert logged_in_client.get(
            f'/traffic/{pull.id}/report.html').status_code == 404

    def test_anonymous_users_are_redirected_to_login(
            self, client, db, user, account):
        pull = make_pull(db, user, account)
        for path in ('report', 'report.html'):
            resp = client.get(f'/traffic/{pull.id}/{path}')
            assert resp.status_code == 302
            assert '/auth/login' in resp.headers['Location']

    def test_a_missing_pull_is_a_404(self, logged_in_client, db, user, account):
        assert logged_in_client.get('/traffic/9999/report').status_code == 404
