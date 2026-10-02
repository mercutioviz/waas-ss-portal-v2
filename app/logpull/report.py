"""Customer-facing report assembly over a completed pull.

This module measures nothing. Every figure it shows was measured by one of
the analysis layers — cache, crawlers, header audit, robots — and this is
the layer that decides what order a reader meets them in, and who is being
asked to act.

Three sections, per the plan: what can be changed on the WaaS application,
what only the customer's own server team can change, and what has to be
deployed as a file on their origin. The split is the whole point. A report
that mixes them produces a meeting in which everyone agrees something should
be done and nobody leaves owning a ticket.

What this deliberately does not do is add the sections up. The cache layer
counts a crawler fetching an uncacheable asset; so does the robots layer.
That is one request seen by two instruments, and a combined "total
recoverable" headline would double-count it while looking more authoritative
than any of the measured numbers underneath it. The rule the robots engine
already follows — measure each claim against the thing it describes, never
sum overlapping totals — applies to the report as a whole, so the sections
are presented side by side and the reader is told explicitly that they
overlap.

Two other things this is careful about, because both are ways a report can
mislead without containing a false sentence:

- **"Not run" is not "nothing found."** A section whose analysis never ran
  is reported as missing, with what to run, rather than rendered empty.
  Silence that looks like a clean bill of health is the worst output here.
- **Limits are generated, not boilerplate.** The known-limits list is built
  from what actually happened on this pull — the sampling factor in force,
  windows that truncated, tables that hit their caps, crawler lists that
  would not load, probes that were challenged. A fixed disclaimer paragraph
  degrades into something nobody reads; a list that names this pull's
  specific gaps is what makes the rest of the numbers credible.
"""
from datetime import datetime, timezone

from app.logpull.analysis import CATEGORY_ORIGIN, CATEGORY_ROBOTS, CATEGORY_WAAS

#: Section order is the order a reader should act in, which is roughly the
#: order of how cheaply each change can be made. WaaS settings are a console
#: change; origin headers need the customer's server team; robots.txt needs
#: that team *and* a judgement about what should stay indexed.
SECTIONS = [
    {
        'key': CATEGORY_WAAS,
        'label': 'WaaS configuration',
        'owner': 'Changed on the WaaS application',
        'blurb': 'Settings on the WaaS application itself — caching, rewrites, '
                 'rate limits. Nothing here has been applied: these are '
                 'findings, not actions taken.',
    },
    {
        'key': CATEGORY_ORIGIN,
        'label': 'Origin / backend',
        'owner': 'Changed on your own web servers',
        'blurb': 'Response headers and application behaviour at the origin. '
                 'WaaS sits in front of these and cannot change them — they '
                 'need your server or application team.',
    },
    {
        'key': CATEGORY_ROBOTS,
        'label': 'Crawl control (robots.txt)',
        'owner': 'Deployed as a file on your origin',
        'blurb': 'robots.txt is served by the origin, so WaaS cannot deploy '
                 'it. The proposed file below was measured by replaying it '
                 'against this pull\'s own traffic.',
    },
]

SECTION_INDEX = {s['key']: i for i, s in enumerate(SECTIONS)}

SEVERITY_RANK = {'warning': 0, 'info': 1}

SEVERITY_LABELS = {
    'warning': 'Needs attention',
    'info': 'For information',
}

#: The producers assign two severities and that is all they assign. Rendering
#: them as a four-rung critical/high/medium/low ladder would be inventing a
#: judgement no layer actually made — and the ladder is exactly the part of a
#: report readers argue about instead of reading.
SEVERITIES = ('warning', 'info')

#: Short form of each section label, for the summary table's owner column where
#: the full sentence would not fit.
SECTION_LABELS = {s['key']: s['label'] for s in SECTIONS}

#: The cap flags are named for the counter they guard, which is the right name
#: inside the aggregators and the wrong one in a document a customer reads.
#: An unmapped flag falls back to its raw key — a limit stated awkwardly is
#: still better than a limit silently dropped.
CAP_LABELS = {
    'hosts': 'hosts',
    'extensions': 'file types',
    'assets': 'individual URLs',
    'repeat': 'repeatedly-fetched URLs',
    'crawler_urls_trimmed': 'URLs per crawler',
    'crawler_prefixes_trimmed': 'site areas per crawler',
    'crawler_ips': 'client IPs per crawler',
    'url_space_trimmed': 'the crawler/visitor URL cross-tab',
    'query_keys_trimmed': 'query-string parameters',
}

#: The audit's verdict constants in the customer's language. A reader should
#: not have to know that `etag_suppresses_last_modified` is the interesting one.
VERDICT_LABELS = {
    'conditional_ok': 'Revalidates correctly (304)',
    'etag_suppresses_last_modified': 'Broken ETag cancels a working Last-Modified',
    'etag_rejected': 'Own ETag not accepted',
    'no_conditional_support': 'No 304 to any conditional request',
    'no_validators': 'No ETag and no Last-Modified',
    'challenged': 'Answered with a challenge page',
    'non_200': 'Did not return 200',
    'error': 'Unreachable',
}


def _fmt_int(value):
    return f'{int(value or 0):,}'


def _fmt_pct(value):
    return f'{(value or 0) * 100:.1f}%'


def _fmt_bytes(value):
    value = value or 0
    if value >= 1e12:
        return f'{value / 1e12:.2f} TB'
    if value >= 1e9:
        return f'{value / 1e9:.2f} GB'
    if value >= 1e6:
        return f'{value / 1e6:.1f} MB'
    return f'{_fmt_int(value)} B'


def _kpi(value, label, tone='plain', note=None):
    return {'value': value, 'label': label, 'tone': tone, 'note': note}


def _headline(analysis, robots):
    """The handful of numbers worth putting above the fold.

    Each one is a single measured ratio, not a composite. A KPI that blends
    two measurements is the same double-counting problem in smaller type.
    """
    out = []
    sample = (analysis or {}).get('sample') or {}
    rows = sample.get('rows') or 0
    if rows:
        scale = sample.get('scale') or 1.0
        note = (f'{_fmt_pct(1 / scale)} time sample'
                if scale > 1.01 else 'full collection')
        out.append(_kpi(_fmt_int(rows), 'Requests analysed', note=note))

    edge = (analysis or {}).get('edge_cache') or {}
    if edge.get('static_total'):
        rate = edge.get('static_hit_rate') or 0
        out.append(_kpi(_fmt_pct(rate), 'Static assets served from edge cache',
                        tone='bad' if rate < 0.01 else
                             'warn' if rate < 0.5 else 'good'))

    reval = (analysis or {}).get('revalidation') or {}
    if reval.get('static_full') or reval.get('static_revalidated'):
        ratio = reval.get('static_ratio') or 0
        out.append(_kpi(_fmt_pct(ratio), 'Static requests that revalidate (304)',
                        tone='bad' if ratio < 0.05 else
                             'warn' if ratio < 0.3 else 'good'))

    repeat = (analysis or {}).get('repeat_fetch') or {}
    if repeat.get('excess_requests'):
        out.append(_kpi(_fmt_int(repeat['excess_requests']),
                        'Redundant static refetches', tone='warn',
                        note=f'{_fmt_pct(repeat.get("excess_share"))} of '
                             f'static traffic'))

    crawlers = (analysis or {}).get('crawlers') or {}
    if crawlers.get('crawler_requests'):
        share = crawlers.get('crawler_request_share') or 0
        out.append(_kpi(_fmt_pct(share), 'Requests from declared crawlers',
                        tone='warn' if share >= 0.25 else 'plain',
                        note=f'{_fmt_pct(crawlers.get("crawler_byte_share"))} '
                             f'of bytes sent'))

    measurement = (robots or {}).get('measurement') or {}
    if measurement.get('crawler_requests'):
        current = (measurement.get('current') or {}).get('request_share') or 0
        out.append(_kpi(_fmt_pct(current), 'Crawl blocked by the current robots.txt',
                        tone='bad' if current < 0.02 else 'plain'))
        net = measurement.get('net') or {}
        if net.get('requests'):
            out.append(_kpi(_fmt_bytes(net.get('bytes')),
                            'Measured saving from the proposed robots.txt',
                            tone='good',
                            note=f'{_fmt_int(net["requests"])} sampled requests'))
    return out


def _collect_findings(analysis, header_audit, robots):
    """Every layer's findings in one list, each tagged with where it came from.

    Source is carried through because a reader who disputes a number needs to
    know which instrument produced it, and because a layer that did not run
    has to be distinguishable from one that ran and found nothing.
    """
    out = []
    for source, findings in (
        ('log analysis', (analysis or {}).get('findings') or []),
        ('live header audit', (header_audit or {}).get('findings') or []),
        ('robots.txt replay', (robots or {}).get('findings') or []),
    ):
        for order, finding in enumerate(findings):
            item = dict(finding)
            item['source'] = source
            item['order'] = order
            item.setdefault('category', CATEGORY_WAAS)
            item.setdefault('impact', None)
            out.append(item)
    return out


def _rank(finding):
    return (
        SEVERITY_RANK.get(finding.get('severity'), 9),
        SECTION_INDEX.get(finding.get('category'), 9),
        finding.get('order', 0),
    )


def _missing(analysis, header_audit, robots, *, raw_deleted=False):
    """Analyses that have not been run, and what running them would add.

    Rendering an absent section as empty would read as "we checked and it was
    fine", which is the one thing this report must never accidentally say.
    """
    out = []
    if not (analysis or {}).get('findings') and not (analysis or {}).get('sample'):
        out.append({
            'what': 'Log analysis',
            'why': 'Cache behaviour, repeat fetches, per-host egress and '
                   'crawler classification all come from this pass.',
            'how': 'Run "Analyze" on the results page.' if not raw_deleted else
                   'The collected rows have passed their retention window; '
                   'this needs a new pull.',
        })
    if not header_audit:
        out.append({
            'what': 'Live header audit',
            'why': 'Only a three-probe conditional replay can tell a broken '
                   'ETag apart from an origin that simply does not support '
                   'conditional requests — and the difference decides whether '
                   'the fix is a one-line header rewrite or a caching redesign.',
            'how': 'Run "Audit origin headers" on the results page. It sends '
                   'real requests to the origin, so it is never automatic.',
        })
    elif header_audit.get('error'):
        out.append({
            'what': 'Live header audit',
            'why': 'The audit ran but failed, so nothing in this report '
                   'describes the origin\'s actual response headers.',
            'how': f'Error: {header_audit["error"]}',
        })
    if not robots:
        out.append({
            'what': 'robots.txt proposal',
            'why': 'Crawl recommendations are only worth making with a '
                   'measured before/after; without this pass there is no '
                   'proposed file and no figure attached to it.',
            'how': 'Run "Generate and measure" on the results page.'
                   if not raw_deleted else
                   'The collected rows have passed their retention window; '
                   'a proposal cannot be measured without them.',
        })
    elif robots.get('error'):
        out.append({
            'what': 'robots.txt proposal',
            'why': 'The proposal pass failed, so no crawl file was generated.',
            'how': f'Error: {robots["error"]}',
        })
    return out


def _limits(meta, analysis, header_audit, robots):
    """Known limits, built from what actually happened on this pull."""
    out = []
    sample = (analysis or {}).get('sample') or {}
    scale = sample.get('scale') or 1.0
    rows = sample.get('rows') or 0

    if scale > 1.01:
        exact = sample.get('rows_total_exact')
        against = (f' against an exact count of {_fmt_int(exact)} requests'
                   if exact else '')
        out.append(
            f'Figures are measured on a {_fmt_pct(1 / scale)} time sample '
            f'({_fmt_int(rows)} rows) and extrapolated by ×{scale:,.1f}'
            f'{against}. Sampled totals carry a sampling error; shares and '
            f'ratios are far more stable than absolute counts, which is why '
            f'the recommendations are stated as shares wherever possible.')
    elif rows:
        out.append(f'Figures are measured on all {_fmt_int(rows)} rows '
                   f'collected for the window — no extrapolation.')

    if sample.get('truncated_windows'):
        out.append(
            f'{_fmt_int(sample["truncated_windows"])} collection window(s) hit '
            f'the API\'s 10,000-row pagination cap and were truncated. Traffic '
            f'in those windows is under-represented rather than missing, so '
            f'busy periods are flattened slightly.')

    # The crawler pass keeps its own cap flags rather than writing into the
    # cache pass's dict, so both have to be read or a capped crawler table
    # would go unmentioned.
    caps = dict((analysis or {}).get('caps') or {})
    caps.update(((analysis or {}).get('crawlers') or {}).get('caps') or {})
    capped = sorted({CAP_LABELS.get(name, name)
                     for name, hit in caps.items() if hit})
    if capped:
        out.append(
            f'The following breakdowns reached their size cap and show the '
            f'busiest entries rather than every entry: {", ".join(capped)}. '
            f'Totals are unaffected; long tails are not enumerated.')

    ranges = ((analysis or {}).get('crawlers') or {}).get('ranges') or {}
    unavailable = sorted(k for k, m in ranges.items() if not m.get('available'))
    if unavailable:
        out.append(
            f'Published crawler IP ranges could not be loaded for: '
            f'{", ".join(unavailable)}. Crawlers that depend on those lists '
            f'are reported as unverifiable, not as impostors — an unreachable '
            f'list is not evidence about the traffic.')

    records = (header_audit or {}).get('assets') or []
    if records:
        probed_at = (header_audit or {}).get('generated_at')
        when = f' on {probed_at[:10]}' if probed_at else ''
        out.append(
            f'The header audit probed {len(records)} of the busiest assets '
            f'live{when}. It reflects configuration at that moment, which may '
            f'differ from the collection window, and it is a sample of assets '
            f'rather than a survey of the site.')
        if (header_audit or {}).get('budget_exceeded'):
            out.append(
                f'The audit stopped at its time budget before probing every '
                f'asset it selected ({len(records)} of '
                f'{(header_audit or {}).get("requested", len(records))} '
                f'requested). Each probe is three live requests to your '
                f'origin, so the budget exists to keep the audit polite.')
        challenged = [r for r in records if r.get('verdict') == 'challenged']
        if challenged:
            out.append(
                f'{len(challenged)} probe(s) were answered with a WaaS '
                f'challenge page instead of the asset. Those responses '
                f'describe the challenge, not the asset, and are excluded '
                f'from the header conclusions rather than folded in.')

    if robots:
        if robots.get('current_text_source') == 'pasted':
            out.append(
                'The "current robots.txt" baseline is the file you supplied. '
                'That is better evidence than a live fetch, which passes '
                'through WaaS and can be rewritten or answered with a '
                'challenge page.')
        elif robots.get('fetch_error'):
            out.append(
                f'The current robots.txt could not be fetched '
                f'({robots["fetch_error"]}), so the before/after comparison '
                f'uses an empty baseline and understates what the existing '
                f'file does.')
        elif (robots.get('served') or {}).get('served_as_html'):
            out.append(
                'The fetch for /robots.txt returned an HTML body, which parses '
                'as no rules at all. The "current" figures were measured '
                'against that empty rule set and understate the real file. '
                'Check CaptchaState in the WAF logs for /robots.txt before '
                'concluding the file is broken.')
        ceiling = (robots.get('measurement') or {}).get('ceiling') or {}
        if ceiling.get('request_share'):
            out.append(
                f'robots.txt is honoured voluntarily and only by clients that '
                f'declare themselves. {_fmt_pct(ceiling["request_share"])} of '
                f'non-crawler requests match the same patterns and are beyond '
                f'the reach of any crawl rule — that is the ceiling on what '
                f'this lever can do.')

    out.append(
        'The three sections measure overlapping traffic: a crawler fetching an '
        'uncacheable asset is counted by the cache analysis and by the crawl '
        'analysis both. The per-section figures are each measured against what '
        'they describe and must not be added together.')

    if meta.get('raw_deleted'):
        out.append(
            'The raw rows for this pull have passed their retention window and '
            'were deleted. The figures above are kept; a deeper or re-run '
            'analysis needs a new collection.')
    return out


def build(meta, *, analysis=None, header_audit=None, robots=None):
    """Assemble the report document.

    Takes plain dicts rather than the `LogPull` row, so the assembly is
    testable without a database and the route stays responsible for
    authorisation.
    """
    meta = dict(meta or {})
    meta.setdefault('generated_at', datetime.now(timezone.utc).isoformat())

    findings = _collect_findings(analysis, header_audit, robots)
    findings.sort(key=_rank)

    by_section = {s['key']: [] for s in SECTIONS}
    for finding in findings:
        by_section.setdefault(finding['category'], []).append(finding)

    sections = []
    for spec in SECTIONS:
        items = by_section.get(spec['key']) or []
        sections.append({
            **spec,
            'findings': items,
            'warnings': sum(1 for f in items if f['severity'] == 'warning'),
            'count': len(items),
        })

    counts = {level: sum(1 for f in findings if f['severity'] == level)
              for level in SEVERITIES}
    counts['total'] = len(findings)

    return {
        'meta': meta,
        'headline': _headline(analysis, robots),
        'summary': findings,
        'sections': sections,
        'counts': counts,
        'severity_labels': SEVERITY_LABELS,
        'section_labels': SECTION_LABELS,
        'verdict_labels': VERDICT_LABELS,
        'limits': _limits(meta, analysis, header_audit, robots),
        'missing': _missing(analysis, header_audit, robots,
                            raw_deleted=meta.get('raw_deleted', False)),
        'robots_file': (robots or {}).get('file'),
        'robots_host': (robots or {}).get('host'),
    }
