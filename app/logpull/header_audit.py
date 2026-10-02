"""Live cache-header audit of the busiest static assets, with a three-probe
conditional replay.

The log rows say how often an asset is refetched. They do not say *why*. This
fetches the assets the analysis identified and records what a browser actually
receives — freshness lifetime, validators, compression — and then asks the
origin three separate conditional questions.

**Why three probes and not one.** A single request carrying both validators
is the obvious test and it is the one that hides the most common cause. Under
RFC 9110 §13.2.2 a server that receives both `If-None-Match` and
`If-Modified-Since` must honour the ETag and *ignore* the date. So a broken
ETag does not merely fail to help — it suppresses a `Last-Modified` that works
perfectly on its own, and the combined probe reports "conditional requests
unsupported" with no hint of the cause.

    If-None-Match only    -> 200   the ETag is rejected
    If-Modified-Since only -> 304  the date validator works
    both                  -> 200   the broken one wins — the finding

Apache's `mod_deflate` produces exactly this by appending `-gzip` to the ETag
on compressed responses while matching against the unsuffixed value. The fix
belongs to the customer's server team, not to the portal:

    RequestHeader edit "If-None-Match" '^"(.*)-(gzip|br)"$' '"$1"'

Two operational cautions, both learned from a live engagement:

- **A probe can be challenged.** WaaS may answer with a CAPTCHA page instead
  of the asset, and headers read off a challenge page describe the challenge.
  Status and body size are recorded for every probe and any non-200 is shown
  rather than folded into the results.
- **`Accept-Encoding` is sent but may not arrive.** WaaS adds a
  `remove-accept-encoding-header` request rewrite by default, so an absent
  `Content-Encoding` here is expected — and is itself the finding, reported
  as advisory because that rewrite is load-bearing elsewhere.

TLS is verified. A certificate failure is recorded as a result, not silenced,
matching the profiler's probe conventions.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime
from urllib.parse import quote, urlsplit

import requests

from app.profiler.cache_analysis import parse_cache_control
from app.traffic_insights import _pct, _rate

logger = logging.getLogger(__name__)

USER_AGENT = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36')

BASE_HEADERS = {
    'User-Agent': USER_AGENT,
    'Accept': '*/*',
    'Accept-Encoding': 'gzip, deflate, br',
}

PROBE_TIMEOUT = 20.0
MAX_BODY_BYTES = 262_144

#: Politeness delay between probes. These requests land on a customer's live
#: origin; four probes per asset across dozens of assets should not look like
#: a burst to anyone watching their traffic.
INTER_PROBE_SLEEP = 0.4

#: Hard wall-clock cap. A probe that hangs must not extend the pull's
#: analysis phase indefinitely.
AUDIT_BUDGET_SECONDS = 420.0

MAX_TARGETS = 48

#: WaaS's canned CAPTCHA response has a distinctive wire size. Combined with
#: an HTML content type on a non-HTML URL it is a reliable tell.
CAPTCHA_BODY_BYTES = 1336

# Verdicts
VERDICT_OK = 'conditional_ok'
VERDICT_ETAG_SUPPRESSES = 'etag_suppresses_last_modified'
VERDICT_ETAG_REJECTED = 'etag_rejected'
VERDICT_NO_CONDITIONAL = 'no_conditional_support'
VERDICT_NO_VALIDATORS = 'no_validators'
VERDICT_CHALLENGED = 'challenged'
VERDICT_BLOCKED = 'non_200'
VERDICT_ERROR = 'error'

TEXT_EXTENSIONS = ('js', 'css', 'svg', 'json', 'xml', 'html')


def _asset_url(host, path):
    """Absolute URL for a logged request, with the path left intact.

    Log paths arrive already percent-encoded where they need to be, so only
    characters that would break the request line are escaped.
    """
    if not path.startswith('/'):
        path = '/' + path
    return f'https://{host}{quote(path, safe="/%:@&=+$,;~!*()\'-._")}'


def _looks_like_challenge(status, body_bytes, content_type, url):
    """True when a 200 is answering with a page rather than the asset.

    An HTML body in response to a request for a .js or .png is already wrong;
    `CAPTCHA_BODY_BYTES` only tells us which canned page it was.
    """
    if status != 200:
        return False
    if 'html' not in (content_type or '').lower():
        return False
    ext = urlsplit(url).path.rsplit('.', 1)[-1].lower()
    if ext in ('html', 'htm', ''):
        return False
    return True


class _Probe:
    """One HTTP round-trip, recorded whether it succeeded or not."""

    def __init__(self, label):
        self.label = label
        self.status = None
        self.bytes = None
        self.elapsed_ms = None
        self.error = None
        self.headers = {}

    def as_dict(self):
        return {
            'label': self.label,
            'status': self.status,
            'bytes': self.bytes,
            'elapsed_ms': self.elapsed_ms,
            'error': self.error,
        }


def _get(url, extra_headers=None, timeout=PROBE_TIMEOUT, label='get',
         session=None):
    probe = _Probe(label)
    headers = dict(BASE_HEADERS)
    if extra_headers:
        headers.update(extra_headers)
    getter = session.get if session is not None else requests.get
    started = time.monotonic()
    try:
        response = getter(url, headers=headers, timeout=timeout,
                          allow_redirects=False, stream=True)
        probe.status = response.status_code
        probe.headers = dict(response.headers)
        body = response.raw.read(MAX_BODY_BYTES, decode_content=False) or b''
        probe.bytes = len(body)
        response.close()
    except requests.exceptions.SSLError as e:
        probe.error = f'TLS error: {str(e)[:160]}'
    except requests.exceptions.Timeout:
        probe.error = 'Timed out'
    except requests.exceptions.RequestException as e:
        probe.error = str(e)[:160]
    except Exception as e:  # noqa: BLE001 — a probe must never kill the audit
        probe.error = str(e)[:160]
    probe.elapsed_ms = int((time.monotonic() - started) * 1000)
    return probe


def _classify(record):
    """Decide what the three conditional probes proved.

    Order matters: a challenged or non-200 baseline tells us nothing about
    the origin's conditional handling, so those verdicts win before any
    validator logic runs.
    """
    if record.get('error'):
        return VERDICT_ERROR
    if record.get('challenged'):
        return VERDICT_CHALLENGED
    if record.get('status') != 200:
        return VERDICT_BLOCKED

    has_etag = bool(record.get('etag'))
    has_lm = bool(record.get('last_modified'))
    if not has_etag and not has_lm:
        return VERDICT_NO_VALIDATORS

    inm = record.get('inm_status')
    ims = record.get('ims_status')
    both = record.get('both_status')

    if has_etag and has_lm:
        if both == 304:
            return VERDICT_OK
        # The date validator works on its own but the combined request does
        # not: the ETag is both broken and, per §13.2.2, authoritative.
        if ims == 304 and inm != 304:
            return VERDICT_ETAG_SUPPRESSES
        if inm == 304:
            return VERDICT_OK
        return VERDICT_NO_CONDITIONAL

    if has_etag:
        return VERDICT_OK if inm == 304 else VERDICT_ETAG_REJECTED
    return VERDICT_OK if ims == 304 else VERDICT_NO_CONDITIONAL


def probe_asset(target, *, session=None, timeout=PROBE_TIMEOUT, sleep=time.sleep):
    """Baseline fetch plus the three conditional probes for one asset."""
    host = target['host']
    path = target['url']
    url = _asset_url(host, path)
    record = {
        'host': host,
        'url': path,
        'absolute_url': url,
        'requests': target.get('requests'),
        'probes': [],
    }

    base = _get(url, label='baseline', timeout=timeout, session=session)
    record['probes'].append(base.as_dict())
    record['status'] = base.status
    record['bytes'] = base.bytes
    record['elapsed_ms'] = base.elapsed_ms
    if base.error:
        record['error'] = base.error
        record['verdict'] = VERDICT_ERROR
        return record

    headers = base.headers
    record.update(
        cache_control=headers.get('Cache-Control'),
        expires=headers.get('Expires'),
        etag=headers.get('ETag'),
        last_modified=headers.get('Last-Modified'),
        content_encoding=headers.get('Content-Encoding'),
        content_length=headers.get('Content-Length'),
        content_type=headers.get('Content-Type'),
        vary=headers.get('Vary'),
        age=headers.get('Age'),
    )
    parsed = parse_cache_control(record['cache_control'])
    record['max_age'] = parsed['max_age'] if parsed else None
    record['no_store'] = bool(parsed and parsed['no_store'])
    record['no_cache'] = bool(parsed and parsed['no_cache'])
    record['has_lifetime'] = bool(
        (record['max_age'] or 0) > 0 or record['expires']
    )
    record['challenged'] = _looks_like_challenge(
        base.status, base.bytes, record['content_type'], url)

    if base.status == 200 and not record['challenged']:
        etag = record['etag']
        lm = record['last_modified']
        for label, extra in (
            ('inm', {'If-None-Match': etag} if etag else None),
            ('ims', {'If-Modified-Since': lm} if lm else None),
            ('both', {k: v for k, v in (('If-None-Match', etag),
                                        ('If-Modified-Since', lm)) if v} or None),
        ):
            if not extra:
                continue
            sleep(INTER_PROBE_SLEEP)
            probe = _get(url, extra, timeout=timeout, label=label, session=session)
            record['probes'].append(probe.as_dict())
            record[f'{label}_status'] = probe.status
            record[f'{label}_bytes'] = probe.bytes

    record['verdict'] = _classify(record)
    return record


def audit(targets, *, session=None, timeout=PROBE_TIMEOUT, sleep=time.sleep,
          budget_seconds=AUDIT_BUDGET_SECONDS, clock=time.monotonic,
          max_targets=MAX_TARGETS):
    """Probe each target in turn and summarize what the origin is doing.

    Serial on purpose. These requests hit a customer's live origin, and under
    gevent the network waits yield anyway, so the only thing parallelism would
    buy is a burst in someone else's access log.
    """
    started = clock()
    records = []
    budget_exceeded = False

    for target in list(targets)[:max_targets]:
        if clock() - started > budget_seconds:
            budget_exceeded = True
            break
        try:
            records.append(probe_asset(target, session=session, timeout=timeout,
                                       sleep=sleep))
        except Exception as e:  # noqa: BLE001 — one bad target must not end the audit
            logger.warning('header audit failed for %s%s: %s',
                           target.get('host'), target.get('url'), e)
            records.append({
                'host': target.get('host'), 'url': target.get('url'),
                'error': str(e)[:160], 'verdict': VERDICT_ERROR, 'probes': [],
            })
        sleep(INTER_PROBE_SLEEP)

    verdicts = {}
    for record in records:
        verdicts[record['verdict']] = verdicts.get(record['verdict'], 0) + 1

    result = {
        'generated_at': datetime.utcnow().isoformat(),
        'probed': len(records),
        'requested': len(list(targets)),
        'budget_exceeded': budget_exceeded,
        'verdicts': verdicts,
        'assets': records,
    }
    result['findings'] = build_findings(records)
    return result


# --- findings --------------------------------------------------------------


def _finding(code, severity, category, title, detail, evidence, impact=None):
    return {
        'code': code,
        'severity': severity,
        'category': category,
        'title': title,
        'detail': detail,
        'evidence': evidence,
        'impact': impact,
    }


def _of(subset, records):
    """The audit's impact figure is always a count out of what was probed.

    Reporting "12 assets" without the denominator would let a probe of 12
    read like a probe of 200 — and the denominator here is small by design,
    because each probe is three live requests to the customer's origin.
    """
    return f'{len(subset)} of {len(records)} probed assets'


def _brief(records):
    return [{'host': r.get('host'), 'url': r.get('url'),
             'etag': r.get('etag'), 'last_modified': r.get('last_modified'),
             'cache_control': r.get('cache_control'),
             'inm_status': r.get('inm_status'), 'ims_status': r.get('ims_status'),
             'both_status': r.get('both_status'), 'verdict': r.get('verdict')}
            for r in records[:8]]


def build_findings(records):
    findings = []
    usable = [r for r in records if r.get('verdict') not in
              (VERDICT_ERROR, VERDICT_CHALLENGED, VERDICT_BLOCKED)]

    suppressed = [r for r in records if r.get('verdict') == VERDICT_ETAG_SUPPRESSES]
    if suppressed:
        findings.append(_finding(
            'origin_etag_suppresses_last_modified', 'warning', 'origin',
            'A broken ETag is cancelling a working Last-Modified',
            f'{len(suppressed)} of the busiest assets answered a date-only conditional '
            'request with 304, but answered 200 as soon as the ETag was included. '
            'Under RFC 9110 §13.2.2 a server receiving both validators must honour the '
            'ETag and ignore the date, so the broken validator wins and every '
            'conditional request becomes a full transfer. Apache\'s mod_deflate causes '
            'this by appending "-gzip" to the ETag on compressed responses while '
            'matching against the unsuffixed value. This is an origin-side fix:\n\n'
            '    RequestHeader edit "If-None-Match" \'^"(.*)-(gzip|br)"$\' \'"$1"\'\n\n'
            'A single probe carrying both validators would have reported this as '
            '"conditional requests not supported" and hidden the cause entirely.',
            {'assets': _brief(suppressed)},
            impact=_of(suppressed, records),
        ))

    rejected = [r for r in records if r.get('verdict') == VERDICT_ETAG_REJECTED]
    if rejected:
        findings.append(_finding(
            'origin_etag_rejected', 'warning', 'origin',
            'The origin will not accept the ETags it issues',
            f'{len(rejected)} assets returned 200 for a conditional request carrying '
            'the exact ETag the origin had just sent. Every revalidation therefore '
            'costs a full body transfer instead of a 304. The usual causes are a '
            'validator rewritten in transit, or a load-balanced origin whose nodes '
            'generate different ETags for the same file.',
            {'assets': _brief(rejected)},
            impact=_of(rejected, records),
        ))

    no_lifetime = [r for r in usable if r.get('status') == 200
                   and not r.get('has_lifetime') and not r.get('no_store')]
    if no_lifetime:
        findings.append(_finding(
            'origin_no_freshness_lifetime', 'warning', 'origin',
            'Static assets carry no freshness lifetime',
            f'{len(no_lifetime)} of the busiest static assets came back with no '
            'usable max-age or Expires. A browser with no lifetime must contact the '
            'server on every page load even when it already holds a perfectly good '
            'copy — which is exactly the repeat-fetch pattern the log analysis '
            'measured. Giving fingerprinted assets a long max-age removes those '
            'requests outright rather than making them cheaper.',
            {'assets': _brief(no_lifetime)},
            impact=_of(no_lifetime, records),
        ))

    no_validators = [r for r in records if r.get('verdict') == VERDICT_NO_VALIDATORS]
    if no_validators:
        findings.append(_finding(
            'origin_no_validators', 'info', 'origin',
            'Some assets send neither ETag nor Last-Modified',
            f'{len(no_validators)} assets offered no validator at all, so a browser '
            'has no way to ask "has this changed?" — once its copy expires the only '
            'option is a full re-download.',
            {'assets': _brief(no_validators)},
            impact=_of(no_validators, records),
        ))

    uncompressed = [
        r for r in usable
        if r.get('status') == 200 and not r.get('content_encoding')
        and (r.get('url') or '').rsplit('.', 1)[-1].lower() in TEXT_EXTENSIONS
    ]
    if uncompressed:
        findings.append(_finding(
            'waas_compression_absent', 'info', 'waas_config',
            'Text assets are being served uncompressed',
            f'{len(uncompressed)} text assets came back with no Content-Encoding even '
            'though the probe advertised gzip, deflate and br. WaaS adds a '
            '"remove-accept-encoding-header" request rewrite by default, which strips '
            'the header before the origin sees it — so the origin never learns the '
            'client could accept compression. That rewrite is load-bearing across the '
            'estate, so treat this as context for a bandwidth conversation rather '
            'than a setting to flip unilaterally.',
            {'assets': _brief(uncompressed)},
            impact=_of(uncompressed, records),
        ))

    challenged = [r for r in records if r.get('verdict') == VERDICT_CHALLENGED]
    if challenged:
        findings.append(_finding(
            'audit_challenged', 'info', 'waas_config',
            'Some probes were answered with a challenge page',
            f'{len(challenged)} probes received an HTML body in place of the asset, '
            'which means WaaS challenged the request. The headers on those responses '
            'describe the challenge page, not the asset, so they are excluded from '
            'the conclusions above rather than quietly folded in.',
            {'assets': _brief(challenged)},
            impact=_of(challenged, records),
        ))

    errored = [r for r in records if r.get('verdict') == VERDICT_ERROR]
    if errored:
        findings.append(_finding(
            'audit_unreachable', 'info', 'origin',
            'Some assets could not be reached',
            f'{len(errored)} probes failed outright (connection, TLS or timeout). '
            'They are listed so the sample size behind the findings above is visible.',
            {'assets': [{'host': r.get('host'), 'url': r.get('url'),
                         'error': r.get('error')} for r in errored[:8]]},
            impact=_of(errored, records),
        ))

    ok = [r for r in records if r.get('verdict') == VERDICT_OK]
    if ok and not suppressed and not rejected:
        findings.append(_finding(
            'origin_conditional_ok', 'info', 'origin',
            'Conditional requests are honoured',
            f'{len(ok)} of {len(records)} probed assets returned 304 to a conditional '
            f'request ({_pct(_rate(len(ok), len(records)) or 0)}). Revalidation works '
            'on this origin, so any excess traffic the log analysis found is a '
            'freshness-lifetime problem rather than a validator problem.',
            {'assets': _brief(ok)},
            impact=_of(ok, records),
        ))

    return findings
