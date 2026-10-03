"""Per-application traffic hints for the application list.

Answers one question cheaply: of the apps on this account, which ones carry
enough traffic to be worth pointing an analysis at? On a 59-app account that
is otherwise guesswork, and the spread is wide enough to be decisive —
measured on one account, 30-day request counts ran from 25 to 28,454,451.

Two measures, from two different APIs, because no single endpoint has both:

- **Requests** — exact, from the v4 logs API's count field via
  ``LogSource.count()``. One call per app at roughly 0.3–1.1s, available on
  any account. This is the same primitive the log-pull pre-flight uses.
- **Egress bytes and attack share** — from the v2 bandwidth report, which
  returns every app on the account in a single ~1.1s call but requires v2
  email/password credentials.

The v4 API has no per-application usage endpoint at all; its ``/fup_usage/``
report is account-scoped and carries no application field, so it cannot
answer this question however it is sliced.

Results are cached in ``AppTrafficSnapshot`` so revisiting the list is free.
The cache is deliberately short-lived: these are hints for choosing a target,
not figures anyone should quote.
"""
import logging
import time
from datetime import datetime, timedelta

from app import db
from app.logpull.source import LogSource
from app.logpull.windows import Window
from app.models import AppTrafficSnapshot
from app.waas_client import WaasApiError

logger = logging.getLogger(__name__)

#: The window every hint describes. Fixed rather than configurable because the
#: v2 bandwidth report returns HTTP 500 for r_45d and above, so 30 days is the
#: ceiling on the half of the data that cannot be recomputed locally.
WINDOW_DAYS = 30

QUICK_RANGE = 'r_30d'

#: Long enough that paging back and forth between accounts is instant, short
#: enough that a day-old number never masquerades as current.
TTL_SECONDS = 6 * 3600

#: Per-request ceiling on how many apps one count sweep will touch. Each count
#: is a live API call taking up to ~1.1s, and gunicorn's worker timeout is
#: 120s; chunking keeps any single request far inside that and lets the table
#: fill progressively instead of all at once at the end.
MAX_COUNT_BATCH = 10


def load_cached(account_id, app_names, window_days=WINDOW_DAYS, now=None):
    """Return ``{app_name: dict}`` for cached rows that are still fresh.

    Stale rows are omitted rather than returned with a flag — a caller that
    wants them refreshed and a caller that wants them displayed want the same
    thing here, which is a fetch.
    """
    if not app_names:
        return {}
    now = now or datetime.utcnow()
    cutoff = now - timedelta(seconds=TTL_SECONDS)
    rows = AppTrafficSnapshot.query.filter(
        AppTrafficSnapshot.account_id == account_id,
        AppTrafficSnapshot.window_days == window_days,
        AppTrafficSnapshot.app_name.in_(list(app_names)),
        AppTrafficSnapshot.captured_at >= cutoff,
    ).all()
    return {row.app_name: row.to_dict() for row in rows}


def _bad_share(row):
    """Attack traffic as a fraction of the app's total.

    Computed as a ratio on purpose. The underlying ``*_sum`` floats are
    expressed in whatever unit the report chose for the range — MB at r_7d, GB
    at r_30d — so their absolute values cannot be compared or displayed
    without conversion, but their ratio is unit-independent.
    """
    total = row.get('app_total_sum')
    bad = row.get('app_bad_sum')
    if not total or bad is None:
        return None
    try:
        return max(0.0, min(1.0, float(bad) / float(total)))
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def fetch_bandwidth(client, account, quick_range=QUICK_RANGE):
    """Per-app bandwidth for the whole account in one call.

    Returns ``{app_name: {'metered_bytes': int, 'bad_share': float|None}}``,
    or ``{}`` when the account has no v2 credentials. The empty dict is the
    honest answer there — the data is unavailable, which is different from
    the account having no traffic, and the caller reports it as such.
    """
    return fetch_bandwidth_report(client, account, quick_range)[0]


def fetch_bandwidth_report(client, account, quick_range=QUICK_RANGE):
    """As ``fetch_bandwidth``, plus the name of the account actually reported on.

    The second return value matters because the v2 report endpoints take no
    account parameter: they describe whichever account the v2 login resolves
    to, which is not necessarily the account this portal row's API key
    reaches. Both credentials live on the same ``WaasAccount``, and nothing
    makes them agree. Callers must check before attributing these numbers to
    anything — see ``scope_matches``.
    """
    if not account.has_v2_credentials:
        return {}, None

    result = client.get_bandwidth_summary(quick_range=quick_range) or {}
    rows = (result.get('data') or {}).get('bandwidth_data') or []
    upstream = (result.get('account') or {}).get('name')

    out = {}
    for row in rows:
        name = row.get('name')
        if not name:
            continue
        # Duplicate display names are possible (one account had two apps both
        # called "Test App"). Summing is the only reading that doesn't silently
        # drop traffic, and the list keys on name too, so it matches the row.
        entry = out.setdefault(name, {'metered_bytes': 0, 'bad_share': None})
        entry['metered_bytes'] += int(row.get('metered_bytes') or 0)
        share = _bad_share(row)
        if share is not None:
            entry['bad_share'] = max(entry['bad_share'] or 0.0, share)
    return out, upstream


def scope_matches(measured, app_names):
    """Do these bandwidth rows describe the apps we are about to label?

    The v2 report family has no account parameter, so a portal account whose
    API key reaches one WaaS account while its v2 login belongs to another
    will happily return a full, valid-looking payload for the wrong account.
    Observed live: two portal rows sharing one v2 login both reported on the
    login's default account, and the second one's apps appeared nowhere in it.

    Name overlap is the available test — the v4 application list carries no
    id field to join on. A single shared name is enough, since the alternative
    is two unrelated accounts coincidentally naming an app alike.
    """
    if not measured or not app_names:
        return True       # nothing to contradict; the caller shows dashes anyway
    return bool(set(measured) & set(app_names))


def fetch_counts(client, app_names, window_days=WINDOW_DAYS, now=None):
    """Exact request counts per app. ``{app_name: (count, error)}``.

    One app failing must not cost the rest of the batch their numbers, so
    failures are recorded per app and returned alongside the successes.
    ``LogSource`` already retries with bounded backoff, so a failure here has
    already been given its chances.
    """
    now = int(now or time.time())
    window = Window(now - window_days * 86400, now)

    out = {}
    for name in app_names:
        try:
            out[name] = (LogSource(client, name).count(window), None)
        except (WaasApiError, ValueError, KeyError) as e:
            logger.warning(f'Traffic hint: count failed for {name}: {e}')
            out[name] = (None, str(e)[:255])
    return out


def upsert(account_id, rows, window_days=WINDOW_DAYS, now=None):
    """Write or refresh cache rows. ``rows`` is ``{app_name: fields}``.

    Fields absent from a given call are left alone rather than nulled, because
    the two measures arrive from separate endpoints at separate times and
    whichever lands second must not erase the first.
    """
    if not rows:
        return {}
    now = now or datetime.utcnow()

    existing = {
        row.app_name: row
        for row in AppTrafficSnapshot.query.filter(
            AppTrafficSnapshot.account_id == account_id,
            AppTrafficSnapshot.window_days == window_days,
            AppTrafficSnapshot.app_name.in_(list(rows)),
        ).all()
    }

    out = {}
    for name, fields in rows.items():
        row = existing.get(name)
        if row is None:
            row = AppTrafficSnapshot(account_id=account_id, app_name=name,
                                     window_days=window_days)
            db.session.add(row)
            existing[name] = row
        for key in ('requests', 'metered_bytes', 'bad_share', 'error'):
            if key in fields:
                setattr(row, key, fields[key])
        row.captured_at = now
        out[name] = row

    db.session.commit()
    return {name: row.to_dict() for name, row in out.items()}
