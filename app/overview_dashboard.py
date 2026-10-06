"""Aggregation helpers for the account-overview dashboard charts.

The route (``main.dashboard_chart_data``) owns the WaaS API calls; everything
here is pure so it can be unit-tested without a client.

Two things shape this module:

- **Server health is free.** ``GET /applications/`` already returns each app's
  ``servers`` array with a ``health`` field, so the health doughnut needs no
  per-app call at all. It used to be built from ``get_application()`` (the full
  config *export*) once per app, which cost ~1.8s each and was ~80% of the
  endpoint's runtime.
- **Log data is not free.** Logs are only available per app
  (``/applications/{name}/logs/``), so the log-derived charts have to sample.
  The fan-out runs one greenlet per account under a wall-clock budget — the
  same ``gevent.pool`` shape ``app/profiler/subresources.py`` uses. One
  greenlet per account (rather than one per app) means no ``WaasClient`` is
  ever touched by two greenlets, and it degrades evenly: if the budget runs
  out, every account has got through roughly the same number of its apps.
"""
import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone

import gevent
import gevent.pool

logger = logging.getLogger(__name__)

#: Apps sampled per account for the log-derived charts. Health covers every
#: app regardless; this only bounds the per-app log fan-out.
MAX_APPS_PER_ACCOUNT = 5

#: Concurrent accounts in flight. The work is pure network wait, and the
#: portal runs a single gevent worker, so this costs no CPU.
POOL_SIZE = 8

#: Wall-clock ceiling for each fan-out pass, in seconds. Picked to stay well
#: under nginx's 60s proxy_read_timeout on `location /` (which is the default —
#: the v2 site block sets no proxy_read_timeout, so gunicorn's own 120s never
#: applies). Exceeding it returns partial data rather than a 504.
LIST_FETCH_BUDGET_SECONDS = 15.0
LOG_FETCH_BUDGET_SECONDS = 20.0
COUNTS_FETCH_BUDGET_SECONDS = 30.0

#: Per-request timeout for one app's log call, so a single hung call cannot
#: eat the whole budget.
LOG_REQUEST_TIMEOUT_SECONDS = 10.0


def run_in_pool(tasks, budget_seconds, pool_size=POOL_SIZE):
    """Run zero-arg callables concurrently under a hard wall-clock cap.

    Returns the number that finished. Tasks report results through their own
    closures rather than return values, so whatever a task completed before
    being killed at the deadline is still kept.
    """
    tasks = list(tasks)
    if not tasks:
        return 0
    pool = gevent.pool.Pool(pool_size)
    greenlets = [pool.spawn(task) for task in tasks]
    gevent.wait(greenlets, timeout=max(budget_seconds, 0.0))
    finished = 0
    for greenlet in greenlets:
        if greenlet.ready():
            finished += 1
        else:
            greenlet.kill(block=False)
    return finished


def extract_app_list(apps_resp):
    """Normalise the varying shapes ``list_applications()`` can return."""
    if isinstance(apps_resp, list):
        return apps_resp
    if isinstance(apps_resp, dict):
        for key in ('results', 'data', 'applications'):
            if key in apps_resp:
                value = apps_resp[key]
                if isinstance(value, list):
                    return value
    return []


def tally_server_health(app_list, health=None):
    """Count server health across every app in ``app_list``.

    Reads ``servers[].health`` straight off the application list response.
    Anything that isn't recognisably up or down counts as unknown, including
    apps with no servers at all.
    """
    health = health if health is not None else {'up': 0, 'down': 0, 'unknown': 0}
    for app in app_list:
        if not isinstance(app, dict):
            continue
        for server in app.get('servers') or []:
            if not isinstance(server, dict):
                continue
            state = (server.get('health') or '').strip().lower()
            if state == 'up':
                health['up'] += 1
            elif state == 'down':
                health['down'] += 1
            else:
                health['unknown'] += 1
    return health


def app_names(app_list, limit=None):
    """Pull usable application names out of a list response, in order."""
    names = []
    for app in app_list:
        if not isinstance(app, dict):
            continue
        name = app.get('name')
        if name:
            names.append(name)
            if limit is not None and len(names) >= limit:
                break
    return names


def accumulate_log_entries(entries, timeline=None, top_ips=None, top_attack_types=None):
    """Fold one app's log entries into the shared chart accumulators.

    Returns ``(timeline, top_ips, top_attack_types, attack_count)``.
    """
    timeline = timeline if timeline is not None else defaultdict(int)
    top_ips = top_ips if top_ips is not None else Counter()
    top_attack_types = top_attack_types if top_attack_types is not None else Counter()
    attack_count = 0

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        # WaaS returns 'EpochTime' in epoch milliseconds.
        raw_ts = entry.get('EpochTime')
        if raw_ts:
            try:
                moment = datetime.fromtimestamp(int(raw_ts) / 1000.0, tz=timezone.utc)
                timeline[moment.strftime('%m-%d %H:00')] += 1
            except (ValueError, TypeError, OSError, OverflowError):
                pass

        client_ip = entry.get('ClientIP')
        if client_ip:
            top_ips[client_ip] += 1

        # Prefer AttackGroup for WAF events, fall back to Action
        # (Blocked/Allowed/...) for plain access-log rows.
        attack_type = entry.get('AttackGroup') or entry.get('Action')
        if attack_type and attack_type != '-':
            top_attack_types[attack_type] += 1
            attack_count += 1

    return timeline, top_ips, top_attack_types, attack_count


def build_chart_payload(timeline, top_ips, top_attack_types, server_health,
                        total_requests, total_attacks, apps_sampled,
                        apps_total, partial, errors=None):
    """Assemble the JSON body the dashboard charts consume."""
    sorted_timeline = sorted(timeline.items())
    return {
        'attack_timeline': {
            'labels': [label for label, _ in sorted_timeline],
            'data': [count for _, count in sorted_timeline],
        },
        'top_ips': {
            'labels': [ip for ip, _ in top_ips.most_common(10)],
            'data': [count for _, count in top_ips.most_common(10)],
        },
        'top_attack_types': {
            'labels': [name for name, _ in top_attack_types.most_common(8)],
            'data': [count for _, count in top_attack_types.most_common(8)],
        },
        'server_health': server_health,
        'summary': {
            'total_requests': total_requests,
            'total_attacks': total_attacks,
            # apps_checked is what the old payload called this; keep the name
            # so the template keeps working, but send the total alongside so
            # the UI can say "40 of 194" instead of implying full coverage.
            'apps_checked': apps_sampled,
            'apps_total': apps_total,
            'partial': partial,
        },
        'errors': errors or [],
    }
