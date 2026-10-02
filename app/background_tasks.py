"""Background task helpers for WebSocket-powered operations."""

import logging
import time
import traceback
from datetime import datetime, timedelta

from app import db, socketio
from app.waas_client import WaasClient, WaasApiError

logger = logging.getLogger(__name__)

SITE_PROFILE_RETENTION_DAYS = 30
SECURITY_METRIC_RETENTION_DAYS = 90
SECURITY_METRIC_QUICK_RANGE = 'r_1h'


def run_bulk_operation(session_id, items, operation_func, name='Bulk operation'):
    """Run a bulk operation with per-item progress events.

    Args:
        session_id: Unique ID for this operation (used as SocketIO room).
        items: List of dicts with item details (must have 'label' key).
        operation_func: Callable(item) -> dict with 'status' and optional 'error'.
        name: Human-readable operation name.
    """
    total = len(items)
    results = []

    socketio.emit('bulk_progress', {
        'phase': 'started',
        'total': total,
        'completed': 0,
        'name': name,
    }, room=session_id)

    for i, item in enumerate(items):
        try:
            result = operation_func(item)
            result['label'] = item.get('label', f'Item {i + 1}')
            results.append(result)
        except Exception as e:
            logger.error(f'Bulk op error on {item}: {traceback.format_exc()}')
            results.append({
                'label': item.get('label', f'Item {i + 1}'),
                'status': 'error',
                'error': str(e),
            })

        socketio.emit('bulk_progress', {
            'phase': 'progress',
            'total': total,
            'completed': i + 1,
            'current': results[-1],
            'percent': int(((i + 1) / total) * 100),
        }, room=session_id)

    succeeded = sum(1 for r in results if r.get('status') == 'success')
    failed = total - succeeded

    socketio.emit('bulk_progress', {
        'phase': 'completed',
        'total': total,
        'succeeded': succeeded,
        'failed': failed,
        'results': results,
    }, room=session_id)

    return results


def run_clone_operation(session_id, steps):
    """Run a multi-step clone operation with per-step progress.

    Args:
        session_id: Unique ID for this operation (used as SocketIO room).
        steps: List of dicts with 'name' and 'func' (callable returning dict).
    """
    total = len(steps)
    results = []

    socketio.emit('clone_progress', {
        'phase': 'started',
        'total': total,
        'completed': 0,
    }, room=session_id)

    for i, step in enumerate(steps):
        step_name = step.get('name', f'Step {i + 1}')

        socketio.emit('clone_progress', {
            'phase': 'step_start',
            'step': i + 1,
            'total': total,
            'step_name': step_name,
            'percent': int((i / total) * 100),
        }, room=session_id)

        try:
            result = step['func']()
            result['step_name'] = step_name
            results.append(result)
        except WaasApiError as e:
            logger.error(f'Clone step "{step_name}" error: {traceback.format_exc()}')
            results.append({
                'step_name': step_name,
                'status': 'error',
                'error': str(e),
                'api_details': {
                    'status_code': e.status_code,
                    'method': e.request_method,
                    'url': e.request_url,
                    'request_data': e.request_data,
                    'response_data': e.response_data,
                },
            })
        except Exception as e:
            logger.error(f'Clone step "{step_name}" error: {traceback.format_exc()}')
            results.append({
                'step_name': step_name,
                'status': 'error',
                'error': str(e),
            })

        socketio.emit('clone_progress', {
            'phase': 'step_complete',
            'step': i + 1,
            'total': total,
            'step_name': step_name,
            'result': results[-1],
            'percent': int(((i + 1) / total) * 100),
        }, room=session_id)

        # Abort on critical failure (step 1 is create app — if that fails, skip rest)
        if results[-1].get('status') == 'error' and i == 0:
            socketio.emit('clone_progress', {
                'phase': 'aborted',
                'reason': results[-1].get('error', 'Critical step failed'),
                'results': results,
            }, room=session_id)
            return results

    all_ok = all(r.get('status') == 'success' for r in results)

    socketio.emit('clone_progress', {
        'phase': 'completed',
        'success': all_ok,
        'results': results,
    }, room=session_id)

    return results


def run_site_profile(app, profile_id: int, session_id: str, target_url: str) -> None:
    """Greenlet body: probe `target_url`, persist result, emit progress.

    Signals over SocketIO as `profile_progress` events with the same
    started / step_start / step_complete / completed / error shape as
    clone_progress (adapted for our step vocabulary).

    All failure paths — including unhandled exceptions — write a terminal
    status back to the SiteProfile row so no row is left stuck in 'probing'.
    """
    from app.models import SiteProfile
    from app.profiler.probe import PROBE_STEPS, SsrfRejected, run_probe
    from app.profiler.recommender import recommend
    from app.socketio_events import clear_join_signal, pending_join

    with app.app_context():
        # Wait up to 10s for the browser to join the room before we start
        # emitting. The route pre-creates the Event before spawning us, so
        # handle_join will fire it whichever ordering the scheduler picks.
        # 10s is generous cover for slow SocketIO polling handshakes;
        # falls through anyway so a browser that never connects doesn't
        # hang the greenlet.
        try:
            pending_join(session_id).wait(timeout=10.0)
        except Exception:  # pragma: no cover — defensive
            pass

        profile_row = db.session.get(SiteProfile, profile_id)
        if profile_row is None:
            logger.error(f'run_site_profile: no SiteProfile with id={profile_id}')
            clear_join_signal(session_id)
            return

        profile_row.status = SiteProfile.STATUS_PROBING
        db.session.commit()

        step_labels = {s.key: s.label for s in PROBE_STEPS}
        total = len(PROBE_STEPS)

        socketio.emit('profile_progress', {
            'phase': 'started',
            'total': total,
            'target_url': target_url,
        }, room=session_id)

        # Track step ordering so 'skip' / 'error' events can be positioned
        # correctly in the UI even when a step is missed entirely.
        step_index = {s.key: i + 1 for i, s in enumerate(PROBE_STEPS)}

        def _emit(step_key: str, phase: str, data: dict | None = None) -> None:
            payload = {
                'phase': f'step_{phase}',
                'step': step_index.get(step_key, 0),
                'total': total,
                'step_key': step_key,
                'step_name': step_labels.get(step_key, step_key),
                'percent': int((step_index.get(step_key, 0) / total) * 100),
            }
            if data:
                payload['data'] = data
            socketio.emit('profile_progress', payload, room=session_id)

        try:
            profile = run_probe(target_url, emit=_emit)
            recommendation = recommend(profile)

            profile_row.profile = profile.to_dict()
            profile_row.recommendation = recommendation
            profile_row.status = SiteProfile.STATUS_COMPLETE
            profile_row.completed_at = datetime.utcnow()
            db.session.commit()

            socketio.emit('profile_progress', {
                'phase': 'completed',
                'redirect_url': f'/profiler/{profile_id}/results',
                'confidence': profile.confidence,
            }, room=session_id)

        except SsrfRejected as e:
            profile_row.status = SiteProfile.STATUS_ERROR
            profile_row.error_message = str(e)
            profile_row.completed_at = datetime.utcnow()
            db.session.commit()
            socketio.emit('profile_progress', {
                'phase': 'error',
                'reason': str(e),
                'category': 'ssrf',
            }, room=session_id)

        except Exception as e:  # noqa: BLE001 — terminal-state guarantee
            logger.error(f'run_site_profile error: {traceback.format_exc()}')
            profile_row.status = SiteProfile.STATUS_ERROR
            profile_row.error_message = str(e)
            profile_row.completed_at = datetime.utcnow()
            db.session.commit()
            socketio.emit('profile_progress', {
                'phase': 'error',
                'reason': str(e),
                'category': 'internal',
            }, room=session_id)

        finally:
            clear_join_signal(session_id)


def run_site_profile_cleanup(app) -> int:
    """Delete SiteProfile rows older than SITE_PROFILE_RETENTION_DAYS.

    Runs on a daily APScheduler cron job (see app/__init__.py) and is also
    exposed as `flask cleanup-site-profiles` for manual invocation.
    """
    from app.models import SiteProfile

    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(days=SITE_PROFILE_RETENTION_DAYS)
        deleted = SiteProfile.query.filter(SiteProfile.created_at < cutoff) \
            .delete(synchronize_session=False)
        db.session.commit()
        logger.info(f'Site profile cleanup: deleted {deleted} row(s) older than '
                    f'{SITE_PROFILE_RETENTION_DAYS} days.')
        return deleted


def _parse_app_list(result):
    """Normalise a list_applications() response into a plain Python list.

    Duplicated (not imported) from app.routes.applications, matching the
    existing convention of each call site keeping its own small copy
    (see app/routes/features.py, app/routes/templates.py).
    """
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        apps = result.get('results', result.get('data', result.get('applications', [])))
        return apps if isinstance(apps, list) else [result]
    return []


def capture_security_metrics(app) -> int:
    """Snapshot per-app WAF security metrics for trend history.

    Iterates every active WaasAccount (system-wide, not scoped to a portal
    user) and every application under it, reusing the existing get_logs() +
    aggregate_waf_logs() aggregation — no duplicate metric logic.

    Runs on an hourly APScheduler job (see app/__init__.py) and is also
    exposed as `flask run-security-metrics` for manual invocation.
    """
    from app.models import WaasAccount, SecurityMetricSnapshot
    from app.security_dashboard import aggregate_waf_logs

    captured = 0

    with app.app_context():
        accounts = WaasAccount.query.filter_by(is_active=True).all()
        for account in accounts:
            try:
                client = WaasClient.from_account(account)
                apps = _parse_app_list(client.list_applications())
            except WaasApiError as e:
                logger.warning(f'Security metric capture: failed to list apps for account {account.id}: {e}')
                continue

            for app_entry in apps:
                app_id = app_entry.get('name')
                if not app_id:
                    continue
                try:
                    result = client.get_logs(
                        app_id,
                        quick_range=SECURITY_METRIC_QUICK_RANGE,
                        items_per_page=1000,
                        filter_fields={'LogType': [{'condition': 'is', 'value': 'WF'}]},
                    )
                except WaasApiError as e:
                    logger.warning(f'Security metric capture: failed to fetch logs for '
                                   f'account {account.id}/{app_id}: {e}')
                    continue

                logs = result.get('results', []) if isinstance(result, dict) else []
                total_from_api = result.get('count', len(logs)) if isinstance(result, dict) else len(logs)
                data = aggregate_waf_logs(logs, SECURITY_METRIC_QUICK_RANGE, total_from_api=total_from_api)

                snapshot = SecurityMetricSnapshot(
                    account_id=account.id,
                    app_id=app_id,
                    app_name=app_entry.get('name', app_id),
                    quick_range=SECURITY_METRIC_QUICK_RANGE,
                    blocked_count=data['blocked_count'],
                    unique_ip_count=data['unique_ip_count'],
                    unique_rule_count=data['unique_rule_count'],
                )
                snapshot.top_rules = data['top_rules']
                snapshot.top_ips = data['top_ips']
                snapshot.top_urls = data['top_urls']
                db.session.add(snapshot)
                captured += 1

        db.session.commit()
        logger.info(f'Security metric capture: recorded {captured} snapshot(s).')
        return captured


def run_security_metric_cleanup(app) -> int:
    """Delete SecurityMetricSnapshot rows older than SECURITY_METRIC_RETENTION_DAYS.

    Runs on a daily APScheduler cron job (see app/__init__.py) and is also
    exposed as `flask cleanup-security-metrics` for manual invocation.
    """
    from app.models import SecurityMetricSnapshot

    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(days=SECURITY_METRIC_RETENTION_DAYS)
        deleted = SecurityMetricSnapshot.query.filter(SecurityMetricSnapshot.captured_at < cutoff) \
            .delete(synchronize_session=False)
        db.session.commit()
        logger.info(f'Security metric cleanup: deleted {deleted} row(s) older than '
                    f'{SECURITY_METRIC_RETENTION_DAYS} days.')
        return deleted


# --- Log pulls (traffic reduction analysis) --------------------------------

LOG_PULL_RAW_RETENTION_DAYS = 3
LOG_PULL_RESULT_RETENTION_DAYS = 30


def run_log_pull(app, pull_id: int, session_id: str) -> None:
    """Greenlet body: collect access logs for a LogPull, persist, emit progress.

    Unlike run_site_profile this can run for hours, which changes two things.
    Progress is written to the LogPull row on a throttle and SocketIO merely
    mirrors it, so a browser that reconnects (or a user on another machine)
    sees real state. And every exit path — including a service restart
    landing mid-pull — leaves either a terminal status or `interrupted` with
    the partial data intact and resumable.
    """
    from app.logpull.runner import DiskAborted, PullRunner
    from app.logpull.windows import Cancelled, Window
    from app.models import LogPull
    from app.socketio_events import clear_join_signal, pending_join

    with app.app_context():
        try:
            pending_join(session_id).wait(timeout=10.0)
        except Exception:  # pragma: no cover — defensive
            pass

        pull = db.session.get(LogPull, pull_id)
        if pull is None:
            logger.error(f'run_log_pull: no LogPull with id={pull_id}')
            clear_join_signal(session_id)
            return

        def emit(payload):
            socketio.emit('logpull_progress', payload, room=session_id)

        try:
            account = pull.account
            client = WaasClient.from_account(account)

            pull.status = LogPull.STATUS_RUNNING
            pull.started_at = datetime.utcnow()
            pull.phase = LogPull.PHASE_COUNTING
            pull.raw_expires_at = datetime.utcnow() + timedelta(days=LOG_PULL_RAW_RETENTION_DAYS)
            db.session.commit()
            emit(pull.to_dict())

            runner = PullRunner(db, pull, client, app.instance_path, emit=emit)

            # Exact denominator for the progress bar. Already computed at
            # pre-flight, but re-counted here because the user may have sat
            # on the confirmation page and the window has moved since.
            if not pull.rows_expected:
                total = runner.source.count(Window(pull.range_start, pull.range_end))
                pull.rows_expected = total
                db.session.commit()

            summary = runner.run()
            summary['analysis'] = _analyze_collected(app, pull, summary, emit,
                                                     runner.store)

            pull.result = summary
            pull.status = LogPull.STATUS_COMPLETE
            pull.phase = LogPull.PHASE_DONE
            pull.completed_at = datetime.utcnow()
            pull.bytes_on_disk = runner.store.size_bytes()
            pull.eta_seconds = 0
            db.session.commit()
            emit(pull.to_dict())

        except Cancelled:
            logger.info(f'run_log_pull: pull {pull_id} cancelled by user')
            _finish_pull(pull, LogPull.STATUS_CANCELLED,
                         'Cancelled. Partial data kept.', emit)

        except DiskAborted as e:
            logger.error(f'run_log_pull: pull {pull_id} aborted on disk: {e}')
            _finish_pull(pull, LogPull.STATUS_ABORTED_DISK, str(e), emit)

        except WaasApiError as e:
            logger.error(f'run_log_pull: pull {pull_id} API error: {e}')
            _finish_pull(pull, LogPull.STATUS_ERROR, str(e), emit)

        except Exception as e:  # noqa: BLE001 — terminal-state guarantee
            logger.error(f'run_log_pull error: {traceback.format_exc()}')
            _finish_pull(pull, LogPull.STATUS_ERROR, str(e), emit)

        finally:
            clear_join_signal(session_id)


#: Emit an analysis progress tick at most this often. The parse is a tight
#: loop over millions of rows; a socket write per chunk would cost more than
#: the parsing.
ANALYSIS_EMIT_INTERVAL_SECONDS = 2.0


def _analyze_collected(app, pull, summary, emit, store=None):
    """Run the cache analysis over the rows just collected.

    Failure here is not failure of the pull. The rows are on disk and the
    collection is the expensive part, so an analysis that blows up leaves a
    complete pull with an `analysis_error` the user can retry, rather than
    throwing away hours of fetching.
    """
    from app.logpull.analysis import analyze_pull
    from app.logpull.crawlers import ranges_cache_dir
    from app.logpull.store import PullStore
    from app.models import LogPull

    store = store or PullStore(app.instance_path, pull.id)
    pull.phase = LogPull.PHASE_ANALYZING
    db.session.commit()
    emit(pull.to_dict())

    state = {'last': 0.0}

    def on_progress(rows):
        now = time.monotonic()
        if now - state['last'] < ANALYSIS_EMIT_INTERVAL_SECONDS:
            return
        state['last'] = now
        emit({**pull.to_dict(), 'analysis_rows': rows})

    try:
        return analyze_pull(store, summary, on_progress=on_progress,
                            ranges_dir=ranges_cache_dir(app.instance_path))
    except Exception as e:  # noqa: BLE001 — never lose a completed collection
        logger.error(f'log pull {pull.id} analysis failed: {traceback.format_exc()}')
        return {'error': str(e)[:300]}


def run_log_pull_analysis(app, pull_id: int) -> None:
    """Re-run the cache analysis over an already-collected pull.

    Needed because the analysis is cheap relative to the collection and its
    logic will keep changing: a pull collected last week should be able to
    benefit from this week's metrics without spending hours re-fetching rows
    that are already on disk.
    """
    from app.logpull.store import PullStore
    from app.models import LogPull

    with app.app_context():
        pull = db.session.get(LogPull, pull_id)
        if pull is None:
            logger.error(f'run_log_pull_analysis: no LogPull with id={pull_id}')
            return

        def emit(payload):
            socketio.emit('logpull_progress', payload, room=pull.session_id)

        store = PullStore(app.instance_path, pull.id)
        previous_phase = pull.phase
        try:
            summary = pull.result or {}
            analysis = _analyze_collected(app, pull, summary, emit, store)
            summary['analysis'] = analysis
            pull.result = summary
            pull.phase = LogPull.PHASE_DONE
            db.session.commit()
            emit(pull.to_dict())
        except Exception:  # noqa: BLE001 — defensive; _analyze_collected catches its own
            logger.error(f'run_log_pull_analysis error: {traceback.format_exc()}')
            db.session.rollback()
            pull.phase = previous_phase
            db.session.commit()


def run_header_audit(app, pull_id: int) -> None:
    """Probe the busiest static assets live and record what came back.

    Separate from the pull on purpose: this sends real requests to the
    customer's origin, so it is something a user asks for explicitly rather
    than a side effect of collecting logs.
    """
    from app.logpull.header_audit import audit
    from app.models import LogPull

    with app.app_context():
        pull = db.session.get(LogPull, pull_id)
        if pull is None:
            logger.error(f'run_header_audit: no LogPull with id={pull_id}')
            return

        analysis = (pull.result or {}).get('analysis') or {}
        targets = analysis.get('audit_targets') or []
        report = pull.report or {}
        try:
            report['header_audit'] = audit(targets)
        except Exception as e:  # noqa: BLE001 — the audit is best-effort
            logger.error(f'run_header_audit error: {traceback.format_exc()}')
            report['header_audit'] = {
                'error': str(e)[:300], 'assets': [], 'findings': [],
                'probed': 0, 'requested': len(targets),
            }
        report['header_audit']['skipped_hosts'] = analysis.get('audit_skipped_hosts') or []
        pull.report = report
        db.session.commit()
        socketio.emit('logpull_audit_done', {'pull_id': pull.id},
                      room=pull.session_id)


def _finish_pull(pull, status, message, emit):
    """Write a terminal status, tolerating a broken session."""
    from app.models import LogPull

    try:
        pull.status = status
        pull.phase = LogPull.PHASE_DONE
        pull.error_message = message
        pull.completed_at = datetime.utcnow()
        db.session.commit()
        emit(pull.to_dict())
    except Exception:  # pragma: no cover — defensive
        logger.error(f'_finish_pull failed: {traceback.format_exc()}')
        db.session.rollback()


def reconcile_interrupted_pulls(app) -> int:
    """Mark pulls left RUNNING by a restart as interrupted.

    Called at startup. A greenlet does not survive `systemctl restart`, so
    any row still claiming to be running is stale. Its partial data stays on
    disk and the day checkpoints make it resumable, so this marks rather
    than deletes.
    """
    from app.models import LogPull

    with app.app_context():
        stale = LogPull.query.filter(
            LogPull.status.in_(LogPull.ACTIVE_STATUSES)
        ).all()
        for pull in stale:
            pull.status = LogPull.STATUS_INTERRUPTED
            pull.error_message = (
                'Interrupted by a portal restart. Collected days were kept; '
                'resuming continues from the last completed day.'
            )
        if stale:
            db.session.commit()
            logger.info(f'Marked {len(stale)} interrupted log pull(s).')
        return len(stale)


def run_log_pull_cleanup(app) -> int:
    """Retention sweep: reap raw rows, then whole pulls.

    Two windows, deliberately. Raw rows are gigabytes with a short useful
    life; the aggregates and report are kilobytes and should outlive them.
    Splitting the two is what makes a 3-day raw retention safe — the pull
    stays visible and its report still opens afterwards, just marked as
    having expired raw data.
    """
    from app.logpull.store import PullStore
    from app.models import LogPull

    with app.app_context():
        freed = 0
        now = datetime.utcnow()

        raw_due = LogPull.query.filter(
            LogPull.raw_deleted.is_(False),
            LogPull.raw_expires_at.isnot(None),
            LogPull.raw_expires_at < now,
            LogPull.status.notin_(LogPull.ACTIVE_STATUSES),
        ).all()
        for pull in raw_due:
            freed += PullStore(app.instance_path, pull.id).delete_raw()
            pull.raw_deleted = True
            pull.bytes_on_disk = PullStore(app.instance_path, pull.id).size_bytes()

        result_cutoff = now - timedelta(days=LOG_PULL_RESULT_RETENTION_DAYS)
        old = LogPull.query.filter(
            LogPull.created_at < result_cutoff,
            LogPull.status.notin_(LogPull.ACTIVE_STATUSES),
        ).all()
        for pull in old:
            freed += PullStore(app.instance_path, pull.id).delete_all()
            db.session.delete(pull)

        if raw_due or old:
            db.session.commit()
            logger.info(
                f'Log pull cleanup: reaped raw for {len(raw_due)}, '
                f'deleted {len(old)} pull(s), freed {freed / 1e6:.1f} MB.'
            )
        return len(raw_due) + len(old)
