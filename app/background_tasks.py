"""Background task helpers for WebSocket-powered operations."""

import logging
import traceback
from datetime import datetime

from app import db, socketio
from app.waas_client import WaasApiError

logger = logging.getLogger(__name__)


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

        logger.info(f'profiler: emitting to room={session_id} (probe of {target_url})')
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
