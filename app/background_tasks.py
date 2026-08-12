"""Background task helpers for WebSocket-powered operations."""

import logging
import traceback
from app import socketio
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
