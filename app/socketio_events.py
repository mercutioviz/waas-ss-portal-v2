"""SocketIO event handlers for real-time updates."""

import logging

import gevent.event
from flask_login import current_user
from flask_socketio import emit, join_room, leave_room
from app import socketio

logger = logging.getLogger(__name__)

# Optional "browser has joined the room" handshake used by the profiler flow.
# A background greenlet can call `pending_join(room)` to get an Event, then
# `event.wait(timeout=…)` before its first emit — cleaner than the fixed
# time.sleep in the older bulk/clone flows. Existing flows are unaffected:
# they never call pending_join, so no Event is ever created for their rooms.
_JOIN_SIGNALS: dict[str, gevent.event.Event] = {}


def pending_join(room: str) -> gevent.event.Event:
    """Return an Event that fires when a client joins `room`. Idempotent."""
    ev = _JOIN_SIGNALS.get(room)
    if ev is None:
        ev = gevent.event.Event()
        _JOIN_SIGNALS[room] = ev
    return ev


def clear_join_signal(room: str) -> None:
    """Drop the signal after the greenlet is done with it."""
    _JOIN_SIGNALS.pop(room, None)


@socketio.on('connect')
def handle_connect():
    """Authenticate WebSocket connections."""
    authed = current_user.is_authenticated
    logger.info(f'socketio: connect fired, authenticated={authed}, user={getattr(current_user, "username", "?")}')
    if not authed:
        return False  # Reject unauthenticated connections


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    logger.info(f'socketio: disconnect fired, user={getattr(current_user, "username", "?")}')


@socketio.on('join')
def handle_join(data):
    """Join a room for scoped updates (e.g., bulk operation session)."""
    # Log FIRST, before any guard — we need to see the handler firing at all,
    # even when the auth or room check bails out.
    logger.info(f'socketio: join fired, data={data!r}, authed={current_user.is_authenticated}')
    room = data.get('room') if isinstance(data, dict) else None
    if room and current_user.is_authenticated:
        join_room(room)
        logger.info(f'socketio: user={current_user.username} joined room={room}')
        emit('joined', {'room': room})
        # If a background greenlet is waiting for this room to be joined
        # before starting to emit, release it now.
        pending = _JOIN_SIGNALS.get(room)
        if pending is not None:
            pending.set()
            logger.info(f'socketio: released pending_join for room={room}')


@socketio.on('leave')
def handle_leave(data):
    """Leave a room."""
    room = data.get('room')
    if room:
        leave_room(room)
        logger.debug(f'User {current_user.username} left room {room}')
