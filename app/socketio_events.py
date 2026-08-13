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
    if not current_user.is_authenticated:
        return False  # Reject unauthenticated connections
    logger.debug(f'WebSocket connected: user={current_user.username}')


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    if current_user.is_authenticated:
        logger.debug(f'WebSocket disconnected: user={current_user.username}')


@socketio.on('join')
def handle_join(data):
    """Join a room for scoped updates (e.g., bulk operation session)."""
    room = data.get('room')
    if room and current_user.is_authenticated:
        join_room(room)
        logger.debug(f'User {current_user.username} joined room {room}')
        emit('joined', {'room': room})
        # If a background greenlet is waiting for this room to be joined
        # before starting to emit, release it now.
        pending = _JOIN_SIGNALS.get(room)
        if pending is not None:
            pending.set()


@socketio.on('leave')
def handle_leave(data):
    """Leave a room."""
    room = data.get('room')
    if room:
        leave_room(room)
        logger.debug(f'User {current_user.username} left room {room}')
