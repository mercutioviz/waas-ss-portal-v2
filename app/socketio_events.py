"""SocketIO event handlers for real-time updates."""

import logging
from flask_login import current_user
from flask_socketio import emit, join_room, leave_room
from app import socketio

logger = logging.getLogger(__name__)


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


@socketio.on('leave')
def handle_leave(data):
    """Leave a room."""
    room = data.get('room')
    if room:
        leave_room(room)
        logger.debug(f'User {current_user.username} left room {room}')
