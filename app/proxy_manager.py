"""
Proxy Session Manager
Manages the lifecycle of noVNC browser proxy sessions:
  Xvfb → Chromium → x11vnc → websockify
"""
import logging
import os
import signal
import socket
import subprocess
import time
from datetime import datetime, timedelta

from app import db
from app.models import ProxySession

logger = logging.getLogger(__name__)

# Resource allocation ranges
DISPLAY_RANGE = (10, 30)       # :10 through :30
VNC_PORT_BASE = 5900           # VNC port = 5900 + display_number
WS_PORT_RANGE = (6080, 6100)   # WebSocket ports for websockify

# Limits
MAX_SESSIONS_PER_USER = 3
SESSION_TIMEOUT_MINUTES = 30


class ProxyManagerError(Exception):
    """Custom exception for proxy manager errors"""
    pass


def _is_pid_alive(pid):
    """Check if a process with the given PID is still running"""
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def _kill_pid(pid, name='process'):
    """Kill a process by PID, first with SIGTERM then SIGKILL"""
    if not pid:
        return
    try:
        os.kill(pid, signal.SIGTERM)
        # Give it a moment to terminate gracefully
        for _ in range(10):
            time.sleep(0.1)
            try:
                os.kill(pid, 0)
            except (OSError, ProcessLookupError):
                logger.info(f'  {name} (PID {pid}) terminated gracefully')
                return
        # Force kill
        os.kill(pid, signal.SIGKILL)
        logger.info(f'  {name} (PID {pid}) force killed')
    except (OSError, ProcessLookupError):
        logger.debug(f'  {name} (PID {pid}) already dead')


def _resolve_cname(cname):
    """Resolve a CNAME/hostname to an IP address"""
    try:
        ip = socket.gethostbyname(cname)
        logger.info(f'Resolved {cname} → {ip}')
        return ip
    except socket.gaierror as e:
        raise ProxyManagerError(f'Cannot resolve CNAME "{cname}": {e}')


def _allocate_resources():
    """Find the next available display number and websocket port.

    Returns (display_number, vnc_port, websocket_port) or raises ProxyManagerError.
    """
    # Get all active sessions
    active = ProxySession.query.filter(
        ProxySession.status.in_(['starting', 'active'])
    ).all()

    used_displays = {s.display_number for s in active if s.display_number}
    used_ws_ports = {s.websocket_port for s in active if s.websocket_port}

    # Find first free display
    display_number = None
    for d in range(DISPLAY_RANGE[0], DISPLAY_RANGE[1] + 1):
        if d not in used_displays:
            display_number = d
            break

    if display_number is None:
        raise ProxyManagerError('No free display numbers available. Try again later.')

    vnc_port = VNC_PORT_BASE + display_number

    # Find first free websocket port
    websocket_port = None
    for p in range(WS_PORT_RANGE[0], WS_PORT_RANGE[1] + 1):
        if p not in used_ws_ports:
            websocket_port = p
            break

    if websocket_port is None:
        raise ProxyManagerError('No free WebSocket ports available. Try again later.')

    logger.info(f'Allocated resources: display=:{display_number}, vnc_port={vnc_port}, ws_port={websocket_port}')
    return display_number, vnc_port, websocket_port


def start_session(user_id, account_id, app_id, domain, cname):
    """Start a new noVNC browser proxy session.

    Args:
        user_id: ID of the user requesting the session
        account_id: ID of the WaaS account
        app_id: WaaS application name/ID
        domain: The domain to browse (e.g. www.example.com)
        cname: The WaaS CNAME for the application

    Returns:
        ProxySession object

    Raises:
        ProxyManagerError on failure
    """
    # Check concurrent session limit
    active_count = ProxySession.query.filter_by(
        user_id=user_id
    ).filter(
        ProxySession.status.in_(['starting', 'active'])
    ).count()

    if active_count >= MAX_SESSIONS_PER_USER:
        raise ProxyManagerError(
            f'Maximum {MAX_SESSIONS_PER_USER} concurrent sessions allowed. '
            f'Please stop an existing session first.'
        )

    # Check if there's already an active session for this exact app+domain
    existing = ProxySession.query.filter_by(
        user_id=user_id,
        account_id=account_id,
        app_id=app_id,
        domain=domain,
    ).filter(
        ProxySession.status.in_(['starting', 'active'])
    ).first()

    if existing:
        # Return the existing session instead of creating a new one
        logger.info(f'Returning existing session {existing.id} for {domain}')
        return existing

    # Resolve CNAME to IP
    cname_ip = _resolve_cname(cname)

    # Allocate display/ports
    display_number, vnc_port, websocket_port = _allocate_resources()

    # Create the session record
    session = ProxySession(
        user_id=user_id,
        account_id=account_id,
        app_id=app_id,
        domain=domain,
        cname=cname,
        cname_ip=cname_ip,
        display_number=display_number,
        vnc_port=vnc_port,
        websocket_port=websocket_port,
        status='starting',
    )
    db.session.add(session)
    db.session.commit()

    display_str = f':{display_number}'
    pids = {}

    try:
        # 1. Start Xvfb
        xvfb_cmd = [
            'Xvfb', display_str,
            '-screen', '0', '1280x900x24',
            '-ac',  # disable access control
            '-nolisten', 'tcp',
        ]
        logger.info(f'Starting Xvfb: {" ".join(xvfb_cmd)}')
        xvfb_proc = subprocess.Popen(
            xvfb_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pids['xvfb'] = xvfb_proc.pid
        session.xvfb_pid = xvfb_proc.pid
        time.sleep(0.5)  # Give Xvfb time to initialize

        if xvfb_proc.poll() is not None:
            raise ProxyManagerError(f'Xvfb failed to start on display {display_str}')

        # 2. Start Chromium
        chromium_cmd = [
            'chromium',
            '--no-sandbox',
            '--disable-gpu',
            '--disable-dev-shm-usage',
            '--disable-software-rasterizer',
            f'--display={display_str}',
            f'--window-size=1280,900',
            '--start-maximized',
            '--no-first-run',
            '--disable-default-apps',
            '--disable-extensions',
            '--disable-sync',
            '--disable-translate',
            '--disable-background-networking',
            f'--host-resolver-rules=MAP {domain} {cname_ip}',
            '--ignore-certificate-errors',
            f'https://{domain}/',
        ]
        logger.info(f'Starting Chromium for {domain} → {cname_ip}')
        env = os.environ.copy()
        env['DISPLAY'] = display_str
        chromium_proc = subprocess.Popen(
            chromium_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        pids['chromium'] = chromium_proc.pid
        session.chromium_pid = chromium_proc.pid
        time.sleep(1)  # Give Chromium time to open

        # 3. Start x11vnc
        vnc_cmd = [
            'x11vnc',
            '-display', display_str,
            '-rfbport', str(vnc_port),
            '-nopw',          # no password (secured by nginx + session)
            '-shared',        # allow shared connections
            '-forever',       # don't exit after first client disconnects
            '-noxrecord',
            '-noxfixes',
            '-noxdamage',
            '-nowf',
            '-cursor', 'arrow',
        ]
        logger.info(f'Starting x11vnc on display {display_str}, port {vnc_port}')
        vnc_proc = subprocess.Popen(
            vnc_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pids['vnc'] = vnc_proc.pid
        session.vnc_pid = vnc_proc.pid
        time.sleep(0.5)

        if vnc_proc.poll() is not None:
            raise ProxyManagerError('x11vnc failed to start')

        # 4. Start websockify
        websockify_cmd = [
            'websockify',
            '--web', '/usr/share/novnc',
            str(websocket_port),
            f'localhost:{vnc_port}',
        ]
        logger.info(f'Starting websockify: ws:{websocket_port} → vnc:{vnc_port}')
        websockify_proc = subprocess.Popen(
            websockify_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pids['websockify'] = websockify_proc.pid
        session.websockify_pid = websockify_proc.pid
        time.sleep(0.3)

        if websockify_proc.poll() is not None:
            raise ProxyManagerError('websockify failed to start')

        # All processes started successfully
        session.status = 'active'
        db.session.commit()

        logger.info(
            f'Session {session.id} started: {domain} → {cname_ip}, '
            f'display=:{display_number}, ws_port={websocket_port}, '
            f'PIDs: xvfb={pids["xvfb"]}, chromium={pids["chromium"]}, '
            f'vnc={pids["vnc"]}, websockify={pids["websockify"]}'
        )
        return session

    except Exception as e:
        # Clean up any processes that were started
        logger.error(f'Session start failed, cleaning up: {e}')
        for name, pid in pids.items():
            _kill_pid(pid, name)
        session.status = 'error'
        session.stopped_at = datetime.utcnow()
        db.session.commit()
        raise ProxyManagerError(f'Failed to start proxy session: {e}')


def stop_session(session_id):
    """Stop a proxy session and kill all associated processes.

    Args:
        session_id: ID of the ProxySession to stop

    Returns:
        The updated ProxySession object
    """
    session = ProxySession.query.get(session_id)
    if not session:
        raise ProxyManagerError(f'Session {session_id} not found')

    if session.status in ('stopped', 'error'):
        logger.info(f'Session {session_id} already {session.status}')
        return session

    logger.info(f'Stopping session {session_id} (domain={session.domain})')

    # Kill processes in reverse order (websockify → vnc → chromium → xvfb)
    _kill_pid(session.websockify_pid, 'websockify')
    _kill_pid(session.vnc_pid, 'x11vnc')
    _kill_pid(session.chromium_pid, 'chromium')
    _kill_pid(session.xvfb_pid, 'Xvfb')

    session.status = 'stopped'
    session.stopped_at = datetime.utcnow()
    db.session.commit()

    logger.info(f'Session {session_id} stopped')
    return session


def cleanup_stale_sessions():
    """Find and stop sessions that are stale (timed out or have dead processes).

    Returns:
        Number of sessions cleaned up
    """
    cutoff = datetime.utcnow() - timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    cleaned = 0

    active_sessions = ProxySession.query.filter(
        ProxySession.status.in_(['starting', 'active'])
    ).all()

    for session in active_sessions:
        should_stop = False
        reason = ''

        # Check timeout
        if session.started_at and session.started_at < cutoff:
            should_stop = True
            reason = 'timeout'

        # Check if key processes are dead
        elif not _is_pid_alive(session.xvfb_pid) and not _is_pid_alive(session.chromium_pid):
            should_stop = True
            reason = 'dead processes'

        if should_stop:
            logger.info(f'Cleaning up stale session {session.id} (reason: {reason})')
            try:
                stop_session(session.id)
                cleaned += 1
            except Exception as e:
                logger.error(f'Error cleaning session {session.id}: {e}')

    if cleaned:
        logger.info(f'Cleaned up {cleaned} stale session(s)')
    return cleaned


def get_active_session(user_id, account_id, app_id):
    """Get the active proxy session for a user/app combination, if any.

    Returns:
        ProxySession or None
    """
    session = ProxySession.query.filter_by(
        user_id=user_id,
        account_id=account_id,
        app_id=app_id,
    ).filter(
        ProxySession.status.in_(['starting', 'active'])
    ).first()

    # Verify the session is actually still alive
    if session and not _is_pid_alive(session.xvfb_pid):
        logger.info(f'Session {session.id} has dead Xvfb, marking as stopped')
        session.status = 'stopped'
        session.stopped_at = datetime.utcnow()
        db.session.commit()
        return None

    return session


def get_user_active_sessions(user_id):
    """Get all active proxy sessions for a user.

    Returns:
        List of ProxySession objects
    """
    return ProxySession.query.filter_by(
        user_id=user_id,
    ).filter(
        ProxySession.status.in_(['starting', 'active'])
    ).order_by(ProxySession.started_at.desc()).all()