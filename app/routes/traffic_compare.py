"""Before/after traffic comparisons — arm, watch, read.

    GET  /traffic/compare/              — this user's comparisons
    GET  /traffic/compare/new           — wizard
    POST /traffic/compare/preflight     — JSON: per-window counts and cost
    POST /traffic/compare/new           — arm one
    GET  /traffic/compare/<id>/watch    — progress
    GET  /traffic/compare/<id>/status   — JSON, the durable source of truth
    POST /traffic/compare/<id>/cancel   — cooperative cancel
    POST /traffic/compare/<id>/pin      — exempt from the retention sweep
    GET  /traffic/compare/<id>/results  — the report

Arming collects the windows that have already settled and defers the one that
has not. The deferred window is picked up by `run_due_comparisons` rather than
by a greenlet parked for hours — see `app/traffic_comparison.py` for why the
`after` child row must not exist before then.
"""
import uuid
from datetime import datetime, timezone

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_babel import gettext as _
from flask_login import current_user, login_required

from app import db, socketio
from app.background_tasks import run_traffic_comparison
from app.logpull.compare import DEFAULT_INGEST_LAG, plan_labels
from app.logpull.preflight import format_duration
from app.logpull.source import LogSource
from app.models import AuditLog, LogPull, TrafficComparison, get_user_accounts
from app.routes.applications import get_client_for_account
from app.socketio_events import pending_join
from app.traffic_comparison import (
    DEFAULT_CONTROL_DAYS,
    DEFAULT_DURATION,
    DEFAULT_GUARD,
    DURATION_CHOICES,
    MAX_CONTROL_DAYS,
    arm,
    limits,
    plan_for,
    preflight,
    verdict,
)
from app.waas_client import WaasApiError

bp = Blueprint('traffic_compare', __name__, url_prefix='/traffic/compare')

PER_PAGE = 20

STATUS_BADGES = {
    TrafficComparison.STATUS_PENDING: 'bg-secondary',
    TrafficComparison.STATUS_COLLECTING: 'bg-info',
    TrafficComparison.STATUS_WAITING: 'bg-primary',
    TrafficComparison.STATUS_ANALYZING: 'bg-info',
    TrafficComparison.STATUS_COMPLETE: 'bg-success',
    TrafficComparison.STATUS_ERROR: 'bg-danger',
    TrafficComparison.STATUS_CANCELLED: 'bg-warning text-dark',
    TrafficComparison.STATUS_INTERRUPTED: 'bg-warning text-dark',
}

DURATION_LABELS = {
    3600: _('1 hour'),
    7200: _('2 hours (recommended)'),
    21600: _('6 hours'),
    86400: _('24 hours — a full daily cycle'),
}


def _get_or_404(comparison_id):
    from flask import abort

    comparison = TrafficComparison.query.filter_by(
        id=comparison_id, user_id=current_user.id).first()
    if comparison is None:
        abort(404)
    return comparison


def _busy():
    """The pull or comparison currently holding the single collection slot."""
    pull = LogPull.query.filter(
        LogPull.status.in_(LogPull.ACTIVE_STATUSES)).first()
    if pull is not None:
        return pull
    return TrafficComparison.query.filter(
        TrafficComparison.status.in_(TrafficComparison.BUSY_STATUSES)).first()


def _parse_change_at(value):
    """Epoch seconds from the form's `datetime-local`, read as UTC."""
    raw = (value or '').strip().replace('Z', '+00:00')
    if not raw:
        raise ValueError(_('Enter when the change was made.'))
    try:
        moment = datetime.fromisoformat(raw)
    except ValueError:
        raise ValueError(_('That is not a valid date and time.')) from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp())


def _clean_plan_inputs(source):
    """`(change_at, duration, guard, control_days)` from form or JSON."""
    change_at = _parse_change_at(source.get('change_at'))

    try:
        duration = int(source.get('duration') or DEFAULT_DURATION)
    except (TypeError, ValueError):
        duration = DEFAULT_DURATION
    if duration not in DURATION_CHOICES:
        duration = DEFAULT_DURATION

    try:
        guard = int(source.get('guard') or DEFAULT_GUARD)
    except (TypeError, ValueError):
        guard = DEFAULT_GUARD
    guard = max(0, min(guard, 3600))

    try:
        control_days = int(source.get('control_days') or DEFAULT_CONTROL_DAYS)
    except (TypeError, ValueError):
        control_days = DEFAULT_CONTROL_DAYS
    control_days = max(0, min(control_days, MAX_CONTROL_DAYS))

    return change_at, duration, guard, control_days


def _segments(raw):
    """Segment names from a comma-separated field; empty means auto-pick."""
    if not raw:
        return []
    return [part.strip() for part in str(raw).split(',') if part.strip()]


# --- list ------------------------------------------------------------------


@bp.route('/')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    comparisons = (
        TrafficComparison.query.filter_by(user_id=current_user.id)
        .order_by(TrafficComparison.created_at.desc())
        .paginate(page=page, per_page=PER_PAGE, error_out=False)
    )
    return render_template(
        'traffic/compare_index.html',
        comparisons=comparisons,
        status_badges=STATUS_BADGES,
        busy=_busy(),
    )


# --- wizard ----------------------------------------------------------------


@bp.route('/new')
@login_required
def new():
    account_id = request.args.get('account_id', type=int)
    accounts = get_user_accounts(current_user)

    account = None
    applications = []
    error = None
    if account_id:
        client, account, _perm = get_client_for_account(account_id)
        if not client:
            flash(_('Account not found or access denied.'), 'danger')
            return redirect(url_for('traffic_compare.new'))
        try:
            result = client.list_applications()
            if isinstance(result, dict):
                result = result.get('results') or result.get('data') or []
            applications = result if isinstance(result, list) else []
        except WaasApiError as e:
            error = str(e)

    return render_template(
        'traffic/compare_new.html',
        accounts=accounts,
        account=account,
        applications=applications,
        app_id=request.args.get('app_id') or '',
        change_at=request.args.get('change_at') or '',
        change_note=request.args.get('note') or '',
        duration_choices=[(seconds, DURATION_LABELS[seconds])
                          for seconds in DURATION_CHOICES],
        default_duration=DEFAULT_DURATION,
        default_guard=DEFAULT_GUARD,
        default_control_days=DEFAULT_CONTROL_DAYS,
        max_control_days=MAX_CONTROL_DAYS,
        ingest_lag_seconds=DEFAULT_INGEST_LAG,
        busy=_busy(),
        error=error,
    )


@bp.route('/preflight', methods=['POST'])
@login_required
def preflight_estimate():
    """One count query per planned window, before anything is committed.

    This is what stops a comparison running blind. The production run that
    motivated the feature hit a control day carrying four times the traffic of
    its neighbours; with this, that shows up as a number on the form instead
    of as an unexplained twenty-minute wait.
    """
    payload = request.json if request.is_json else {}
    account_id = payload.get('account_id')
    app_id = payload.get('app_id')
    if not account_id or not app_id:
        return jsonify({'error': 'account_id and app_id are required'}), 400

    try:
        change_at, duration, guard, control_days = _clean_plan_inputs(payload)
    except ValueError as e:
        return jsonify({'error': str(e)})

    client, _account, _perm = get_client_for_account(account_id)
    if not client:
        return jsonify({'error': 'Account not found or access denied'}), 403

    from app.logpull.compare import plan_comparison
    plan = plan_comparison(change_at, duration, guard=guard,
                           control_days=control_days, allow_future=True)

    try:
        report = preflight(LogSource(client, app_id), plan,
                           current_app.instance_path)
    except WaasApiError as e:
        return jsonify({'error': str(e)}), 502

    report['now_label'] = format_duration(report['now_seconds'])
    report['later_label'] = format_duration(report['later_seconds'])
    report['total_label'] = format_duration(report['option']['seconds'])
    report['busy'] = _busy() is not None
    for window in report['windows']:
        window['label_text'] = window['label']
        window['when'] = datetime.fromtimestamp(
            window['start'], tz=timezone.utc).strftime('%m-%d %H:%M')
    return jsonify(report)


@bp.route('/new', methods=['POST'])
@login_required
def create():
    account_id = request.form.get('account_id', type=int)
    app_id = (request.form.get('app_id') or '').strip()
    app_name = (request.form.get('app_name') or app_id).strip()

    if not account_id or not app_id:
        flash(_('Select an account and an application.'), 'danger')
        return redirect(url_for('traffic_compare.new'))

    try:
        change_at, duration, guard, control_days = _clean_plan_inputs(request.form)
    except ValueError as e:
        flash(str(e), 'danger')
        return redirect(url_for('traffic_compare.new', account_id=account_id))

    existing = _busy()
    if existing is not None:
        flash(_('A collection is already running. Only one runs at a time — '
                'wait for it to finish or cancel it.'), 'warning')
        return redirect(url_for('traffic_compare.index'))

    client, account, _perm = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or access denied.'), 'danger')
        return redirect(url_for('traffic_compare.new'))

    from app.logpull.compare import plan_comparison
    plan = plan_comparison(change_at, duration, guard=guard,
                           control_days=control_days, allow_future=True)

    try:
        report = preflight(LogSource(client, app_id), plan,
                           current_app.instance_path)
    except WaasApiError as e:
        flash(_('Could not size the comparison: %(err)s', err=str(e)), 'danger')
        return redirect(url_for('traffic_compare.new', account_id=account_id))

    if report['option']['disk']['blocked']:
        flash(_('Not enough free disk space for this comparison (needs about '
                '%(need)s GB). Try shorter windows or fewer control days.',
                need=round(report['option']['bytes'] / 1e9, 1)), 'danger')
        return redirect(url_for('traffic_compare.new', account_id=account_id))

    comparison = arm(
        current_user.id, account,
        app_id=app_id, app_name=app_name,
        change_at=change_at, duration=duration, guard=guard,
        control_days=control_days,
        focus_url=(request.form.get('focus_url') or '').strip() or None,
        segments=_segments(request.form.get('segments')),
        change_note=(request.form.get('change_note') or '').strip() or None,
        pinned=request.form.get('pinned') == 'yes',
        counts=report['windows'],
    )

    AuditLog.log(
        user_id=current_user.id,
        action='traffic_comparison_start',
        details=(f'before/after of {app_name} around '
                 f'{datetime.fromtimestamp(change_at, tz=timezone.utc)
                    .strftime("%Y-%m-%d %H:%M")} UTC, '
                 f'{format_duration(duration)} windows, '
                 f'{control_days} control day(s), '
                 f'~{report["total_rows"]:,} rows'),
    )

    pending_join(comparison.session_id)
    socketio.start_background_task(
        run_traffic_comparison, current_app._get_current_object(),
        comparison.id, comparison.session_id)

    return redirect(url_for('traffic_compare.watch', comparison_id=comparison.id))


# --- progress --------------------------------------------------------------


@bp.route('/<int:comparison_id>/watch')
@login_required
def watch(comparison_id):
    comparison = _get_or_404(comparison_id)
    if comparison.status == TrafficComparison.STATUS_COMPLETE:
        return redirect(url_for('traffic_compare.results',
                                comparison_id=comparison.id))
    return render_template(
        'traffic/compare_watch.html',
        comparison=comparison,
        session_id=comparison.session_id,
        status_badges=STATUS_BADGES,
    )


@bp.route('/<int:comparison_id>/status')
@login_required
def status(comparison_id):
    """Durable progress, read straight off the rows.

    Primary source on page load and after any reconnect, not a fallback: a
    comparison outlives the tab it was started from, and during the wait for
    the `after` window it outlives the SocketIO connection entirely.
    """
    comparison = _get_or_404(comparison_id)
    payload = comparison.to_dict()
    payload['eta_label'] = (format_duration(comparison.eta_seconds)
                            if comparison.eta_seconds else None)
    payload['waiting_label'] = (format_duration(comparison.waiting_seconds)
                                if comparison.waiting_seconds else None)
    payload['results_url'] = url_for('traffic_compare.results',
                                     comparison_id=comparison.id)
    return jsonify(payload)


@bp.route('/<int:comparison_id>/cancel', methods=['POST'])
@login_required
def cancel(comparison_id):
    """Cooperative cancel. Collected windows are kept."""
    comparison = _get_or_404(comparison_id)
    if comparison.status in TrafficComparison.TERMINAL_STATUSES:
        flash(_('That comparison has already finished.'), 'info')
        return redirect(url_for('traffic_compare.index'))

    comparison.cancel_requested = True
    for pull in comparison.windows:
        if pull.is_active:
            pull.cancel_requested = True
    if comparison.status == TrafficComparison.STATUS_WAITING:
        # Nothing is running to notice the flag, so settle it here.
        comparison.status = TrafficComparison.STATUS_CANCELLED
        comparison.completed_at = datetime.utcnow()
    db.session.commit()

    flash(_('Cancelling. Windows already collected are kept.'), 'info')
    return redirect(url_for('traffic_compare.index'))


@bp.route('/<int:comparison_id>/pin', methods=['POST'])
@login_required
def pin(comparison_id):
    """Exempt this comparison's rows from the retention sweep, or release it."""
    comparison = _get_or_404(comparison_id)
    comparison.pinned = request.form.get('pinned') == 'yes'
    for pull in comparison.windows:
        pull.pinned = comparison.pinned
        if comparison.pinned:
            pull.raw_expires_at = None
    db.session.commit()

    flash(_('Pinned — these rows will not be swept.') if comparison.pinned
          else _('Unpinned — these rows return to the normal retention window.'),
          'success')
    return redirect(url_for('traffic_compare.results',
                            comparison_id=comparison.id))


# --- results ---------------------------------------------------------------


@bp.route('/<int:comparison_id>/results')
@login_required
def results(comparison_id):
    comparison = _get_or_404(comparison_id)
    if comparison.status != TrafficComparison.STATUS_COMPLETE:
        return redirect(url_for('traffic_compare.watch',
                                comparison_id=comparison.id))

    plan = plan_for(comparison)
    result = comparison.result or {}
    return render_template(
        'traffic/compare_results.html',
        comparison=comparison,
        result=result,
        # Passed rather than {% set %} in the template: a block-local name is
        # not visible from the extra_js block, where the chart is built.
        tl=result.get('timeline') or {},
        verdict=verdict(result),
        limits=limits(comparison, result),
        plan_windows=plan_labels(plan),
        status_badges=STATUS_BADGES,
    )
