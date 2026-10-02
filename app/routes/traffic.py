"""Traffic reduction analysis — log pull lifecycle.

    GET  /traffic/                      — this user's pulls
    GET  /traffic/new?account_id=N      — app picker + window/mode form
    POST /traffic/preflight             — JSON: exact count + per-mode estimate
    POST /traffic/new                   — create and start a pull
    GET  /traffic/<id>/watch            — progress page (SocketIO room = session_id)
    GET  /traffic/<id>/status           — JSON progress, the durable source of truth
    POST /traffic/<id>/cancel           — cooperative cancel
    POST /traffic/<id>/resume           — restart an interrupted pull from its checkpoints
    GET  /traffic/<id>/results          — collection summary + cache analysis
    POST /traffic/<id>/analyze          — re-run the cache analysis over rows on disk
    POST /traffic/<id>/audit            — live header audit of the busiest assets

Only one pull runs at a time. The portal is a single gevent worker, so two
concurrent multi-hour pulls would contend for one event loop and make the
whole portal sluggish without finishing any sooner.
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
from app.background_tasks import run_header_audit, run_log_pull, run_log_pull_analysis
from app.logpull import corpus_bytes, preflight
from app.logpull.preflight import MAX_TOTAL_BYTES, format_duration
from app.logpull.source import LogSource
from app.logpull.store import PullStore
from app.logpull.windows import (
    DEFAULT_SAMPLE_SLOT,
    DEFAULT_SAMPLE_WINDOW,
    MODE_FULL,
    MODE_SAMPLE,
)
from app.models import AuditLog, LogPull, WaasAccount, get_user_accounts
from app.routes.applications import get_client_for_account
from app.socketio_events import pending_join
from app.waas_client import WaasApiError

bp = Blueprint('traffic', __name__, url_prefix='/traffic')

PULLS_PER_PAGE = 20

# 7 days is the default because the production findings this feature was
# built from were all visible within a few days; the 30-day window mattered
# for confidence, not detection.
WINDOW_CHOICES = [(7, _('7 days (recommended)')), (30, _('30 days'))]
ALLOWED_WINDOW_DAYS = {7, 30}

STATUS_BADGES = {
    LogPull.STATUS_PENDING: 'bg-secondary',
    LogPull.STATUS_RUNNING: 'bg-info',
    LogPull.STATUS_COMPLETE: 'bg-success',
    LogPull.STATUS_ERROR: 'bg-danger',
    LogPull.STATUS_CANCELLED: 'bg-warning text-dark',
    LogPull.STATUS_INTERRUPTED: 'bg-warning text-dark',
    LogPull.STATUS_ABORTED_DISK: 'bg-danger',
}


def _get_pull_or_404(pull_id):
    from flask import abort

    pull = LogPull.query.filter_by(id=pull_id, user_id=current_user.id).first()
    if pull is None:
        abort(404)
    return pull


def active_pull():
    """The one pull currently holding the slot, if any."""
    return LogPull.query.filter(
        LogPull.status.in_(LogPull.ACTIVE_STATUSES)
    ).order_by(LogPull.created_at.desc()).first()


def _range_for(window_days, now=None):
    """Half-open `[start, end)` covering the last `window_days` whole days.

    `end` is the current second rather than a day boundary so the window
    includes today's traffic; the drain's day planner clips the partial day
    at both ends.
    """
    end = int((now or datetime.now(timezone.utc)).timestamp())
    return end - window_days * 86400, end


@bp.route('/')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    pulls = (
        LogPull.query.filter_by(user_id=current_user.id)
        .order_by(LogPull.created_at.desc())
        .paginate(page=page, per_page=PULLS_PER_PAGE, error_out=False)
    )
    return render_template(
        'traffic/index.html',
        pulls=pulls,
        status_badges=STATUS_BADGES,
        active=active_pull(),
        corpus_bytes=corpus_bytes(current_app.instance_path),
        corpus_max_bytes=MAX_TOTAL_BYTES,
    )


@bp.route('/new')
@login_required
def new_pull():
    account_id = request.args.get('account_id', type=int)
    accounts = get_user_accounts(current_user)

    account = None
    applications = []
    error = None
    if account_id:
        client, account, _perm = get_client_for_account(account_id)
        if not client:
            flash(_('Account not found or access denied.'), 'danger')
            return redirect(url_for('traffic.new_pull'))
        try:
            result = client.list_applications()
            if isinstance(result, dict):
                result = result.get('results') or result.get('data') or []
            applications = result if isinstance(result, list) else []
        except WaasApiError as e:
            error = str(e)

    return render_template(
        'traffic/new.html',
        accounts=accounts,
        account=account,
        applications=applications,
        window_choices=WINDOW_CHOICES,
        active=active_pull(),
        error=error,
    )


@bp.route('/preflight', methods=['POST'])
@login_required
def preflight_estimate():
    """Exact row count plus a per-mode projection, before anything is started.

    This is what turns sample-vs-full from a blind checkbox into an informed
    choice: one count query costs a fraction of a second and tells the user
    whether "full" means four minutes or a day and a half.
    """
    account_id = request.json.get('account_id') if request.is_json else None
    app_id = request.json.get('app_id') if request.is_json else None
    window_days = (request.json.get('window_days') if request.is_json else None) or 7

    try:
        window_days = int(window_days)
    except (TypeError, ValueError):
        window_days = 7
    if window_days not in ALLOWED_WINDOW_DAYS:
        window_days = 7

    if not account_id or not app_id:
        return jsonify({'error': 'account_id and app_id are required'}), 400

    client, account, _perm = get_client_for_account(account_id)
    if not client:
        return jsonify({'error': 'Account not found or access denied'}), 403

    start, end = _range_for(window_days)
    source = LogSource(client, app_id)

    try:
        report = preflight(
            source, start, end, current_app.instance_path,
            corpus_bytes=corpus_bytes(current_app.instance_path),
        )
    except WaasApiError as e:
        return jsonify({'error': str(e)}), 502

    for mode, option in report['options'].items():
        option['duration_label'] = format_duration(option['seconds'])
    report['window_days'] = window_days
    report['busy'] = active_pull() is not None
    return jsonify(report)


@bp.route('/new', methods=['POST'])
@login_required
def create_pull():
    account_id = request.form.get('account_id', type=int)
    app_id = (request.form.get('app_id') or '').strip()
    app_name = (request.form.get('app_name') or app_id).strip()
    mode = request.form.get('mode') or MODE_SAMPLE
    window_days = request.form.get('window_days', type=int) or 7
    confirmed = request.form.get('confirm_full') == 'yes'

    if mode not in (MODE_SAMPLE, MODE_FULL):
        mode = MODE_SAMPLE
    if window_days not in ALLOWED_WINDOW_DAYS:
        window_days = 7

    if not account_id or not app_id:
        flash(_('Select an account and an application.'), 'danger')
        return redirect(url_for('traffic.new_pull'))

    existing = active_pull()
    if existing is not None:
        flash(_('A log pull is already running (#%(id)s). Only one runs at a '
                'time — wait for it to finish or cancel it.', id=existing.id), 'warning')
        return redirect(url_for('traffic.watch_pull', pull_id=existing.id))

    client, account, _perm = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or access denied.'), 'danger')
        return redirect(url_for('traffic.new_pull'))

    start, end = _range_for(window_days)
    source = LogSource(client, app_id)

    try:
        report = preflight(
            source, start, end, current_app.instance_path,
            corpus_bytes=corpus_bytes(current_app.instance_path),
        )
    except WaasApiError as e:
        flash(_('Could not size the pull: %(err)s', err=str(e)), 'danger')
        return redirect(url_for('traffic.new_pull', account_id=account_id))

    if report['corpus_full']:
        flash(_('Stored log pulls exceed the configured cap. Free space on the '
                'admin storage page before starting another.'), 'danger')
        return redirect(url_for('traffic.index'))

    option = report['options'][mode]
    if option['disk']['blocked']:
        flash(_('Not enough free disk space for this pull (needs about '
                '%(need)s GB, %(free)s GB free). Try a sampled pull or a '
                'shorter window.',
                need=round(option['bytes'] / 1e9, 1),
                free=round(option['disk']['free_bytes'] / 1e9, 1)), 'danger')
        return redirect(url_for('traffic.new_pull', account_id=account_id))

    if mode == MODE_FULL and report['full_requires_confirmation'] and not confirmed:
        flash(_('A full pull of this application is estimated at %(dur)s. '
                'Confirm on the form to proceed.',
                dur=format_duration(option['seconds'])), 'warning')
        return redirect(url_for('traffic.new_pull', account_id=account_id))

    session_id = str(uuid.uuid4())
    pull = LogPull(
        user_id=current_user.id,
        account_id=account.id,
        app_id=app_id,
        app_name=app_name,
        mode=mode,
        window_days=window_days,
        range_start=start,
        range_end=end,
        sample_window_seconds=DEFAULT_SAMPLE_WINDOW,
        sample_slot_seconds=DEFAULT_SAMPLE_SLOT,
        session_id=session_id,
        rows_expected=option['rows'],
        status=LogPull.STATUS_PENDING,
        phase=LogPull.PHASE_QUEUED,
    )
    db.session.add(pull)
    db.session.commit()

    AuditLog.log(
        user_id=current_user.id,
        action='logpull_start',
        details=f'{mode} pull of {app_name} over {window_days}d '
                f'(~{option["rows"]:,} rows, est. {format_duration(option["seconds"])})',
    )

    # Pre-create the join-signal Event synchronously, before spawning the
    # greenlet — otherwise the browser's `join` can arrive first and be
    # dropped. Same race the profiler documents at routes/profiler.py:195.
    pending_join(session_id)
    real_app = current_app._get_current_object()
    socketio.start_background_task(run_log_pull, real_app, pull.id, session_id)

    return redirect(url_for('traffic.watch_pull', pull_id=pull.id))


@bp.route('/<int:pull_id>/watch')
@login_required
def watch_pull(pull_id):
    pull = _get_pull_or_404(pull_id)
    if pull.status == LogPull.STATUS_COMPLETE:
        return redirect(url_for('traffic.pull_results', pull_id=pull.id))
    return render_template(
        'traffic/watch.html',
        pull=pull,
        session_id=pull.session_id,
        status_badges=STATUS_BADGES,
    )


@bp.route('/<int:pull_id>/status')
@login_required
def pull_status(pull_id):
    """Durable progress, read straight off the row.

    For a job this long the DB is the source of truth and SocketIO is the
    optimization — the inverse of the profiler's weighting. This endpoint is
    the primary source on page load and after any reconnect, not just a
    fallback for dropped events.
    """
    pull = _get_pull_or_404(pull_id)
    payload = pull.to_dict()
    payload['eta_label'] = format_duration(pull.eta_seconds) if pull.eta_seconds else None
    payload['results_url'] = url_for('traffic.pull_results', pull_id=pull.id)
    return jsonify(payload)


@bp.route('/<int:pull_id>/cancel', methods=['POST'])
@login_required
def cancel_pull(pull_id):
    """Request cancellation. Cooperative — the runner checks at window
    boundaries, so this returns immediately but the pull stops shortly
    after, keeping whatever it has already collected."""
    pull = _get_pull_or_404(pull_id)
    if not pull.is_active:
        flash(_('That pull is not running.'), 'info')
        return redirect(url_for('traffic.index'))

    pull.cancel_requested = True
    db.session.commit()
    AuditLog.log(user_id=current_user.id, action='logpull_cancel',
                 details=f'Cancelled log pull #{pull.id} ({pull.app_name})')
    flash(_('Cancellation requested. Collected data will be kept.'), 'info')
    return redirect(url_for('traffic.watch_pull', pull_id=pull.id))


@bp.route('/<int:pull_id>/resume', methods=['POST'])
@login_required
def resume_pull(pull_id):
    """Restart an interrupted or cancelled pull.

    Days already checkpointed on disk are skipped, so this continues rather
    than starting over.
    """
    pull = _get_pull_or_404(pull_id)
    if pull.status not in (LogPull.STATUS_INTERRUPTED, LogPull.STATUS_CANCELLED,
                           LogPull.STATUS_ERROR, LogPull.STATUS_ABORTED_DISK):
        flash(_('That pull cannot be resumed.'), 'warning')
        return redirect(url_for('traffic.index'))

    existing = active_pull()
    if existing is not None:
        flash(_('Another pull is running (#%(id)s).', id=existing.id), 'warning')
        return redirect(url_for('traffic.watch_pull', pull_id=existing.id))

    if pull.raw_deleted:
        flash(_('The raw data for that pull has expired. Start a new pull.'), 'warning')
        return redirect(url_for('traffic.index'))

    session_id = str(uuid.uuid4())
    pull.session_id = session_id
    pull.status = LogPull.STATUS_PENDING
    pull.phase = LogPull.PHASE_QUEUED
    pull.cancel_requested = False
    pull.error_message = None
    pull.completed_at = None
    db.session.commit()

    AuditLog.log(user_id=current_user.id, action='logpull_resume',
                 details=f'Resumed log pull #{pull.id} ({pull.app_name})')

    pending_join(session_id)
    real_app = current_app._get_current_object()
    socketio.start_background_task(run_log_pull, real_app, pull.id, session_id)
    return redirect(url_for('traffic.watch_pull', pull_id=pull.id))


@bp.route('/<int:pull_id>/results')
@login_required
def pull_results(pull_id):
    pull = _get_pull_or_404(pull_id)
    store = PullStore(current_app.instance_path, pull.id)
    summary = pull.result or {}
    analysis = summary.get('analysis') or {}
    report = pull.report or {}
    return render_template(
        'traffic/results.html',
        pull=pull,
        summary=summary,
        analysis=analysis,
        header_audit=report.get('header_audit') or {},
        status_badges=STATUS_BADGES,
        on_disk=store.size_bytes(),
        can_analyze=not pull.raw_deleted and not pull.is_active
        and pull.phase != LogPull.PHASE_ANALYZING,
    )


@bp.route('/<int:pull_id>/analyze', methods=['POST'])
@login_required
def analyze_pull_route(pull_id):
    """Re-run the cache analysis over rows already on disk.

    Collection is the expensive half and the analysis keeps gaining metrics,
    so a pull from last week should be able to pick up this week's findings
    without re-fetching anything.
    """
    pull = _get_pull_or_404(pull_id)
    if pull.is_active or pull.phase == LogPull.PHASE_ANALYZING:
        flash(_('That pull is still working. Wait for it to finish.'), 'info')
        return redirect(url_for('traffic.pull_results', pull_id=pull.id))
    if pull.raw_deleted:
        flash(_('The raw rows for that pull have expired, so there is nothing '
                'left to re-analyze. Start a new pull.'), 'warning')
        return redirect(url_for('traffic.pull_results', pull_id=pull.id))

    pull.phase = LogPull.PHASE_ANALYZING
    db.session.commit()

    AuditLog.log(user_id=current_user.id, action='logpull_analyze',
                 details=f'Re-ran analysis for log pull #{pull.id} ({pull.app_name})')

    real_app = current_app._get_current_object()
    socketio.start_background_task(run_log_pull_analysis, real_app, pull.id)
    flash(_('Analysis started. Reload this page in a moment.'), 'info')
    return redirect(url_for('traffic.pull_results', pull_id=pull.id))


@bp.route('/<int:pull_id>/audit', methods=['POST'])
@login_required
def header_audit_route(pull_id):
    """Probe the busiest static assets live.

    This is a separate, explicit action because it sends real requests to the
    customer's origin. Collecting logs is passive; this is not, so it is not
    something the portal should do as a side effect.
    """
    pull = _get_pull_or_404(pull_id)
    analysis = (pull.result or {}).get('analysis') or {}
    targets = analysis.get('audit_targets') or []
    if not targets:
        flash(_('No assets to probe. Run the analysis first — the audit uses the '
                'busiest static assets it finds.'), 'warning')
        return redirect(url_for('traffic.pull_results', pull_id=pull.id))

    AuditLog.log(
        user_id=current_user.id, action='logpull_header_audit',
        details=f'Header audit of {len(targets)} asset(s) for log pull '
                f'#{pull.id} ({pull.app_name})',
    )

    real_app = current_app._get_current_object()
    socketio.start_background_task(run_header_audit, real_app, pull.id)
    flash(_('Probing %(n)s assets. This takes a minute or two — reload to see '
            'the results.', n=len(targets)), 'info')
    return redirect(url_for('traffic.pull_results', pull_id=pull.id))
