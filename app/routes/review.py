"""Account/Config Review report (Phase 6) -- per-application synthesis of
FP/FN scoring, config-vs-traffic recommendations, config history, trend, and
baseline-template comparison, tying phases 1-4 into a single artifact."""
import logging

from flask import Blueprint, render_template, request, flash, redirect, url_for, session, g
from flask_login import login_required, current_user
from flask_babel import gettext as _

from app.models import ConfigSnapshot, ConfigTemplate, SecurityMetricSnapshot, TemplateApplication, get_user_accounts
from app.waas_client import WaasApiError
from app.fp_scoring import group_waf_logs
from app.config_advisor import compute_traffic_stats
from app.review_service import build_review
from app.routes.applications import get_client_for_account, _site_profile_signal
from app.routes.logs import QUICK_RANGES

bp = Blueprint('review', __name__, url_prefix='/review')

logger = logging.getLogger(__name__)

SNAPSHOT_HISTORY_LIMIT = 10
DEFAULT_QUICK_RANGE = 'r_7d'


@bp.route('/')
@login_required
def index():
    """Launcher page: account -> application picker, mirroring logs.index."""
    accounts = get_user_accounts(current_user)

    account_id = request.args.get('account_id', type=int)
    if account_id:
        session['current_account_id'] = account_id
    elif g.current_account:
        account_id = g.current_account.id

    selected_account = None
    applications = []

    if account_id:
        client, selected_account, perm = get_client_for_account(account_id)
        if client:
            try:
                result = client.list_applications_v2()
                applications = result.get('results', [])
            except WaasApiError as e:
                flash(_('Failed to load applications: %(error)s', error=str(e)), 'danger')

    return render_template(
        'review/index.html',
        accounts=accounts,
        selected_account=selected_account,
        applications=applications,
    )


def _snapshot_to_dict(snap):
    return {
        'id': snap.id,
        'resource_type': snap.resource_type,
        'resource_label': snap.resource_label,
        'created_at': snap.created_at,
        'is_reverted': snap.is_reverted,
    }


def _resolve_baseline(account_id, app_id, template_id):
    """Pick the baseline template: an explicit ?template_id, else the most
    recently applied template for this app, else None."""
    template = None
    if template_id:
        template = ConfigTemplate.query.get(template_id)
    if not template:
        last_application = (
            TemplateApplication.query
            .filter_by(account_id=account_id, app_name=app_id)
            .order_by(TemplateApplication.applied_at.desc())
            .first()
        )
        if last_application:
            template = ConfigTemplate.query.get(last_application.template_id)
    return template


@bp.route('/<int:account_id>/<app_id>')
@login_required
def report(account_id, app_id):
    """Full review report for one application."""
    client, account, perm = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or inactive.'), 'danger')
        return redirect(url_for('review.index'))

    valid_ranges = {val for val, _label in QUICK_RANGES}
    quick_range = request.args.get('quick_range', DEFAULT_QUICK_RANGE)
    if quick_range not in valid_ranges:
        quick_range = DEFAULT_QUICK_RANGE

    application = {}
    security_config = {}
    fp_groups = []
    traffic_stats = {}
    site_profile_signal = None
    error = None

    try:
        application = client.get_application(app_id)
        security_config = client.get_security_config(app_id)

        waf_result = client.get_logs(
            app_id, quick_range=quick_range, items_per_page=1000,
            filter_fields={'LogType': [{'condition': 'is', 'value': 'WF'}]},
        )
        fp_groups = group_waf_logs(waf_result.get('results', []))

        access_result = client.get_logs(
            app_id, quick_range=quick_range, items_per_page=1000,
            filter_fields={'LogType': [{'condition': 'is', 'value': 'TR'}]},
        )
        traffic_stats = compute_traffic_stats(access_result.get('results', []))

        site_profile_signal = _site_profile_signal(account, application)
    except WaasApiError as e:
        error = str(e)
        logger.warning('Review report data fetch failed for account=%s app=%s: %s', account_id, app_id, e)

    snapshots = (
        ConfigSnapshot.query
        .filter_by(account_id=account_id, app_id=app_id)
        .order_by(ConfigSnapshot.created_at.desc())
        .limit(SNAPSHOT_HISTORY_LIMIT)
        .all()
    )

    metric_rows = (
        SecurityMetricSnapshot.query
        .filter_by(account_id=account_id, app_id=app_id)
        .order_by(SecurityMetricSnapshot.captured_at.asc())
        .all()
    )

    template = _resolve_baseline(account_id, app_id, request.args.get('template_id', type=int))
    baseline = {'name': template.name, 'config': template.config_dict} if template else None

    review = build_review(
        security_config,
        fp_groups=fp_groups,
        traffic_stats=traffic_stats,
        site_profile_signal=site_profile_signal,
        snapshots=[_snapshot_to_dict(s) for s in snapshots],
        metric_snapshots=[m.to_dict() for m in metric_rows],
        baseline=baseline,
    )

    templates = ConfigTemplate.query.filter(
        (ConfigTemplate.user_id == current_user.id) | (ConfigTemplate.is_global == True)  # noqa: E712
    ).order_by(ConfigTemplate.name).all()

    return render_template(
        'review/report.html',
        account=account,
        app_id=app_id,
        application=application,
        review=review,
        selected_template=template,
        templates=templates,
        quick_range=quick_range,
        quick_ranges=QUICK_RANGES,
        error=error,
    )
