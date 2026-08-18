"""Config History: browse ConfigSnapshot rows, view before/after diffs, and revert.

Foundational safety net for config-mutating write paths (template apply,
raw-config apply, bulk apply, bulk security, and inline security/server/
endpoint edits) — see app/config_history.py for the revert dispatch logic.
"""
import logging
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from flask_babel import gettext as _
from app.models import ConfigSnapshot, get_user_accounts, get_account_for_user, can_write
from app.waas_client import WaasClient, WaasApiError
from app.config_history import revert_snapshot

logger = logging.getLogger(__name__)

bp = Blueprint('config_history', __name__, url_prefix='/config-history')

SNAPSHOTS_PER_PAGE = 25

RESOURCE_TYPE_LABELS = {
    'template_apply': 'Template Apply',
    'template_bulk_apply': 'Bulk Template Apply',
    'raw_config_apply': 'Raw Config Apply',
    'raw_config_bulk_apply': 'Bulk Raw Config Apply',
    'security_config_update': 'Security Config Update',
    'bulk_security_update': 'Bulk Security Update',
    'server_update': 'Server Update',
    'endpoint_update': 'Endpoint Update',
}

RESOURCE_TYPE_BADGES = {
    'template_apply': 'bg-primary',
    'template_bulk_apply': 'bg-primary',
    'raw_config_apply': 'bg-info',
    'raw_config_bulk_apply': 'bg-info',
    'security_config_update': 'bg-warning text-dark',
    'bulk_security_update': 'bg-warning text-dark',
    'server_update': 'bg-secondary',
    'endpoint_update': 'bg-secondary',
}


@bp.route('/')
@login_required
def list_snapshots():
    """Paginated, filterable list of config snapshots across the user's accounts."""
    account_id = request.args.get('account_id', type=int)
    app_id = request.args.get('app_id', type=str)
    resource_type = request.args.get('resource_type', type=str)

    accounts = get_user_accounts(current_user)
    account_ids = [a.id for a in accounts]

    query = ConfigSnapshot.query.filter(ConfigSnapshot.account_id.in_(account_ids)) if account_ids \
        else ConfigSnapshot.query.filter(ConfigSnapshot.id == None)  # noqa: E711 — no accounts, empty result

    selected_account = None
    if account_id:
        selected_account = next((a for a in accounts if a.id == account_id), None)
        if selected_account is None:
            abort(404)
        query = query.filter_by(account_id=account_id)

    if app_id:
        query = query.filter_by(app_id=app_id)

    if resource_type:
        query = query.filter_by(resource_type=resource_type)

    page = request.args.get('page', 1, type=int)
    snapshots = query.order_by(ConfigSnapshot.created_at.desc()) \
        .paginate(page=page, per_page=SNAPSHOTS_PER_PAGE, error_out=False)

    return render_template(
        'config_history/list.html',
        snapshots=snapshots,
        accounts=accounts,
        selected_account=selected_account,
        app_id=app_id,
        resource_type=resource_type,
        resource_type_labels=RESOURCE_TYPE_LABELS,
        resource_type_badges=RESOURCE_TYPE_BADGES,
    )


@bp.route('/<int:snapshot_id>')
@login_required
def view_snapshot(snapshot_id):
    """Detail view: before/applied diff, revert lineage, revert action."""
    snapshot = ConfigSnapshot.query.get_or_404(snapshot_id)
    account, perm = get_account_for_user(snapshot.account_id, current_user)
    if not account:
        abort(404)

    return render_template(
        'config_history/detail.html',
        snapshot=snapshot,
        account=account,
        can_revert=can_write(perm),
        resource_type_labels=RESOURCE_TYPE_LABELS,
        resource_type_badges=RESOURCE_TYPE_BADGES,
    )


@bp.route('/<int:snapshot_id>/revert', methods=['POST'])
@login_required
def revert(snapshot_id):
    """Revert a single snapshot back to its captured before-state."""
    snapshot = ConfigSnapshot.query.get_or_404(snapshot_id)

    if current_user.role == 'viewer':
        flash(_('You do not have permission to revert configurations.'), 'danger')
        return redirect(url_for('config_history.view_snapshot', snapshot_id=snapshot_id))

    account, perm = get_account_for_user(snapshot.account_id, current_user, min_permission='write')
    if not account or not can_write(perm):
        flash(_('Account not found or insufficient permissions.'), 'danger')
        return redirect(url_for('config_history.view_snapshot', snapshot_id=snapshot_id))

    client = WaasClient.from_account(account)
    try:
        revert_snapshot(snapshot, client, current_user.id)
        flash(_('Reverted "%(app_id)s" to its prior state.', app_id=snapshot.app_id), 'success')
    except ValueError as e:
        flash(str(e), 'warning')
    except WaasApiError as e:
        flash(_('Failed to revert: %(error)s', error=str(e)), 'danger')

    return redirect(url_for('config_history.view_snapshot', snapshot_id=snapshot_id))


@bp.route('/batch/<batch_id>/revert', methods=['POST'])
@login_required
def revert_batch(batch_id):
    """Revert every not-yet-reverted snapshot in a bulk-operation batch."""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to revert configurations.'), 'danger')
        return redirect(url_for('config_history.list_snapshots'))

    snapshots = ConfigSnapshot.query.filter_by(batch_id=batch_id, reverted_at=None).all()
    if not snapshots:
        flash(_('No revertible snapshots found for this batch.'), 'warning')
        return redirect(url_for('config_history.list_snapshots'))

    results = []
    client_cache = {}
    for snapshot in snapshots:
        account, perm = get_account_for_user(snapshot.account_id, current_user, min_permission='write')
        if not account or not can_write(perm):
            results.append({'app_id': snapshot.app_id, 'success': False, 'error': 'Insufficient permissions'})
            continue
        try:
            client = client_cache.get(account.id)
            if not client:
                client = WaasClient.from_account(account)
                client_cache[account.id] = client
            revert_snapshot(snapshot, client, current_user.id)
            results.append({'app_id': snapshot.app_id, 'success': True, 'error': None})
        except (ValueError, WaasApiError) as e:
            results.append({'app_id': snapshot.app_id, 'success': False, 'error': str(e)})

    success_count = sum(1 for r in results if r['success'])
    fail_count = len(results) - success_count
    flash(
        _('Batch revert: %(ok)d succeeded, %(fail)d failed.', ok=success_count, fail=fail_count),
        'success' if fail_count == 0 else 'warning'
    )

    return render_template(
        'config_history/batch_revert_results.html',
        results=results,
        batch_id=batch_id,
        success_count=success_count,
        fail_count=fail_count,
    )
