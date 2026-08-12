import json
import logging
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, make_response
from flask_login import login_required, current_user
from flask_babel import gettext as _
from werkzeug.utils import secure_filename
from app import db
from app.models import (
    WaasAccount, AuditLog, Feature, FeatureApplication,
    get_user_accounts, get_account_for_user, can_write,
)
from app.forms import FeatureForm, FeatureFromAppForm
from app.waas_client import WaasClient, WaasApiError
from app import limiter

logger = logging.getLogger(__name__)

bp = Blueprint('features', __name__, url_prefix='/raw-configs')


# Legacy redirect blueprint — preserves old /features/* bookmarks.
# Registered separately in app/__init__.py.
legacy_bp = Blueprint('features_legacy', __name__, url_prefix='/features')


@legacy_bp.route('/', defaults={'subpath': ''})
@legacy_bp.route('/<path:subpath>')
def legacy_redirect(subpath):
    """301 redirect from old /features/* URLs to /raw-configs/*."""
    target = '/raw-configs/' + subpath if subpath else '/raw-configs/'
    if request.query_string:
        target += '?' + request.query_string.decode('utf-8')
    return redirect(target, code=301)


def get_client_for_account(account_id, min_permission='read'):
    """Helper to get WaasClient for an account the user can access."""
    account, perm = get_account_for_user(account_id, current_user, min_permission=min_permission)
    if not account:
        return None, None
    return WaasClient.from_account(account), account


def get_feature_or_404(feature_id, owner_only=False):
    """Get a feature by ID, checking visibility rules."""
    feature = Feature.query.get_or_404(feature_id)
    if owner_only:
        if feature.user_id != current_user.id and not current_user.is_admin:
            return None
    else:
        if feature.user_id != current_user.id and not feature.is_global and not feature.is_predefined:
            return None
    return feature


def apply_feature_to_app(client, feature, app_id):
    """Apply a feature to an app using its configured API endpoint.

    For /endpoints/ targets, merges feature config on top of the current
    endpoint config so we don't clobber user's cipher suites, PFS, etc.
    """
    payload = feature.config_dict

    if '/endpoints/' in feature.api_endpoint:
        try:
            current_config = client.get_application(app_id)
            current_https = (current_config.get('endpoints', {}).get('https') or {})
            merged = {**current_https, **(payload.get('https', {}))}
            payload = {'https': merged}
        except WaasApiError:
            pass  # proceed with feature payload as-is

    return client.call_api(feature.api_method, feature.api_endpoint, app_id, payload)


CATEGORY_BADGES = {
    'Security Hardening': 'bg-danger',
    'Performance': 'bg-success',
    'Compliance': 'bg-primary',
    'Network': 'bg-info',
    'Custom': 'bg-secondary',
}


@bp.route('/')
@login_required
def list_features():
    """List features in 3 sections: My, Global, Predefined"""
    my_features = Feature.query.filter_by(user_id=current_user.id, is_predefined=False).order_by(Feature.updated_at.desc()).all()
    global_features = Feature.query.filter(
        Feature.is_global == True,
        Feature.is_predefined == False,
        Feature.user_id != current_user.id,
    ).order_by(Feature.updated_at.desc()).all()
    predefined_features = Feature.query.filter_by(is_predefined=True).order_by(Feature.name).all()
    return render_template(
        'features/list.html',
        my_features=my_features,
        global_features=global_features,
        predefined_features=predefined_features,
        category_badges=CATEGORY_BADGES,
    )


@bp.route('/add', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute", methods=["POST"])
def add_feature():
    """Create a new feature"""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to create raw configs.'), 'danger')
        return redirect(url_for('features.list_features'))

    form = FeatureForm()

    if form.validate_on_submit():
        is_global = form.is_global.data and current_user.is_admin

        feature = Feature(
            user_id=current_user.id,
            name=form.name.data.strip(),
            description=form.description.data.strip() if form.description.data else None,
            category=form.category.data,
            is_global=is_global,
            api_endpoint=form.api_endpoint.data,
            api_method=form.api_method.data,
            config_data='{}',
        )
        db.session.add(feature)
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='feature_create',
            resource_type='feature',
            resource_id=feature.id,
            details=f'Created feature: {feature.name}',
            ip_address=request.remote_addr,
        )

        flash(_('Raw config "%(name)s" created. Now edit its configuration.', name=feature.name), 'success')
        return redirect(url_for('features.edit_config', feature_id=feature.id))

    return render_template('features/add.html', form=form)


@bp.route('/<int:feature_id>')
@login_required
def view_feature(feature_id):
    """View feature details + applied apps"""
    feature = get_feature_or_404(feature_id)
    if not feature:
        flash(_('Raw config not found or access denied.'), 'danger')
        return redirect(url_for('features.list_features'))

    applied_apps = FeatureApplication.query.filter_by(feature_id=feature.id).order_by(FeatureApplication.applied_at.desc()).all()
    accounts = get_user_accounts(current_user)
    return render_template(
        'features/view.html',
        feature=feature,
        applied_apps=applied_apps,
        accounts=accounts,
        category_badges=CATEGORY_BADGES,
    )


@bp.route('/<int:feature_id>/edit', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per minute", methods=["POST"])
def edit_feature(feature_id):
    """Edit feature metadata"""
    feature = get_feature_or_404(feature_id, owner_only=True)
    if not feature:
        flash(_('Raw config not found or access denied.'), 'danger')
        return redirect(url_for('features.list_features'))

    if current_user.role == 'viewer':
        flash(_('You do not have permission to edit raw configs.'), 'danger')
        return redirect(url_for('features.view_feature', feature_id=feature_id))

    form = FeatureForm(obj=feature)

    if form.validate_on_submit():
        feature.name = form.name.data.strip()
        feature.description = form.description.data.strip() if form.description.data else None
        feature.category = form.category.data
        feature.is_global = form.is_global.data and current_user.is_admin
        feature.api_endpoint = form.api_endpoint.data
        feature.api_method = form.api_method.data
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='feature_edit',
            resource_type='feature',
            resource_id=feature.id,
            details=f'Edited feature: {feature.name}',
            ip_address=request.remote_addr,
        )

        flash(_('Raw config "%(name)s" updated.', name=feature.name), 'success')
        return redirect(url_for('features.view_feature', feature_id=feature.id))

    return render_template('features/edit.html', form=form, feature=feature)


@bp.route('/<int:feature_id>/edit-config', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per minute", methods=["POST"])
def edit_config(feature_id):
    """Edit raw JSON config data"""
    feature = get_feature_or_404(feature_id, owner_only=True)
    if not feature:
        flash(_('Raw config not found or access denied.'), 'danger')
        return redirect(url_for('features.list_features'))

    if current_user.role == 'viewer':
        flash(_('You do not have permission to edit raw configs.'), 'danger')
        return redirect(url_for('features.view_feature', feature_id=feature_id))

    if request.method == 'POST':
        config_text = request.form.get('config_data', '{}')
        try:
            parsed = json.loads(config_text)
            feature.config_dict = parsed
            db.session.commit()

            AuditLog.log(
                user_id=current_user.id,
                action='feature_config_edit',
                resource_type='feature',
                resource_id=feature.id,
                details=f'Edited config data for feature: {feature.name}',
                ip_address=request.remote_addr,
            )

            flash(_('Raw config configuration updated.'), 'success')
            return redirect(url_for('features.view_feature', feature_id=feature.id))
        except json.JSONDecodeError as e:
            flash(_('Invalid JSON: %(error)s', error=str(e)), 'danger')

    return render_template('features/edit_config.html', feature=feature)


@bp.route('/<int:feature_id>/delete', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def delete_feature(feature_id):
    """Delete a feature (block predefined unless admin)"""
    feature = get_feature_or_404(feature_id, owner_only=True)
    if not feature:
        flash(_('Raw config not found or access denied.'), 'danger')
        return redirect(url_for('features.list_features'))

    if feature.is_predefined and not current_user.is_admin:
        flash(_('Predefined raw configs cannot be deleted.'), 'danger')
        return redirect(url_for('features.view_feature', feature_id=feature_id))

    if current_user.role == 'viewer':
        flash(_('You do not have permission to delete raw configs.'), 'danger')
        return redirect(url_for('features.list_features'))

    feature_name = feature.name
    AuditLog.log(
        user_id=current_user.id,
        action='feature_delete',
        resource_type='feature',
        resource_id=feature.id,
        details=f'Deleted feature: {feature_name}',
        ip_address=request.remote_addr,
    )

    db.session.delete(feature)
    db.session.commit()

    flash(_('Raw config "%(name)s" deleted.', name=feature_name), 'success')
    return redirect(url_for('features.list_features'))


@bp.route('/from-app/<int:account_id>/<app_id>', methods=['GET', 'POST'])
@login_required
def save_as_feature(account_id, app_id):
    """Create a feature from a live application's config"""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to create raw configs.'), 'danger')
        return redirect(url_for('applications.view_application', account_id=account_id, app_id=app_id))

    client, account = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or inactive.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    try:
        app_config = client.get_application(app_id)
    except WaasApiError as e:
        flash(_('Failed to export application config: %(error)s', error=str(e)), 'danger')
        return redirect(url_for('applications.view_application', account_id=account_id, app_id=app_id))

    try:
        security_config = client.get_security_config(app_id)
    except WaasApiError:
        security_config = {}

    form = FeatureFromAppForm()

    if form.validate_on_submit():
        config = {}

        if form.include_basic_security.data:
            if 'protection_mode' in security_config:
                config['protection_mode'] = security_config['protection_mode']
            elif 'protection_mode' in app_config:
                config['protection_mode'] = app_config['protection_mode']

        if form.include_request_limits.data and security_config.get('request_limits'):
            config['request_limits'] = security_config['request_limits']

        if form.include_clickjacking.data and security_config.get('clickjacking_protection'):
            config['clickjacking_protection'] = security_config['clickjacking_protection']

        if form.include_data_theft.data and security_config.get('data_theft_protection'):
            config['data_theft_protection'] = security_config['data_theft_protection']

        if form.include_servers.data and app_config.get('servers'):
            config['servers'] = app_config['servers']

        if form.include_endpoints.data and app_config.get('endpoints'):
            config['endpoints'] = app_config['endpoints']

        is_global = form.is_global.data and current_user.is_admin

        feature = Feature(
            user_id=current_user.id,
            name=form.name.data.strip(),
            description=form.description.data.strip() if form.description.data else None,
            category=form.category.data,
            is_global=is_global,
        )
        feature.config_dict = config
        db.session.add(feature)
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='feature_create_from_app',
            resource_type='feature',
            resource_id=feature.id,
            details=f'Created feature "{feature.name}" from app {app_id} (account: {account.account_name})',
            ip_address=request.remote_addr,
        )

        flash(_('Raw config "%(name)s" created from application "%(app_id)s".', name=feature.name, app_id=app_id), 'success')
        return redirect(url_for('features.view_feature', feature_id=feature.id))

    if request.method == 'GET':
        form.name.data = f'{app_id} - Feature'

    return render_template(
        'features/save_as.html',
        form=form,
        account=account,
        app_id=app_id,
        app_config=app_config,
        security_config=security_config,
    )


@bp.route('/<int:feature_id>/apply/<int:account_id>/<app_id>', methods=['POST'])
@login_required
def apply_feature(feature_id, account_id, app_id):
    """Apply a feature to a single application and track it"""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to apply raw configs.'), 'danger')
        return redirect(url_for('features.view_feature', feature_id=feature_id))

    feature = get_feature_or_404(feature_id)
    if not feature:
        flash(_('Raw config not found or access denied.'), 'danger')
        return redirect(url_for('features.list_features'))

    client, account = get_client_for_account(account_id, min_permission='write')
    if not client:
        flash(_('Account not found or insufficient permissions.'), 'danger')
        return redirect(url_for('features.view_feature', feature_id=feature_id))

    try:
        apply_feature_to_app(client, feature, app_id)

        # Upsert FeatureApplication record
        fa = FeatureApplication.query.filter_by(
            feature_id=feature.id, account_id=account_id, app_name=app_id
        ).first()
        if fa:
            fa.applied_at = datetime.utcnow()
            fa.applied_by = current_user.id
        else:
            fa = FeatureApplication(
                feature_id=feature.id,
                account_id=account_id,
                app_name=app_id,
                applied_by=current_user.id,
            )
            db.session.add(fa)
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='feature_apply',
            resource_type='feature',
            resource_id=feature.id,
            details=f'Applied feature "{feature.name}" to app {app_id} (account: {account.account_name})',
            ip_address=request.remote_addr,
        )

        flash(_('Raw config "%(name)s" applied to "%(app_id)s" successfully.', name=feature.name, app_id=app_id), 'success')
    except WaasApiError as e:
        flash(_('Failed to apply raw config to "%(app_id)s": %(error)s', app_id=app_id, error=str(e)), 'danger')

    return redirect(url_for('applications.view_application', account_id=account_id, app_id=app_id))


@bp.route('/<int:feature_id>/bulk-apply', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute", methods=["POST"])
def bulk_apply(feature_id):
    """Apply a feature to multiple applications"""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to apply raw configs.'), 'danger')
        return redirect(url_for('features.view_feature', feature_id=feature_id))

    feature = get_feature_or_404(feature_id)
    if not feature:
        flash(_('Raw config not found or access denied.'), 'danger')
        return redirect(url_for('features.list_features'))

    accounts = get_user_accounts(current_user, active_only=True)

    if request.method == 'POST':
        selected_apps = request.form.getlist('selected_apps')

        if not selected_apps:
            flash(_('No applications selected.'), 'warning')
            return redirect(url_for('features.bulk_apply', feature_id=feature_id))

        results = []
        for app_entry in selected_apps:
            try:
                acct_id_str, app_name = app_entry.split(':', 1)
                acct_id = int(acct_id_str)
            except (ValueError, IndexError):
                results.append({'app': app_entry, 'account': 'Unknown', 'success': False, 'error': 'Invalid format'})
                continue

            client, account = get_client_for_account(acct_id)
            if not client:
                results.append({'app': app_name, 'account': f'ID {acct_id}', 'success': False, 'error': 'Account not found'})
                continue

            try:
                apply_feature_to_app(client, feature, app_name)
                # Upsert FeatureApplication
                fa = FeatureApplication.query.filter_by(
                    feature_id=feature.id, account_id=acct_id, app_name=app_name
                ).first()
                if fa:
                    fa.applied_at = datetime.utcnow()
                    fa.applied_by = current_user.id
                else:
                    fa = FeatureApplication(
                        feature_id=feature.id,
                        account_id=acct_id,
                        app_name=app_name,
                        applied_by=current_user.id,
                    )
                    db.session.add(fa)
                results.append({'app': app_name, 'account': account.account_name, 'success': True, 'error': None})
            except WaasApiError as e:
                results.append({'app': app_name, 'account': account.account_name, 'success': False, 'error': str(e)})

        db.session.commit()

        success_count = sum(1 for r in results if r['success'])
        fail_count = len(results) - success_count

        AuditLog.log(
            user_id=current_user.id,
            action='feature_bulk_apply',
            resource_type='feature',
            resource_id=feature.id,
            details=f'Bulk applied feature "{feature.name}" to {len(results)} apps ({success_count} ok, {fail_count} failed)',
            ip_address=request.remote_addr,
        )

        return render_template(
            'features/bulk_results.html',
            feature=feature,
            results=results,
            success_count=success_count,
            fail_count=fail_count,
        )

    # GET: fetch apps from all accounts
    accounts_with_apps = []
    for account in accounts:
        try:
            client = WaasClient.from_account(account)
            result = client.list_applications()
            apps = _parse_app_list(result)
            if apps:
                accounts_with_apps.append({'account': account, 'apps': apps})
        except WaasApiError:
            pass

    return render_template(
        'features/bulk_apply.html',
        feature=feature,
        accounts_with_apps=accounts_with_apps,
    )


@bp.route('/<int:feature_id>/export')
@login_required
def export_feature(feature_id):
    """Export a feature as a JSON file download."""
    feature = get_feature_or_404(feature_id)
    if not feature:
        flash(_('Raw config not found or access denied.'), 'danger')
        return redirect(url_for('features.list_features'))

    export_data = {
        'name': feature.name,
        'description': feature.description or '',
        'category': feature.category or 'Custom',
        'config_data': feature.config_dict,
        'api_endpoint': feature.api_endpoint,
        'api_method': feature.api_method,
        'is_global': feature.is_global,
        'exported_at': datetime.now(timezone.utc).isoformat(),
        'version': '1.0',
        'type': 'feature',
    }

    data = json.dumps(export_data, indent=2, default=str)
    filename = secure_filename(f'{feature.name}.json') or 'feature.json'

    AuditLog.log(
        user_id=current_user.id,
        action='feature_export',
        resource_type='feature',
        resource_id=feature.id,
        details=f'Exported feature: {feature.name}',
        ip_address=request.remote_addr,
    )

    response = make_response(data)
    response.headers['Content-Type'] = 'application/json'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


@bp.route('/import', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute", methods=["POST"])
def import_feature():
    """Import a feature from a JSON file."""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to import raw configs.'), 'danger')
        return redirect(url_for('features.list_features'))

    if request.method == 'POST':
        file = request.files.get('feature_file')
        if not file or not file.filename:
            flash(_('Please select a JSON file to import.'), 'warning')
            return redirect(url_for('features.import_feature'))

        if not file.filename.lower().endswith('.json'):
            flash(_('Only .json files are supported.'), 'danger')
            return redirect(url_for('features.import_feature'))

        try:
            content = file.read().decode('utf-8')
            data = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            flash(_('Invalid JSON file: %(error)s', error=str(e)), 'danger')
            return redirect(url_for('features.import_feature'))

        if not isinstance(data, dict) or 'name' not in data or 'config_data' not in data:
            flash(_('Invalid raw config format. File must contain "name" and "config_data" fields.'), 'danger')
            return redirect(url_for('features.import_feature'))

        if not isinstance(data['config_data'], dict):
            flash(_('Invalid raw config format. "config_data" must be a JSON object.'), 'danger')
            return redirect(url_for('features.import_feature'))

        is_global = data.get('is_global', False) and current_user.is_admin

        feature = Feature(
            user_id=current_user.id,
            name=data['name'].strip()[:100],
            description=(data.get('description', '') or '').strip()[:500] or None,
            category=data.get('category', 'Custom').strip()[:50],
            is_global=is_global,
            api_endpoint=data.get('api_endpoint', '/applications/{app_id}/import/').strip()[:255],
            api_method=data.get('api_method', 'PATCH').strip()[:10],
        )
        feature.config_dict = data['config_data']
        db.session.add(feature)
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='feature_import',
            resource_type='feature',
            resource_id=feature.id,
            details=f'Imported feature: {feature.name}',
            ip_address=request.remote_addr,
        )

        flash(_('Raw config "%(name)s" imported successfully.', name=feature.name), 'success')
        return redirect(url_for('features.view_feature', feature_id=feature.id))

    return render_template('features/import.html')


def _parse_app_list(result):
    """Normalise the raw API list response into a plain Python list."""
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        apps = result.get('results', result.get('data', result.get('applications', [])))
        return apps if isinstance(apps, list) else [result]
    return []
