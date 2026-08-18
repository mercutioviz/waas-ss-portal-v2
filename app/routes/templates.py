import json
import logging
import uuid
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, make_response
from flask_login import login_required, current_user
from flask_babel import gettext as _
from werkzeug.utils import secure_filename
from app import db
from app.models import WaasAccount, AuditLog, ConfigTemplate, TemplateApplication, ConfigSnapshot, get_user_accounts, get_account_for_user, can_write
from app.forms import ConfigTemplateForm, TemplateFromAppForm
from app.waas_client import WaasClient, WaasApiError
from app import limiter

logger = logging.getLogger(__name__)

bp = Blueprint('templates', __name__, url_prefix='/templates')


def get_client_for_account(account_id, min_permission='read'):
    """Helper to get WaasClient for an account the user can access."""
    account, perm = get_account_for_user(account_id, current_user, min_permission=min_permission)
    if not account:
        return None, None
    return WaasClient.from_account(account), account


def get_template_or_404(template_id, owner_only=False):
    """Get a template by ID, checking visibility rules.

    If owner_only=True, only the owner can access it.
    Otherwise, owner or global templates are accessible.
    """
    template = ConfigTemplate.query.get_or_404(template_id)
    if owner_only:
        if template.user_id != current_user.id:
            return None
    else:
        if template.user_id != current_user.id and not template.is_global:
            return None
    return template


@bp.route('/')
@login_required
def list_templates():
    """List user's templates and global templates"""
    my_templates = ConfigTemplate.query.filter_by(user_id=current_user.id).order_by(ConfigTemplate.updated_at.desc()).all()
    global_templates = ConfigTemplate.query.filter(
        ConfigTemplate.is_global == True,
        ConfigTemplate.user_id != current_user.id
    ).order_by(ConfigTemplate.updated_at.desc()).all()
    return render_template('templates/list.html', my_templates=my_templates, global_templates=global_templates)


@bp.route('/add', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute", methods=["POST"])
def add_template():
    """Create a new template"""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to create templates.'), 'danger')
        return redirect(url_for('templates.list_templates'))

    form = ConfigTemplateForm()

    if form.validate_on_submit():
        # Restrict global toggle to admins
        is_global = form.is_global.data and current_user.is_admin

        template = ConfigTemplate(
            user_id=current_user.id,
            name=form.name.data.strip(),
            description=form.description.data.strip() if form.description.data else None,
            is_global=is_global,
            config_data='{}'
        )
        db.session.add(template)
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='template_create',
            resource_type='config_template',
            resource_id=template.id,
            details=f'Created config template: {template.name}',
            ip_address=request.remote_addr
        )

        flash(_('Template "%(name)s" created. Now edit its configuration.', name=template.name), 'success')
        return redirect(url_for('templates.edit_config', template_id=template.id))

    return render_template('templates/add.html', form=form)


@bp.route('/<int:template_id>')
@login_required
def view_template(template_id):
    """View template details"""
    template = get_template_or_404(template_id)
    if not template:
        flash(_('Template not found or access denied.'), 'danger')
        return redirect(url_for('templates.list_templates'))

    accounts = get_user_accounts(current_user)
    applied_apps = TemplateApplication.query.filter_by(template_id=template.id)\
        .order_by(TemplateApplication.applied_at.desc()).limit(10).all()
    return render_template('templates/view.html', template=template, accounts=accounts, applied_apps=applied_apps)


@bp.route('/<int:template_id>/edit', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per minute", methods=["POST"])
def edit_template(template_id):
    """Edit template metadata"""
    template = get_template_or_404(template_id, owner_only=True)
    if not template:
        flash(_('Template not found or access denied.'), 'danger')
        return redirect(url_for('templates.list_templates'))

    if current_user.role == 'viewer':
        flash(_('You do not have permission to edit templates.'), 'danger')
        return redirect(url_for('templates.view_template', template_id=template_id))

    form = ConfigTemplateForm(obj=template)

    if form.validate_on_submit():
        template.name = form.name.data.strip()
        template.description = form.description.data.strip() if form.description.data else None
        template.is_global = form.is_global.data and current_user.is_admin
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='template_edit',
            resource_type='config_template',
            resource_id=template.id,
            details=f'Edited config template: {template.name}',
            ip_address=request.remote_addr
        )

        flash(_('Template "%(name)s" updated.', name=template.name), 'success')
        return redirect(url_for('templates.view_template', template_id=template.id))

    return render_template('templates/edit.html', form=form, template=template)


@bp.route('/<int:template_id>/edit-config', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per minute", methods=["POST"])
def edit_config(template_id):
    """Edit raw JSON config data"""
    template = get_template_or_404(template_id, owner_only=True)
    if not template:
        flash(_('Template not found or access denied.'), 'danger')
        return redirect(url_for('templates.list_templates'))

    if current_user.role == 'viewer':
        flash(_('You do not have permission to edit templates.'), 'danger')
        return redirect(url_for('templates.view_template', template_id=template_id))

    if request.method == 'POST':
        config_text = request.form.get('config_data', '{}')
        try:
            parsed = json.loads(config_text)
            template.config_dict = parsed
            db.session.commit()

            AuditLog.log(
                user_id=current_user.id,
                action='template_config_edit',
                resource_type='config_template',
                resource_id=template.id,
                details=f'Edited config data for template: {template.name}',
                ip_address=request.remote_addr
            )

            flash(_('Template configuration updated.'), 'success')
            return redirect(url_for('templates.view_template', template_id=template.id))
        except json.JSONDecodeError as e:
            flash(_('Invalid JSON: %(error)s', error=str(e)), 'danger')

    return render_template('templates/edit_config.html', template=template)


@bp.route('/<int:template_id>/delete', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def delete_template(template_id):
    """Delete a template"""
    template = get_template_or_404(template_id, owner_only=True)
    if not template:
        flash(_('Template not found or access denied.'), 'danger')
        return redirect(url_for('templates.list_templates'))

    if current_user.role == 'viewer':
        flash(_('You do not have permission to delete templates.'), 'danger')
        return redirect(url_for('templates.list_templates'))

    template_name = template.name
    AuditLog.log(
        user_id=current_user.id,
        action='template_delete',
        resource_type='config_template',
        resource_id=template.id,
        details=f'Deleted config template: {template_name}',
        ip_address=request.remote_addr
    )

    db.session.delete(template)
    db.session.commit()

    flash(_('Template "%(name)s" deleted.', name=template_name), 'success')
    return redirect(url_for('templates.list_templates'))


@bp.route('/from-app/<int:account_id>/<app_id>', methods=['GET', 'POST'])
@login_required
def save_as_template(account_id, app_id):
    """Create a template from a live application's exported config"""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to create templates.'), 'danger')
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

    # Also fetch security config for section-level extraction
    try:
        security_config = client.get_security_config(app_id)
    except WaasApiError:
        security_config = {}

    form = TemplateFromAppForm()

    if form.validate_on_submit():
        # Build partial config from selected sections
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

        template = ConfigTemplate(
            user_id=current_user.id,
            name=form.name.data.strip(),
            description=form.description.data.strip() if form.description.data else None,
            is_global=is_global,
        )
        template.config_dict = config
        db.session.add(template)
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='template_create_from_app',
            resource_type='config_template',
            resource_id=template.id,
            details=f'Created template "{template.name}" from app {app_id} (account: {account.account_name})',
            ip_address=request.remote_addr
        )

        flash(_('Template "%(name)s" created from application "%(app_id)s".', name=template.name, app_id=app_id), 'success')
        return redirect(url_for('templates.view_template', template_id=template.id))

    # Pre-fill name suggestion
    if request.method == 'GET':
        form.name.data = f'{app_id} - Security Template'

    return render_template(
        'templates/save_as.html',
        form=form,
        account=account,
        app_id=app_id,
        app_config=app_config,
        security_config=security_config
    )


@bp.route('/<int:template_id>/apply/<int:account_id>/<app_id>', methods=['POST'])
@login_required
def apply_template(template_id, account_id, app_id):
    """Apply a template to a single application"""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to apply templates.'), 'danger')
        return redirect(url_for('templates.view_template', template_id=template_id))

    template = get_template_or_404(template_id)
    if not template:
        flash(_('Template not found or access denied.'), 'danger')
        return redirect(url_for('templates.list_templates'))

    client, account = get_client_for_account(account_id, min_permission='write')
    if not client:
        flash(_('Account not found or insufficient permissions.'), 'danger')
        return redirect(url_for('templates.view_template', template_id=template_id))

    include_servers = request.form.get('include_servers') == 'on'
    include_endpoints = request.form.get('include_endpoints') == 'on'

    try:
        payload_before = client.get_application(app_id)
        client.import_application(
            app_id,
            template.config_dict,
            include_servers=include_servers,
            include_endpoints=include_endpoints
        )

        ConfigSnapshot.record(
            user_id=current_user.id,
            account_id=account.id,
            app_id=app_id,
            resource_type='template_apply',
            payload_before=payload_before,
            resource_label=template.name,
            payload_applied=template.config_dict
        )

        ta = TemplateApplication.query.filter_by(
            template_id=template.id, account_id=account_id, app_name=app_id
        ).first()
        if ta:
            ta.applied_at = datetime.now(timezone.utc)
            ta.applied_by = current_user.id
        else:
            db.session.add(TemplateApplication(
                template_id=template.id, account_id=account_id,
                app_name=app_id, applied_by=current_user.id
            ))
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='template_apply',
            resource_type='config_template',
            resource_id=template.id,
            details=f'Applied template "{template.name}" to app {app_id} (account: {account.account_name})',
            ip_address=request.remote_addr
        )

        flash(_('Template "%(name)s" applied to "%(app_id)s" successfully.', name=template.name, app_id=app_id), 'success')
    except WaasApiError as e:
        flash(_('Failed to apply template to "%(app_id)s": %(error)s', app_id=app_id, error=str(e)), 'danger')

    return redirect(url_for('applications.view_application', account_id=account_id, app_id=app_id))


@bp.route('/<int:template_id>/bulk-apply', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute", methods=["POST"])
def bulk_apply(template_id):
    """Apply a template to multiple applications"""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to apply templates.'), 'danger')
        return redirect(url_for('templates.view_template', template_id=template_id))

    template = get_template_or_404(template_id)
    if not template:
        flash(_('Template not found or access denied.'), 'danger')
        return redirect(url_for('templates.list_templates'))

    accounts = get_user_accounts(current_user, active_only=True)

    if request.method == 'POST':
        selected_apps = request.form.getlist('selected_apps')
        include_servers = request.form.get('include_servers') == 'on'
        include_endpoints = request.form.get('include_endpoints') == 'on'

        if not selected_apps:
            flash(_('No applications selected.'), 'warning')
            return redirect(url_for('templates.bulk_apply', template_id=template_id))

        results = []
        batch_id = str(uuid.uuid4())
        for app_entry in selected_apps:
            # Format: "account_id:app_name"
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
                payload_before = client.get_application(app_name)
                client.import_application(
                    app_name,
                    template.config_dict,
                    include_servers=include_servers,
                    include_endpoints=include_endpoints
                )
                ConfigSnapshot.record(
                    user_id=current_user.id,
                    account_id=account.id,
                    app_id=app_name,
                    resource_type='template_bulk_apply',
                    payload_before=payload_before,
                    resource_label=template.name,
                    payload_applied=template.config_dict,
                    batch_id=batch_id
                )
                results.append({'app': app_name, 'account': account.account_name, 'success': True, 'error': None})
                ta = TemplateApplication.query.filter_by(
                    template_id=template.id, account_id=acct_id, app_name=app_name
                ).first()
                if ta:
                    ta.applied_at = datetime.now(timezone.utc)
                    ta.applied_by = current_user.id
                else:
                    db.session.add(TemplateApplication(
                        template_id=template.id, account_id=acct_id,
                        app_name=app_name, applied_by=current_user.id
                    ))
            except WaasApiError as e:
                results.append({'app': app_name, 'account': account.account_name, 'success': False, 'error': str(e)})

        db.session.commit()
        success_count = sum(1 for r in results if r['success'])
        fail_count = len(results) - success_count

        AuditLog.log(
            user_id=current_user.id,
            action='template_bulk_apply',
            resource_type='config_template',
            resource_id=template.id,
            details=f'Bulk applied template "{template.name}" to {len(results)} apps ({success_count} ok, {fail_count} failed)',
            ip_address=request.remote_addr
        )

        return render_template(
            'templates/bulk_results.html',
            template=template,
            results=results,
            success_count=success_count,
            fail_count=fail_count
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
        'templates/bulk_apply.html',
        template=template,
        accounts_with_apps=accounts_with_apps
    )


@bp.route('/<int:template_id>/export')
@login_required
def export_template(template_id):
    """Export a template as a JSON file download."""
    template = get_template_or_404(template_id)
    if not template:
        flash(_('Template not found or access denied.'), 'danger')
        return redirect(url_for('templates.list_templates'))

    export_data = {
        'name': template.name,
        'description': template.description or '',
        'config_data': template.config_dict,
        'is_global': template.is_global,
        'exported_at': datetime.now(timezone.utc).isoformat(),
        'version': '1.0',
    }

    data = json.dumps(export_data, indent=2, default=str)
    filename = secure_filename(f'{template.name}.json') or 'template.json'

    AuditLog.log(
        user_id=current_user.id,
        action='template_export',
        resource_type='config_template',
        resource_id=template.id,
        details=f'Exported config template: {template.name}',
        ip_address=request.remote_addr,
    )

    response = make_response(data)
    response.headers['Content-Type'] = 'application/json'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


@bp.route('/import', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute", methods=["POST"])
def import_template():
    """Import a template from a JSON file."""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to import templates.'), 'danger')
        return redirect(url_for('templates.list_templates'))

    if request.method == 'POST':
        file = request.files.get('template_file')
        if not file or not file.filename:
            flash(_('Please select a JSON file to import.'), 'warning')
            return redirect(url_for('templates.import_template'))

        if not file.filename.lower().endswith('.json'):
            flash(_('Only .json files are supported.'), 'danger')
            return redirect(url_for('templates.import_template'))

        try:
            content = file.read().decode('utf-8')
            data = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            flash(_('Invalid JSON file: %(error)s', error=str(e)), 'danger')
            return redirect(url_for('templates.import_template'))

        # Validate required fields
        if not isinstance(data, dict) or 'name' not in data or 'config_data' not in data:
            flash(_('Invalid template format. File must contain "name" and "config_data" fields.'), 'danger')
            return redirect(url_for('templates.import_template'))

        if not isinstance(data['config_data'], dict):
            flash(_('Invalid template format. "config_data" must be a JSON object.'), 'danger')
            return redirect(url_for('templates.import_template'))

        is_global = data.get('is_global', False) and current_user.is_admin

        template = ConfigTemplate(
            user_id=current_user.id,
            name=data['name'].strip()[:100],
            description=(data.get('description', '') or '').strip()[:500] or None,
            is_global=is_global,
        )
        template.config_dict = data['config_data']
        db.session.add(template)
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='template_import',
            resource_type='config_template',
            resource_id=template.id,
            details=f'Imported config template: {template.name}',
            ip_address=request.remote_addr,
        )

        flash(_('Template "%(name)s" imported successfully.', name=template.name), 'success')
        return redirect(url_for('templates.view_template', template_id=template.id))

    return render_template('templates/import.html')


def _parse_app_list(result):
    """Normalise the raw API list response into a plain Python list."""
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        apps = result.get('results', result.get('data', result.get('applications', [])))
        return apps if isinstance(apps, list) else [result]
    return []
