from datetime import date
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from flask_babel import gettext as _
from app.models import WaasAccount, AuditLog, get_user_accounts, get_account_for_user, can_write
from app.waas_client import WaasClient, WaasApiError
from app.forms import CertificateUploadForm
from app.routes.main import _parse_cert_expiry
from app import limiter

bp = Blueprint('certificates', __name__, url_prefix='/certificates')


@bp.route('/')
@login_required
def list_certificates():
    """List certificates — user selects which WaaS account to view."""
    accounts = get_user_accounts(current_user)
    selected_account_id = request.args.get('account_id', type=int)

    certificates = []
    selected_account = None
    error = None

    page = request.args.get('page', 1, type=int)
    per_page = 25
    total_certs = 0
    total_pages = 1

    if selected_account_id:
        account, perm = get_account_for_user(selected_account_id, current_user)
        if account:
            selected_account = account
            try:
                client = WaasClient.from_account(account)
                result = client.list_certificates()
                all_certs = result if isinstance(result, list) else result.get('results', result.get('data', []))
                today = date.today()
                for cert in all_certs:
                    expiry_str = cert.get('expiry', cert.get('expiryDate'))
                    expiry_date = _parse_cert_expiry(expiry_str)
                    cert['_days_remaining'] = (expiry_date - today).days if expiry_date else None
                total_certs = len(all_certs)
                total_pages = max(1, (total_certs + per_page - 1) // per_page)
                page = max(1, min(page, total_pages))
                start = (page - 1) * per_page
                certificates = all_certs[start:start + per_page]
            except WaasApiError as e:
                error = str(e)
        else:
            error = _('Account not found or inactive.')

    return render_template(
        'certificates/list.html',
        accounts=accounts,
        certificates=certificates,
        selected_account=selected_account,
        selected_account_id=selected_account_id,
        error=error,
        page=page,
        per_page=per_page,
        total_certs=total_certs,
        total_pages=total_pages,
    )


@bp.route('/<int:account_id>/upload', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute", methods=["POST"])
def upload_certificate(account_id):
    """Upload a certificate to a WaaS application."""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to upload certificates.'), 'danger')
        return redirect(url_for('certificates.list_certificates'))

    account, perm = get_account_for_user(account_id, current_user, min_permission='write')
    if not account:
        flash(_('Account not found or insufficient permissions.'), 'danger')
        return redirect(url_for('certificates.list_certificates'))

    if not can_write(perm):
        flash(_('You do not have write permission on this account.'), 'danger')
        return redirect(url_for('certificates.list_certificates'))

    app_name = request.args.get('app_name') or request.form.get('app_name')

    client = WaasClient.from_account(account)
    applications = []
    try:
        result = client.list_applications()
        if isinstance(result, list):
            applications = result
        elif isinstance(result, dict):
            applications = result.get('results', result.get('data', result.get('applications', [])))
    except WaasApiError:
        pass

    form = CertificateUploadForm()

    if form.validate_on_submit() and app_name:
        try:
            files = {}
            cert_file = form.certificate_file.data
            if cert_file:
                files['certificate'] = (cert_file.filename, cert_file.stream, cert_file.content_type or 'application/octet-stream')

            key_file = form.certificate_key_file.data
            if key_file:
                files['key'] = (key_file.filename, key_file.stream, key_file.content_type or 'application/octet-stream')

            data = {}
            if form.pfx_password.data:
                data['password'] = form.pfx_password.data
            if form.friendly_name.data:
                data['friendly_name'] = form.friendly_name.data

            result = client.upload_certificate(app_name=app_name, files=files, data=data)

            AuditLog.log(
                user_id=current_user.id,
                action='certificate_upload',
                resource_type='certificate',
                details=f'Uploaded certificate to app {app_name} on account {account.account_name}: {form.friendly_name.data or cert_file.filename}',
                ip_address=request.remote_addr
            )

            flash(_('Certificate uploaded successfully.'), 'success')
            return redirect(url_for('certificates.list_certificates', account_id=account_id))

        except WaasApiError as e:
            flash(_('Failed to upload certificate: %(error)s', error=str(e)), 'danger')
    elif form.is_submitted() and not app_name:
        flash(_('Please select an application for this certificate.'), 'warning')

    return render_template(
        'certificates/upload.html',
        account=account,
        form=form,
        applications=applications,
        app_name=app_name
    )


@bp.route('/<int:account_id>/<app_name>/<cert_id>')
@login_required
def view_certificate(account_id, app_name, cert_id):
    """View certificate details (v4 per-application SNI certificate)."""
    account, perm = get_account_for_user(account_id, current_user)
    if not account:
        flash(_('Account not found or access denied.'), 'danger')
        return redirect(url_for('certificates.list_certificates'))

    try:
        client = WaasClient.from_account(account)
        certificate = client.get_certificate(app_name, cert_id)
    except WaasApiError as e:
        flash(_('Failed to load certificate: %(error)s', error=str(e)), 'danger')
        return redirect(url_for('certificates.list_certificates', account_id=account_id))

    return render_template(
        'certificates/view.html',
        account=account,
        certificate=certificate,
        app_name=app_name,
        cert_id=cert_id
    )


@bp.route('/<int:account_id>/<app_name>/<cert_id>/replace', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute", methods=["POST"])
def replace_certificate(account_id, app_name, cert_id):
    """Replace an existing certificate by uploading a new one, then deleting the old."""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to replace certificates.'), 'danger')
        return redirect(url_for('certificates.list_certificates'))

    account, perm = get_account_for_user(account_id, current_user, min_permission='write')
    if not account or not can_write(perm):
        flash(_('Account not found or insufficient permissions.'), 'danger')
        return redirect(url_for('certificates.list_certificates'))

    client = WaasClient.from_account(account)

    old_cert = None
    try:
        old_cert = client.get_certificate(app_name, cert_id)
    except WaasApiError:
        pass

    form = CertificateUploadForm()

    if form.validate_on_submit():
        try:
            files = {}
            cert_file = form.certificate_file.data
            if cert_file:
                files['certificate'] = (cert_file.filename, cert_file.stream, cert_file.content_type or 'application/octet-stream')

            key_file = form.certificate_key_file.data
            if key_file:
                files['key'] = (key_file.filename, key_file.stream, key_file.content_type or 'application/octet-stream')

            data = {}
            if form.pfx_password.data:
                data['password'] = form.pfx_password.data
            if form.friendly_name.data:
                data['friendly_name'] = form.friendly_name.data

            client.upload_certificate(app_name=app_name, files=files, data=data)
            client.delete_certificate(app_name, cert_id)

            AuditLog.log(
                user_id=current_user.id,
                action='certificate_replace',
                resource_type='certificate',
                details=f'Replaced certificate {cert_id} in app {app_name} on account {account.account_name}',
                ip_address=request.remote_addr
            )

            flash(_('Certificate replaced successfully.'), 'success')
            return redirect(url_for('certificates.list_certificates', account_id=account_id))

        except WaasApiError as e:
            flash(_('Failed to replace certificate: %(error)s', error=str(e)), 'danger')

    return render_template(
        'certificates/replace.html',
        account=account,
        form=form,
        app_name=app_name,
        cert_id=cert_id,
        old_cert=old_cert
    )


@bp.route('/<int:account_id>/<app_name>/<cert_id>/delete', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def delete_certificate(account_id, app_name, cert_id):
    """Delete an SNI certificate (v4 per-application)."""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to delete certificates.'), 'danger')
        return redirect(url_for('certificates.list_certificates'))

    account, perm = get_account_for_user(account_id, current_user, min_permission='write')
    if not account or not can_write(perm):
        flash(_('Account not found or insufficient permissions.'), 'danger')
        return redirect(url_for('certificates.list_certificates'))

    try:
        client = WaasClient.from_account(account)
        client.delete_certificate(app_name, cert_id)

        AuditLog.log(
            user_id=current_user.id,
            action='certificate_delete',
            resource_type='certificate',
            details=f'Deleted certificate {cert_id} from app {app_name} on account {account.account_name}',
            ip_address=request.remote_addr
        )

        flash(_('Certificate deleted.'), 'success')
    except WaasApiError as e:
        flash(_('Failed to delete certificate: %(error)s', error=str(e)), 'danger')

    return redirect(url_for('certificates.list_certificates', account_id=account_id))
