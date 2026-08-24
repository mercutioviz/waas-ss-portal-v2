import copy
import json
import logging
import uuid
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
from flask_babel import gettext as _
from app.models import WaasAccount, AuditLog, ConfigSnapshot, get_user_accounts, get_account_for_user, can_write
from app.waas_client import WaasClient, WaasApiError
from app.forms import ApplicationCreateForm, CloneApplicationForm
from app import limiter, socketio
from app.validators import validate_data, ValidationError
from app.validation_schemas import (
    SERVER_FIELDS, SERVER_SSL_FIELDS, SERVER_HEALTH_FIELDS, SERVER_ADVANCED_FIELDS,
    ENDPOINT_TLS_FIELDS, ENDPOINT_PORT_FIELDS, SECURITY_SECTION_SCHEMAS,
    BULK_SECURITY_ACTIONS,
)
from app.security_dashboard import aggregate_waf_logs
from app.routes.logs import QUICK_RANGES

logger = logging.getLogger(__name__)

bp = Blueprint('applications', __name__, url_prefix='/applications')


def get_client_for_account(account_id, min_permission='read'):
    """Helper to get WaasClient for an account the user can access."""
    account, perm = get_account_for_user(account_id, current_user, min_permission=min_permission)
    if not account:
        return None, None, None
    return WaasClient.from_account(account), account, perm


def _parse_app_list(result):
    """Normalise the raw API list response into a plain Python list."""
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        apps = result.get('results', result.get('data', result.get('applications', [])))
        return apps if isinstance(apps, list) else [result]
    return []


@bp.route('/')
@login_required
def list_applications():
    """List applications — user selects which WaaS account to view."""
    accounts = get_user_accounts(current_user)
    selected_account_id = request.args.get('account_id', type=int)
    api_version = request.args.get('api_version', 'v4')

    applications = []
    selected_account = None
    client = None
    error = None

    if selected_account_id:
        client, selected_account, perm = get_client_for_account(selected_account_id)
        if client:
            try:
                if api_version == 'v2' and selected_account.has_v2_credentials:
                    result = client.list_applications_v2()
                    applications = _parse_app_list(result)
                    logger.info(f'Listed {len(applications)} apps via v2 API')
                else:
                    if api_version == 'v2' and not selected_account.has_v2_credentials:
                        api_version = 'v4'
                        flash(_('v2 credentials not available — using v4 API.'), 'warning')
                    result = client.list_applications()
                    applications = _parse_app_list(result)
                    logger.info(f'Listed {len(applications)} apps via v4 API')

                if applications:
                    first_app = applications[0]
                    logger.info(f'First application keys: {list(first_app.keys()) if isinstance(first_app, dict) else type(first_app).__name__}')
                else:
                    logger.info('No applications returned from API')
            except WaasApiError as e:
                error = str(e)
        else:
            error = _('Account not found or inactive.')

    # Build protection_modes lookup from v2 API data
    protection_modes = {}
    if applications and client and selected_account:
        if api_version == 'v2':
            # v2 response already has basic_security.protection_mode
            for app in applications:
                name = app.get('name', '')
                mode = app.get('basic_security', {}).get('protection_mode')
                if name and mode:
                    protection_modes[name] = mode
        elif selected_account.has_v2_credentials:
            # v4 mode but account has v2 creds — make secondary v2 call
            try:
                v2_result = client.list_applications_v2()
                v2_apps = _parse_app_list(v2_result)
                for app in v2_apps:
                    name = app.get('name', '')
                    mode = app.get('basic_security', {}).get('protection_mode')
                    if name and mode:
                        protection_modes[name] = mode
            except WaasApiError:
                logger.debug('Failed to fetch v2 app list for protection modes')

    # Generate curl command for the list API call
    list_curl = None
    if client and selected_account:
        try:
            if api_version == 'v2' and selected_account.has_v2_credentials:
                list_curl = client.generate_curl_command('GET', '/applications/', api_version='v2')
            else:
                list_curl = client.generate_curl_command('GET', '/applications/')
        except Exception:
            pass

    return render_template(
        'applications/list.html',
        accounts=accounts,
        applications=applications,
        selected_account=selected_account,
        selected_account_id=selected_account_id,
        api_version=api_version,
        error=error,
        list_curl=list_curl,
        protection_modes=protection_modes
    )


@bp.route('/api/list')
@login_required
@limiter.limit("60 per minute")
def api_list_applications():
    """JSON endpoint returning app names for a given account_id."""
    account_id = request.args.get('account_id', type=int)
    if not account_id:
        return jsonify({'applications': [], 'error': 'account_id required'}), 400

    client, account, perm = get_client_for_account(account_id)
    if not client:
        return jsonify({'applications': [], 'error': 'Account not found or inactive'}), 404

    try:
        result = client.list_applications()
        apps = _parse_app_list(result)
        app_list = []
        for app in apps:
            if isinstance(app, dict):
                app_list.append({
                    'name': app.get('name', ''),
                    'app_group': app.get('app_group', ''),
                })

        # Merge v2 integer IDs when account has v2 credentials
        if account.has_v2_credentials:
            try:
                v2_result = client.list_applications_v2()
                v2_apps = _parse_app_list(v2_result)
                v2_map = {}
                for v2_app in v2_apps:
                    if isinstance(v2_app, dict) and v2_app.get('name'):
                        v2_map[v2_app['name']] = v2_app.get('id')
                for item in app_list:
                    item['v2_id'] = v2_map.get(item['name'])
            except WaasApiError:
                pass  # v2 lookup failed — leave v2_id absent

        return jsonify({'applications': app_list, 'has_v2_credentials': account.has_v2_credentials})
    except WaasApiError as e:
        return jsonify({'applications': [], 'error': str(e)}), 500


@bp.route('/<int:account_id>/<app_id>')
@login_required
def view_application(account_id, app_id):
    """View application details (v4 export API)."""
    client, account, perm = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or inactive.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    try:
        application = client.get_application(app_id)
    except WaasApiError as e:
        flash(_('Failed to load application: %(error)s', error=str(e)), 'danger')
        return redirect(url_for('applications.list_applications', account_id=account_id))

    # Look up v2 integer ID for the delete button
    v2_app_id = None
    if account.has_v2_credentials:
        try:
            v2_result = client.list_applications_v2()
            v2_apps = _parse_app_list(v2_result)
            for v2_app in v2_apps:
                if isinstance(v2_app, dict) and v2_app.get('name') == app_id:
                    v2_app_id = v2_app.get('id')
                    break
        except WaasApiError:
            pass  # v2 lookup failed — just hide the delete button

    # Fetch URL access redirect rules
    url_access_rules = []
    try:
        rules_result = client.get_url_access_rules(app_id)
        if isinstance(rules_result, list):
            url_access_rules = rules_result
        elif isinstance(rules_result, dict):
            url_access_rules = rules_result.get('results', rules_result.get('data', []))
    except WaasApiError:
        pass  # feature may not be available

    # Generate curl command
    view_curl = None
    try:
        view_curl = client.generate_curl_command(
            'GET', f'/applications/{app_id}/export/',
            params={'include_servers': 'true', 'include_endpoints': 'true'}
        )
    except Exception:
        pass

    return render_template(
        'applications/view.html',
        account=account,
        application=application,
        app_id=app_id,
        v2_app_id=v2_app_id,
        view_curl=view_curl,
        url_access_rules=url_access_rules
    )


@bp.route('/<int:account_id>/create', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute", methods=["POST"])
def create_application(account_id):
    """Create a new WaaS application via v2 API."""
    client, account, perm = get_client_for_account(account_id, min_permission='write')
    if not client:
        flash(_('Account not found or insufficient permissions.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    if current_user.role == 'viewer':
        flash(_('You do not have permission to create applications.'), 'danger')
        return redirect(url_for('applications.list_applications', account_id=account_id))

    if not can_write(perm):
        flash(_('You do not have write permission on this account.'), 'danger')
        return redirect(url_for('applications.list_applications', account_id=account_id))

    if not account.has_v2_credentials:
        flash(_('Application creation requires v2 API credentials (email + password) on this account.'), 'warning')
        return redirect(url_for('applications.list_applications', account_id=account_id))

    form = ApplicationCreateForm()

    if form.validate_on_submit():
        data = {
            'applicationName': form.application_name.data.strip(),
            'hostnames': [{'hostname': form.hostname.data.strip()}],
            'backendIp': form.backend_ip.data.strip(),
            'backendPort': str(form.backend_port.data),
            'backendType': form.backend_type.data,
            'useExistingIp': True,
            'maliciousTraffic': form.malicious_traffic.data,
            'useHttps': form.use_https.data,
            'useHttp': form.use_http.data,
            'redirectHTTP': form.redirect_http.data,
            'service_type': 'HTTP',
            'container': -1,
        }

        if form.use_https.data:
            data['httpsServicePort'] = '443'
        if form.use_http.data:
            data['httpServicePort'] = '80'

        try:
            result = client.create_application_v2(data)
            app_name = form.application_name.data.strip()

            profile_id = request.form.get('profile_id', type=int)
            details = f'Created application "{app_name}" on account {account.account_name} (v2 API)'
            if profile_id:
                details += f' [source=profiler:{profile_id}]'

            AuditLog.log(
                user_id=current_user.id,
                action='application_create',
                resource_type='application',
                resource_id=app_name,
                details=details,
                ip_address=request.remote_addr
            )

            flash(_('Application "%(name)s" created successfully.', name=app_name), 'success')
            return redirect(url_for('applications.list_applications', account_id=account_id))
        except WaasApiError as e:
            flash(_('Failed to create application: %(error)s', error=str(e)), 'danger')

    # Generate curl command for create endpoint
    create_curl = None
    try:
        placeholder = {
            'applicationName': 'my-app',
            'hostnames': [{'hostname': 'www.example.com'}],
            'backendIp': '10.0.0.1',
            'backendPort': '443',
            'backendType': 'HTTPS',
            'useExistingIp': True,
            'maliciousTraffic': 'Passive',
        }
        create_curl = client.generate_curl_command('POST', '/applications/', data=placeholder, api_version='v2')
    except Exception:
        pass

    return render_template(
        'applications/create.html',
        form=form,
        account=account,
        create_curl=create_curl
    )


@bp.route('/<int:account_id>/<int:app_id>/delete', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def delete_application(account_id, app_id):
    """Delete a WaaS application via v2 API."""
    client, account, perm = get_client_for_account(account_id, min_permission='write')
    if not client or not can_write(perm):
        flash(_('Account not found or insufficient permissions.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    if current_user.role == 'viewer':
        flash(_('You do not have permission to delete applications.'), 'danger')
        return redirect(url_for('applications.list_applications', account_id=account_id))

    if not account.has_v2_credentials:
        flash(_('Application deletion requires v2 API credentials on this account.'), 'warning')
        return redirect(url_for('applications.list_applications', account_id=account_id))

    app_name = request.form.get('app_name', f'ID {app_id}')

    try:
        client.delete_application_v2(app_id)

        AuditLog.log(
            user_id=current_user.id,
            action='application_delete',
            resource_type='application',
            resource_id=str(app_id),
            details=f'Deleted application "{app_name}" (ID {app_id}) from account {account.account_name} (v2 API)',
            ip_address=request.remote_addr
        )

        flash(_('Application "%(name)s" deleted.', name=app_name), 'success')
    except WaasApiError as e:
        flash(_('Failed to delete application: %(error)s', error=str(e)), 'danger')

    return redirect(url_for('applications.list_applications', account_id=account_id))


@bp.route('/<int:account_id>/<app_id>/security')
@login_required
def security_config(account_id, app_id):
    """View/edit security configuration for an application (v4 API)."""
    client, account, perm = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or inactive.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    try:
        application = client.get_application(app_id)
        security = client.get_security_config(app_id)
    except WaasApiError as e:
        flash(_('Failed to load security config: %(error)s', error=str(e)), 'danger')
        return redirect(url_for('applications.view_application', account_id=account_id, app_id=app_id))

    # Generate curl command for security endpoints
    security_curl = None
    try:
        security_curl = client.generate_curl_command('GET', f'/applications/{app_id}/basic_security/')
    except Exception:
        pass

    return render_template(
        'applications/security.html',
        account=account,
        application=application,
        security=security,
        app_id=app_id,
        security_curl=security_curl
    )


@bp.route('/<int:account_id>/<app_id>/security', methods=['POST'])
@login_required
def update_security_config(account_id, app_id):
    """Update security configuration (v4 API)."""
    client, account, perm = get_client_for_account(account_id, min_permission='write')
    if not client or not can_write(perm):
        flash(_('Account not found or insufficient permissions.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    if current_user.role == 'viewer':
        flash(_('You do not have permission to modify configurations.'), 'danger')
        return redirect(url_for('applications.security_config', account_id=account_id, app_id=app_id))

    section_getters = {
        'basic_security': client.get_basic_security,
        'request_limits': client.get_request_limits,
        'clickjacking_protection': client.get_clickjacking_protection,
        'data_theft_protection': client.get_data_theft_protection,
    }

    try:
        data = request.get_json() if request.is_json else request.form.to_dict()
        section = data.pop('section', 'basic_security')

        try:
            payload_before = section_getters.get(section, client.get_basic_security)(app_id)
        except WaasApiError:
            payload_before = {}

        if section == 'request_limits':
            int_data = {}
            for k, v in data.items():
                if k == 'csrf_token':
                    continue
                try:
                    int_data[k] = int(v)
                except (ValueError, TypeError):
                    int_data[k] = v
            client.update_request_limits(app_id, int_data)
            payload_applied = int_data
        elif section == 'clickjacking_protection':
            bool_data = {k: (v == 'true' or v is True) for k, v in data.items() if k != 'csrf_token'}
            client.update_clickjacking_protection(app_id, bool_data)
            payload_applied = bool_data
        elif section == 'data_theft_protection':
            bool_data = {k: (v == 'true' or v is True) for k, v in data.items() if k != 'csrf_token'}
            client.update_data_theft_protection(app_id, bool_data)
            payload_applied = bool_data
        else:
            data.pop('csrf_token', None)
            client.update_security_config(app_id, data)
            payload_applied = data

        ConfigSnapshot.record(
            user_id=current_user.id,
            account_id=account.id,
            app_id=app_id,
            resource_type='security_config_update',
            payload_before=payload_before,
            section=section,
            payload_applied=payload_applied
        )

        section_labels = {
            'basic_security': 'protection mode',
            'request_limits': 'request limits',
            'clickjacking_protection': 'clickjacking protection',
            'data_theft_protection': 'data theft protection',
        }
        section_label = section_labels.get(section, section)

        AuditLog.log(
            user_id=current_user.id,
            action='security_config_update',
            resource_type='application',
            resource_id=None,
            details=f'Updated {section_label} for app {app_id} on account {account.account_name}',
            ip_address=request.remote_addr
        )

        flash(_('Security configuration updated.'), 'success')
    except WaasApiError as e:
        flash(_('Failed to update security config: %(error)s', error=str(e)), 'danger')

    return redirect(url_for('applications.security_config', account_id=account_id, app_id=app_id))


@bp.route('/api/<int:account_id>/<app_id>/config')
@login_required
@limiter.limit("60 per minute")
def api_get_application_config(account_id, app_id):
    """JSON endpoint returning security config for an application."""
    client, account, perm = get_client_for_account(account_id)
    if not client:
        return jsonify({'success': False, 'error': 'Account not found or inactive'}), 404

    try:
        config = client.get_security_config(app_id)
        return jsonify({'success': True, 'config': config})
    except WaasApiError as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/<int:account_id>/compare')
@login_required
def compare_applications(account_id):
    """Compare security configs of two applications side-by-side."""
    client, account, perm = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or inactive.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    apps_param = request.args.get('apps', '')
    app_names = [a.strip() for a in apps_param.split(',') if a.strip()]
    if len(app_names) != 2:
        flash(_('Please select exactly 2 applications to compare.'), 'warning')
        return redirect(url_for('applications.list_applications', account_id=account_id))

    configs = {}
    app_details = {}
    for name in app_names:
        try:
            app_details[name] = client.get_application(name)
            configs[name] = client.get_security_config(name)
        except WaasApiError as e:
            flash(_('Failed to load config for %(name)s: %(error)s', name=name, error=str(e)), 'danger')
            return redirect(url_for('applications.list_applications', account_id=account_id))

    return render_template(
        'applications/compare.html',
        account=account,
        app_names=app_names,
        app_details=app_details,
        configs=configs
    )


@bp.route('/<int:account_id>/<app_id>/dns')
@login_required
def dns_info(account_id, app_id):
    """View DNS/CNAME information for an application (v4 API)."""
    client, account, perm = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or inactive.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    try:
        application = client.get_application(app_id)
        endpoints = application.get('endpoints', {})
        dns = {
            'cname': endpoints.get('cname', ''),
            'domains': endpoints.get('domains', []),
            'deployment': endpoints.get('deployment', {}),
        }
    except WaasApiError as e:
        flash(_('Failed to load DNS info: %(error)s', error=str(e)), 'danger')
        return redirect(url_for('applications.view_application', account_id=account_id, app_id=app_id))

    return render_template(
        'applications/dns.html',
        account=account,
        application=application,
        dns=dns,
        app_id=app_id
    )


@bp.route('/<int:account_id>/<app_id>/dashboard')
@login_required
def security_dashboard(account_id, app_id):
    """Per-app security dashboard: page shell only — data loads via AJAX."""
    client, account, perm = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or inactive.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    return render_template(
        'applications/security_dashboard.html',
        account=account,
        app_id=app_id,
    )


@bp.route('/<int:account_id>/<app_id>/dashboard/data')
@login_required
def security_dashboard_data(account_id, app_id):
    """JSON endpoint polled by the security dashboard page."""
    client, account, perm = get_client_for_account(account_id)
    if not client:
        return jsonify({'error': 'Account not found or inactive.'}), 404

    valid_ranges = {value for value, _label in QUICK_RANGES}
    quick_range = request.args.get('quick_range', 'r_1h')
    if quick_range not in valid_ranges:
        quick_range = 'r_1h'

    try:
        result = client.get_logs(
            app_id,
            quick_range=quick_range,
            items_per_page=1000,
            filter_fields={'LogType': [{'condition': 'is', 'value': 'WF'}]},
        )
    except WaasApiError as e:
        return jsonify({'error': str(e)}), 502

    logs = result.get('results', []) if isinstance(result, dict) else []
    total_from_api = result.get('count', len(logs)) if isinstance(result, dict) else len(logs)

    data = aggregate_waf_logs(logs, quick_range, total_from_api=total_from_api)
    data['quick_range'] = quick_range
    return jsonify(data)


# ---- Phase 8: Configuration Editing & Bulk Operations ----

@bp.route('/<int:account_id>/<app_id>/servers/update', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def update_server(account_id, app_id):
    """Update a backend server configuration via import_application (PATCH merge)."""
    client, account, perm = get_client_for_account(account_id, min_permission='write')
    if not client or not can_write(perm):
        return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403

    data = request.get_json()
    if not data or 'server_name' not in data or 'fields' not in data:
        return jsonify({'success': False, 'error': 'server_name and fields required'}), 400

    server_name = data['server_name']
    fields = data['fields']

    # Validate fields against schemas
    try:
        validated_fields = {}
        for key, value in fields.items():
            if key == 'ssl' and isinstance(value, dict):
                validated_fields['ssl'] = validate_data(value, SERVER_SSL_FIELDS)
            elif key == 'health_checks' and isinstance(value, dict):
                validated_fields['health_checks'] = validate_data(value, SERVER_HEALTH_FIELDS)
            elif key == 'advanced' and isinstance(value, dict):
                validated_fields['advanced'] = validate_data(value, SERVER_ADVANCED_FIELDS)
            elif key in SERVER_FIELDS:
                validated_fields[key] = SERVER_FIELDS[key].validate(value, key)
            # Unknown top-level fields are silently dropped
        fields = validated_fields
    except ValidationError as e:
        return jsonify({'success': False, 'error': 'Validation failed', 'fields': e.errors}), 400
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400

    try:
        application = client.get_application(app_id)
        servers = application.get('servers', [])
        payload_before = copy.deepcopy(servers)

        found = False
        for server in servers:
            if server.get('name') == server_name:
                # Merge fields into the server, handling nested ssl/health_checks/advanced
                for key, value in fields.items():
                    if key == 'ssl' and isinstance(value, dict) and isinstance(server.get('ssl'), dict):
                        server['ssl'].update(value)
                    elif key == 'health_checks' and isinstance(value, dict) and isinstance(server.get('health_checks'), dict):
                        server['health_checks'].update(value)
                    elif key == 'advanced' and isinstance(value, dict) and isinstance(server.get('advanced'), dict):
                        server['advanced'].update(value)
                    else:
                        server[key] = value
                found = True
                break

        if not found:
            return jsonify({'success': False, 'error': f'Server "{server_name}" not found'}), 404

        client.import_application(app_id, {'servers': servers}, include_servers=True)

        ConfigSnapshot.record(
            user_id=current_user.id,
            account_id=account.id,
            app_id=app_id,
            resource_type='server_update',
            payload_before=payload_before,
            resource_label=server_name,
            payload_applied=servers
        )

        AuditLog.log(
            user_id=current_user.id,
            action='server_update',
            resource_type='application',
            resource_id=app_id,
            details=f'Updated server "{server_name}" for app {app_id} on account {account.account_name}',
            ip_address=request.remote_addr
        )

        return jsonify({'success': True})
    except WaasApiError as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/<int:account_id>/<app_id>/endpoints/update', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def update_endpoints(account_id, app_id):
    """Update endpoint / frontend TLS configuration via import_application."""
    client, account, perm = get_client_for_account(account_id, min_permission='write')
    if not client or not can_write(perm):
        return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403

    data = request.get_json()
    if not data or 'section' not in data or 'data' not in data:
        return jsonify({'success': False, 'error': 'section and data required'}), 400

    section = data['section']
    payload = data['data']

    # Validate payload against endpoint schemas
    try:
        if section == 'tls':
            payload = validate_data(payload, ENDPOINT_TLS_FIELDS)
        elif section == 'ports':
            payload = validate_data(payload, ENDPOINT_PORT_FIELDS)
    except ValidationError as e:
        return jsonify({'success': False, 'error': 'Validation failed', 'fields': e.errors}), 400

    api_version = 'v4'  # Currently endpoints update uses v4 only
    api_method = 'PATCH'
    api_path = f'/applications/{app_id}/endpoints/'

    try:
        application = client.get_application(app_id)
        endpoints = application.get('endpoints', {})
        payload_before = copy.deepcopy(endpoints)

        if section == 'tls':
            # Merge user payload into the full exported https config
            https_cfg = endpoints.get('https', {})
            https_cfg.update(payload)
            api_payload = {'https': https_cfg}
        elif section == 'ports':
            port_num = payload.pop('port', None)
            ports = endpoints.get('ports', [])
            for p in ports:
                if p.get('port') == port_num:
                    adv = p.get('advanced_configuration', {})
                    adv.update(payload)
                    p['advanced_configuration'] = adv
                    break
            api_payload = {'ports': ports}
        else:
            return jsonify({'success': False, 'error': f'Unknown section: {section}'}), 400

        result = client.update_application_endpoints(app_id, api_payload)

        ConfigSnapshot.record(
            user_id=current_user.id,
            account_id=account.id,
            app_id=app_id,
            resource_type='endpoint_update',
            payload_before=payload_before,
            section=section,
            payload_applied=api_payload
        )

        AuditLog.log(
            user_id=current_user.id,
            action='endpoint_update',
            resource_type='application',
            resource_id=app_id,
            details=f'Updated {section} settings for app {app_id} on account {account.account_name}',
            ip_address=request.remote_addr
        )

        return jsonify({
            'success': True,
            'api': {'version': api_version, 'method': api_method, 'path': api_path}
        })
    except WaasApiError as e:
        error_detail = str(e)
        if e.response_data and isinstance(e.response_data, dict) and 'raw' not in e.response_data:
            error_detail = f'{error_detail}: {e.response_data}'
        return jsonify({
            'success': False,
            'error': error_detail,
            'api': {
                'version': api_version,
                'method': e.request_method or api_method,
                'path': e.request_url or api_path,
                'status': e.status_code,
                'response': e.response_data if (e.response_data and 'raw' not in (e.response_data if isinstance(e.response_data, dict) else {})) else None,
            }
        }), 400
    except Exception as e:
        logger.exception(f'Unexpected error updating endpoints for {app_id}')
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/<int:account_id>/<app_id>/security/ajax', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def security_ajax_update(account_id, app_id):
    """AJAX endpoint for inline security field updates."""
    client, account, perm = get_client_for_account(account_id, min_permission='write')
    if not client or not can_write(perm):
        return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403

    data = request.get_json()
    if not data or 'section' not in data or 'field' not in data:
        return jsonify({'success': False, 'error': 'section, field, and value required'}), 400

    section = data['section']
    field = data['field']
    value = data.get('value')

    # Validate field against section schema
    schema = SECURITY_SECTION_SCHEMAS.get(section)
    if schema:
        validator = schema.get(field)
        if validator:
            try:
                value = validator.validate(value, field)
            except ValueError as e:
                return jsonify({'success': False, 'error': str(e)}), 400

    section_getters = {
        'basic_security': client.get_basic_security,
        'request_limits': client.get_request_limits,
        'clickjacking_protection': client.get_clickjacking_protection,
        'data_theft_protection': client.get_data_theft_protection,
    }
    getter = section_getters.get(section)
    if not getter:
        return jsonify({'success': False, 'error': f'Unknown section: {section}'}), 400

    try:
        payload_before = getter(app_id)
    except WaasApiError:
        payload_before = {}

    try:
        if section == 'basic_security':
            client.update_security_config(app_id, {field: value})
        elif section == 'request_limits':
            try:
                value = int(value)
            except (ValueError, TypeError):
                pass
            client.update_request_limits(app_id, {field: value})
        elif section == 'clickjacking_protection':
            value = value if isinstance(value, bool) else (str(value).lower() == 'true')
            client.update_clickjacking_protection(app_id, {field: value})
        elif section == 'data_theft_protection':
            value = value if isinstance(value, bool) else (str(value).lower() == 'true')
            client.update_data_theft_protection(app_id, {field: value})
        else:
            return jsonify({'success': False, 'error': f'Unknown section: {section}'}), 400

        ConfigSnapshot.record(
            user_id=current_user.id,
            account_id=account.id,
            app_id=app_id,
            resource_type='security_config_update',
            payload_before=payload_before,
            section=section,
            payload_applied={field: value}
        )

        AuditLog.log(
            user_id=current_user.id,
            action='security_config_update',
            resource_type='application',
            resource_id=app_id,
            details=f'Updated {section}.{field}={value} for app {app_id} on account {account.account_name}',
            ip_address=request.remote_addr
        )

        return jsonify({'success': True, 'field': field, 'value': value})
    except WaasApiError as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/<int:account_id>/<app_id>/clone', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute", methods=["POST"])
def clone_application(account_id, app_id):
    """Clone an existing application."""
    client, account, perm = get_client_for_account(account_id, min_permission='write')
    if not client or not can_write(perm):
        flash(_('Account not found or insufficient permissions.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    if not account.has_v2_credentials:
        flash(_('Application cloning requires v2 API credentials (email + password).'), 'warning')
        return redirect(url_for('applications.view_application', account_id=account_id, app_id=app_id))

    try:
        source_app = client.get_application(app_id)
    except WaasApiError as e:
        flash(_('Failed to load source application: %(error)s', error=str(e)), 'danger')
        return redirect(url_for('applications.view_application', account_id=account_id, app_id=app_id))

    # Extract defaults from source
    source_servers = source_app.get('servers', [])
    default_backend_ip = source_servers[0].get('host', '') if source_servers else ''
    default_backend_port = source_servers[0].get('port', 443) if source_servers else 443
    default_backend_type = source_servers[0].get('protocol', 'HTTPS') if source_servers else 'HTTPS'

    form = CloneApplicationForm(
        backend_ip=default_backend_ip,
        backend_port=default_backend_port,
        backend_type=default_backend_type,
    )

    api_error = None

    if form.validate_on_submit():
        create_data = {
            'applicationName': form.new_name.data.strip(),
            'hostnames': [{'hostname': form.new_hostname.data.strip()}],
            'backendIp': form.backend_ip.data.strip(),
            'backendPort': str(form.backend_port.data),
            'backendType': form.backend_type.data,
            'useExistingIp': True,
            'maliciousTraffic': 'Passive',
            'useHttps': True,
            'useHttp': True,
            'service_type': 'HTTP',
            'httpServicePort': '80',
            'httpsServicePort': '443',
            'redirectHTTP': True,
            'container': -1,
        }

        new_app_name = form.new_name.data.strip()
        use_websocket = request.form.get('use_websocket') == '1'

        if use_websocket:
            session_id = str(uuid.uuid4())
            clone_servers = form.clone_servers.data
            clone_endpoints = form.clone_endpoints.data
            clone_security = form.clone_security.data

            # Resolve translated step names while still in request context
            create_step_name = str(_('Create application'))
            import_step_name = str(_('Import configuration'))
            security_step_name = str(_('Copy security settings'))

            step_names = [create_step_name]
            if clone_servers or clone_endpoints:
                step_names.append(import_step_name)
            if clone_security:
                step_names.append(security_step_name)

            # Capture app reference for background task context
            app = current_app._get_current_object()

            def _bg_clone():
                with app.app_context():
                    try:
                        import time
                        time.sleep(2)  # Wait for client to connect and join room
                        from app.background_tasks import run_clone_operation

                        steps = []

                        # Step 1: Create
                        def _create():
                            client.create_application_v2(create_data)
                            return {'status': 'success'}
                        steps.append({'name': create_step_name, 'func': _create})

                        # Step 2: Import
                        if clone_servers or clone_endpoints:
                            def _import():
                                import_data = {}
                                if clone_servers:
                                    import_data['servers'] = source_app.get('servers', [])
                                if clone_endpoints:
                                    import_data['endpoints'] = source_app.get('endpoints', {})
                                client.import_application(
                                    new_app_name, import_data,
                                    include_servers=clone_servers,
                                    include_endpoints=clone_endpoints
                                )
                                return {'status': 'success'}
                            steps.append({'name': import_step_name, 'func': _import})

                        # Step 3: Security
                        if clone_security:
                            def _security():
                                security = client.get_security_config(app_id)
                                mode = security.get('protection_mode')
                                if mode:
                                    client.update_security_config(new_app_name, {'protection_mode': mode})
                                rl = security.get('request_limits', {})
                                if rl:
                                    client.update_request_limits(new_app_name, rl)
                                cj = security.get('clickjacking_protection', {})
                                if cj:
                                    client.update_clickjacking_protection(new_app_name, cj)
                                dtp = security.get('data_theft_protection', {})
                                if dtp:
                                    client.update_data_theft_protection(new_app_name, dtp)
                                return {'status': 'success'}
                            steps.append({'name': security_step_name, 'func': _security})

                        logger.info(f'Calling run_clone_operation with {len(steps)} steps')
                        run_clone_operation(session_id, steps)
                        logger.info(f'Background clone task completed for session {session_id}')
                    except Exception as e:
                        logger.error(f'Background clone task exception: {e}', exc_info=True)
                        socketio.emit('clone_progress', {
                            'phase': 'aborted',
                            'reason': f'Internal error: {str(e)}',
                            'results': [],
                        }, room=session_id)

            socketio.start_background_task(_bg_clone)

            return render_template(
                'applications/clone_progress.html',
                session_id=session_id,
                source_name=app_id,
                new_name=new_app_name,
                account_id=account_id,
                step_names=step_names,
            )

        # Synchronous fallback
        try:
            # Step 1: Create the new app shell via v2
            result = client.create_application_v2(create_data)

            # Step 2: Import source config sections into new app
            import_data = {}
            if form.clone_servers.data:
                import_data['servers'] = source_app.get('servers', [])
            if form.clone_endpoints.data:
                import_data['endpoints'] = source_app.get('endpoints', {})

            if import_data:
                try:
                    client.import_application(
                        new_app_name, import_data,
                        include_servers=form.clone_servers.data,
                        include_endpoints=form.clone_endpoints.data
                    )
                except WaasApiError as e:
                    logger.warning(f'Clone import partial failure: {e}')
                    flash(_('Application created but some config import failed: %(error)s', error=str(e)), 'warning')

            # Step 3: Clone security config if requested
            if form.clone_security.data:
                try:
                    security = client.get_security_config(app_id)
                    mode = security.get('protection_mode')
                    if mode:
                        client.update_security_config(new_app_name, {'protection_mode': mode})
                    rl = security.get('request_limits', {})
                    if rl:
                        client.update_request_limits(new_app_name, rl)
                    cj = security.get('clickjacking_protection', {})
                    if cj:
                        client.update_clickjacking_protection(new_app_name, cj)
                    dtp = security.get('data_theft_protection', {})
                    if dtp:
                        client.update_data_theft_protection(new_app_name, dtp)
                except WaasApiError as e:
                    logger.warning(f'Clone security config partial failure: {e}')
                    flash(_('Security config partially cloned: %(error)s', error=str(e)), 'warning')

            AuditLog.log(
                user_id=current_user.id,
                action='application_clone',
                resource_type='application',
                resource_id=new_app_name,
                details=f'Cloned app "{app_id}" to "{new_app_name}" on account {account.account_name}',
                ip_address=request.remote_addr
            )

            flash(_('Application "%(name)s" cloned successfully.', name=new_app_name), 'success')
            return redirect(url_for('applications.view_application', account_id=account_id, app_id=new_app_name))

        except WaasApiError as e:
            flash(_('Failed to clone application: %(error)s', error=str(e)), 'danger')
            api_error = {
                'message': str(e),
                'status_code': e.status_code,
                'method': e.request_method,
                'url': e.request_url,
                'request_data': e.request_data,
                'response_data': e.response_data,
            }

    return render_template(
        'applications/clone.html',
        form=form,
        account=account,
        source_app=source_app,
        app_id=app_id,
        api_error=api_error
    )


@bp.route('/bulk-security', methods=['GET'])
@login_required
def bulk_security(account_id=None):
    """Bulk security operations page."""
    accounts = get_user_accounts(current_user)
    return render_template('applications/bulk_security.html', accounts=accounts)


# ---- URL Access & Redirects CRUD ----

@bp.route('/<int:account_id>/<app_id>/url-access-rules/create', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def create_url_access_rule(account_id, app_id):
    """Create a new URL access redirect rule."""
    client, account, perm = get_client_for_account(account_id, min_permission='write')
    if not client or not can_write(perm):
        return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'Request body required'}), 400

    try:
        result = client.create_url_access_rule(app_id, data)

        AuditLog.log(
            user_id=current_user.id,
            action='url_access_rule_create',
            resource_type='application',
            resource_id=app_id,
            details=f'Created URL access rule for app {app_id} on account {account.account_name}',
            ip_address=request.remote_addr
        )

        return jsonify({'success': True, 'data': result})
    except WaasApiError as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/<int:account_id>/<app_id>/url-access-rules/update', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def update_url_access_rule(account_id, app_id):
    """Update an existing URL access redirect rule."""
    client, account, perm = get_client_for_account(account_id, min_permission='write')
    if not client or not can_write(perm):
        return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403

    data = request.get_json()
    if not data or 'rule_name' not in data or 'fields' not in data:
        return jsonify({'success': False, 'error': 'rule_name and fields required'}), 400

    rule_name = data['rule_name']
    fields = data['fields']

    try:
        result = client.update_url_access_rule(app_id, rule_name, fields)

        AuditLog.log(
            user_id=current_user.id,
            action='url_access_rule_update',
            resource_type='application',
            resource_id=app_id,
            details=f'Updated URL access rule "{rule_name}" for app {app_id} on account {account.account_name}',
            ip_address=request.remote_addr
        )

        return jsonify({'success': True, 'data': result})
    except WaasApiError as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/<int:account_id>/<app_id>/url-access-rules/delete', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def delete_url_access_rule(account_id, app_id):
    """Delete a URL access redirect rule."""
    client, account, perm = get_client_for_account(account_id, min_permission='write')
    if not client or not can_write(perm):
        return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403

    data = request.get_json()
    if not data or 'rule_name' not in data:
        return jsonify({'success': False, 'error': 'rule_name required'}), 400

    rule_name = data['rule_name']

    try:
        client.delete_url_access_rule(app_id, rule_name)

        AuditLog.log(
            user_id=current_user.id,
            action='url_access_rule_delete',
            resource_type='application',
            resource_id=app_id,
            details=f'Deleted URL access rule "{rule_name}" for app {app_id} on account {account.account_name}',
            ip_address=request.remote_addr
        )

        return jsonify({'success': True})
    except WaasApiError as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/bulk-security', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def bulk_security_execute():
    """Execute a bulk security operation on selected applications."""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to modify configurations.'), 'danger')
        return redirect(url_for('applications.bulk_security'))

    action = request.form.get('action')
    app_selections = request.form.getlist('apps')  # format: "account_id:app_name"

    if not action or not app_selections:
        flash(_('Please select an action and at least one application.'), 'warning')
        return redirect(url_for('applications.bulk_security'))

    if action not in BULK_SECURITY_ACTIONS:
        flash(_('Invalid action selected.'), 'danger')
        return redirect(url_for('applications.bulk_security'))

    # Define bulk actions
    actions = {
        'protection_mode_active': {
            'label': _('Protection Mode -> Active'),
            'method': 'security',
            'data': {'protection_mode': 'Active'},
        },
        'protection_mode_passive': {
            'label': _('Protection Mode -> Passive'),
            'method': 'security',
            'data': {'protection_mode': 'Passive'},
        },
        'enable_tls_1_3': {
            'label': _('Enable TLS 1.3 (Frontend)'),
            'method': 'endpoints',
            'data': {'https': {'enable_tls_1_3': True}},
        },
        'disable_tls_1': {
            'label': _('Disable TLS 1.0 (Frontend)'),
            'method': 'endpoints',
            'data': {'https': {'enable_tls_1': False}},
        },
        'enable_pfs': {
            'label': _('Enable PFS'),
            'method': 'endpoints',
            'data': {'https': {'enable_pfs': True}},
        },
    }

    if action not in actions:
        flash(_('Unknown action.'), 'danger')
        return redirect(url_for('applications.bulk_security'))

    action_info = actions[action]
    use_websocket = request.form.get('use_websocket') == '1'
    batch_id = str(uuid.uuid4())

    def _execute_bulk(action_info, app_selections, user_id, remote_addr, batch_id):
        """Execute bulk operation (runs synchronously or in background)."""
        results = []
        for selection in app_selections:
            parts = selection.split(':', 1)
            if len(parts) != 2:
                continue
            acct_id, app_name = int(parts[0]), parts[1]

            client, account, perm = get_client_for_account(acct_id, min_permission='write')
            if not client or not can_write(perm):
                results.append({
                    'app_name': app_name,
                    'account_name': f'Account #{acct_id}',
                    'status': 'error',
                    'error': 'Insufficient permissions',
                })
                continue

            try:
                if action_info['method'] == 'security':
                    try:
                        payload_before = client.get_basic_security(app_name)
                    except WaasApiError:
                        payload_before = {}
                    client.update_security_config(app_name, action_info['data'])
                    ConfigSnapshot.record(
                        user_id=user_id, account_id=acct_id, app_id=app_name,
                        resource_type='bulk_security_update', payload_before=payload_before,
                        resource_label=str(action_info['label']), section='basic_security',
                        payload_applied=action_info['data'], batch_id=batch_id
                    )
                elif action_info['method'] == 'endpoints':
                    app_export = client.get_application(app_name)
                    endpoints = app_export.get('endpoints', {})
                    payload_before = copy.deepcopy(endpoints)
                    for key, value in action_info['data'].items():
                        if isinstance(value, dict) and isinstance(endpoints.get(key), dict):
                            endpoints[key].update(value)
                        else:
                            endpoints[key] = value
                    client.import_application(app_name, {'endpoints': endpoints}, include_endpoints=True)
                    ConfigSnapshot.record(
                        user_id=user_id, account_id=acct_id, app_id=app_name,
                        resource_type='bulk_security_update', payload_before=payload_before,
                        resource_label=str(action_info['label']), section='endpoints',
                        payload_applied=endpoints, batch_id=batch_id
                    )

                results.append({
                    'app_name': app_name,
                    'account_name': account.account_name,
                    'status': 'success',
                    'error': None,
                })
            except WaasApiError as e:
                results.append({
                    'app_name': app_name,
                    'account_name': account.account_name,
                    'status': 'error',
                    'error': str(e),
                })
        return results

    if use_websocket:
        session_id = str(uuid.uuid4())
        total = len(app_selections)

        # Resolve translated label and capture app ref while in request context
        bulk_op_name = str(action_info['label'])
        bulk_user_id = current_user.id
        app = current_app._get_current_object()

        # Pre-build clients per account while current_user is available
        account_clients = {}
        items = []
        for sel in app_selections:
            parts = sel.split(':', 1)
            label = parts[1] if len(parts) == 2 else sel
            items.append({'selection': sel, 'label': label})
            if len(parts) == 2:
                acct_id = int(parts[0])
                if acct_id not in account_clients:
                    client, account, perm = get_client_for_account(acct_id, min_permission='write')
                    account_clients[acct_id] = (client, perm)

        def _bg_bulk():
            with app.app_context():
                from app.background_tasks import run_bulk_operation

                def _op(item):
                    sel = item['selection']
                    parts = sel.split(':', 1)
                    if len(parts) != 2:
                        return {'status': 'error', 'error': 'Invalid format'}
                    acct_id, app_name = int(parts[0]), parts[1]

                    client, perm = account_clients.get(acct_id, (None, None))
                    if not client or not can_write(perm):
                        return {'status': 'error', 'error': 'Insufficient permissions'}

                    try:
                        if action_info['method'] == 'security':
                            try:
                                payload_before = client.get_basic_security(app_name)
                            except WaasApiError:
                                payload_before = {}
                            client.update_security_config(app_name, action_info['data'])
                            ConfigSnapshot.record(
                                user_id=bulk_user_id, account_id=acct_id, app_id=app_name,
                                resource_type='bulk_security_update', payload_before=payload_before,
                                resource_label=bulk_op_name, section='basic_security',
                                payload_applied=action_info['data'], batch_id=batch_id
                            )
                        elif action_info['method'] == 'endpoints':
                            app_export = client.get_application(app_name)
                            endpoints = app_export.get('endpoints', {})
                            payload_before = copy.deepcopy(endpoints)
                            for key, value in action_info['data'].items():
                                if isinstance(value, dict) and isinstance(endpoints.get(key), dict):
                                    endpoints[key].update(value)
                                else:
                                    endpoints[key] = value
                            client.import_application(app_name, {'endpoints': endpoints}, include_endpoints=True)
                            ConfigSnapshot.record(
                                user_id=bulk_user_id, account_id=acct_id, app_id=app_name,
                                resource_type='bulk_security_update', payload_before=payload_before,
                                resource_label=bulk_op_name, section='endpoints',
                                payload_applied=endpoints, batch_id=batch_id
                            )
                        return {'status': 'success'}
                    except WaasApiError as e:
                        return {'status': 'error', 'error': str(e)}

                run_bulk_operation(session_id, items, _op, name=bulk_op_name)

        socketio.start_background_task(_bg_bulk)

        return render_template(
            'applications/bulk_security_progress.html',
            session_id=session_id,
            action_label=action_info['label'],
            total=total,
        )

    # Synchronous fallback
    results = _execute_bulk(action_info, app_selections, current_user.id, request.remote_addr, batch_id)

    total = len(results)
    succeeded = sum(1 for r in results if r['status'] == 'success')
    failed = total - succeeded

    AuditLog.log(
        user_id=current_user.id,
        action='bulk_security_update',
        resource_type='application',
        resource_id=None,
        details=f'Bulk security: {action} on {total} apps ({succeeded} ok, {failed} failed)',
        ip_address=request.remote_addr
    )

    return render_template(
        'applications/bulk_security_results.html',
        action_label=action_info['label'],
        results=results,
        total=total,
        succeeded=succeeded,
        failed=failed,
    )


# ---- Bulk Delete ----

@bp.route('/bulk-delete', methods=['GET'])
@bp.route('/bulk-delete/<int:account_id>', methods=['GET'])
@login_required
def bulk_delete(account_id=None):
    """Bulk delete applications page."""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to delete applications.'), 'danger')
        return redirect(url_for('applications.list_applications'))
    accounts = get_user_accounts(current_user)
    # Only show accounts with v2 credentials (required for deletion)
    v2_accounts = [a for a in accounts if a.has_v2_credentials]
    return render_template('applications/bulk_delete.html', accounts=v2_accounts, all_accounts=accounts)


@bp.route('/bulk-delete', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def bulk_delete_execute():
    """Execute a bulk delete operation on selected applications."""
    if current_user.role == 'viewer':
        flash(_('You do not have permission to delete applications.'), 'danger')
        return redirect(url_for('applications.bulk_delete'))

    app_selections = request.form.getlist('apps')  # format: "account_id:v2_id:app_name"

    if not app_selections:
        flash(_('Please select at least one application to delete.'), 'warning')
        return redirect(url_for('applications.bulk_delete'))

    use_websocket = request.form.get('use_websocket') == '1'

    if use_websocket:
        session_id = str(uuid.uuid4())
        total = len(app_selections)

        app = current_app._get_current_object()

        # Pre-build clients per account while current_user is available
        account_clients = {}
        items = []
        for sel in app_selections:
            parts = sel.split(':', 2)
            label = parts[2] if len(parts) == 3 else sel
            items.append({'selection': sel, 'label': label})
            if len(parts) >= 2:
                acct_id = int(parts[0])
                if acct_id not in account_clients:
                    client, account, perm = get_client_for_account(acct_id, min_permission='write')
                    account_clients[acct_id] = (client, account, perm)

        def _bg_bulk():
            with app.app_context():
                from app.background_tasks import run_bulk_operation

                def _op(item):
                    sel = item['selection']
                    parts = sel.split(':', 2)
                    if len(parts) != 3:
                        return {'status': 'error', 'error': 'Invalid format'}
                    acct_id, v2_id, app_name = int(parts[0]), parts[1], parts[2]

                    client, account, perm = account_clients.get(acct_id, (None, None, None))
                    if not client or not can_write(perm):
                        return {'status': 'error', 'error': 'Insufficient permissions'}

                    if not account.has_v2_credentials:
                        return {'status': 'error', 'error': 'v2 credentials required'}

                    try:
                        client.delete_application_v2(v2_id)
                        return {'status': 'success'}
                    except WaasApiError as e:
                        return {'status': 'error', 'error': str(e)}

                run_bulk_operation(session_id, items, _op, name='Bulk Delete Applications')

        socketio.start_background_task(_bg_bulk)

        return render_template(
            'applications/bulk_delete_progress.html',
            session_id=session_id,
            total=total,
        )

    # Synchronous fallback
    results = []
    for sel in app_selections:
        parts = sel.split(':', 2)
        if len(parts) != 3:
            continue
        acct_id, v2_id, app_name = int(parts[0]), parts[1], parts[2]

        client, account, perm = get_client_for_account(acct_id, min_permission='write')
        if not client or not can_write(perm):
            results.append({
                'app_name': app_name,
                'account_name': f'Account #{acct_id}',
                'status': 'error',
                'error': 'Insufficient permissions',
            })
            continue

        if not account.has_v2_credentials:
            results.append({
                'app_name': app_name,
                'account_name': account.account_name,
                'status': 'error',
                'error': 'v2 credentials required',
            })
            continue

        try:
            client.delete_application_v2(v2_id)
            results.append({
                'app_name': app_name,
                'account_name': account.account_name,
                'status': 'success',
                'error': None,
            })
        except WaasApiError as e:
            results.append({
                'app_name': app_name,
                'account_name': account.account_name,
                'status': 'error',
                'error': str(e),
            })

    total = len(results)
    succeeded = sum(1 for r in results if r['status'] == 'success')
    failed = total - succeeded

    AuditLog.log(
        user_id=current_user.id,
        action='bulk_delete',
        resource_type='application',
        resource_id=None,
        details=f'Bulk delete: {total} apps ({succeeded} ok, {failed} failed)',
        ip_address=request.remote_addr
    )

    return render_template(
        'applications/bulk_delete_results.html',
        results=results,
        total=total,
        succeeded=succeeded,
        failed=failed,
    )


# ---- Traffic Rewrites ----

def _get_all_rewrites(client, app_id):
    """Fetch all four rewrite types, silently returning empty lists on error."""
    def safe_get(fn):
        try:
            result = fn()
            if isinstance(result, list):
                return result
            if isinstance(result, dict):
                return result.get('results', result.get('data', []))
            return []
        except WaasApiError:
            return []

    return {
        'request': safe_get(lambda: client.get_request_rewrites(app_id)),
        'response': safe_get(lambda: client.get_response_rewrites(app_id)),
        'body': safe_get(lambda: client.get_response_body_rewrites(app_id)),
        'url_translation': safe_get(lambda: client.get_url_translations(app_id)),
    }


@bp.route('/<int:account_id>/<app_id>/traffic-rewrites')
@login_required
def traffic_rewrites(account_id, app_id):
    """Traffic rewrites page for an application."""
    client, account, perm = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or access denied.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    rules = _get_all_rewrites(client, app_id)
    active_tab = request.args.get('tab', 'request')

    return render_template(
        'applications/traffic_rewrites.html',
        account=account,
        app_id=app_id,
        rules=rules,
        active_tab=active_tab,
        user_can_write=current_user.role != 'viewer',
    )


def _rewrite_crud(account_id, app_id, rewrite_type, action):
    """Shared handler for rewrite CRUD AJAX calls."""
    client, account, perm = get_client_for_account(account_id, min_permission='write')
    if not client or not can_write(perm):
        return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'Request body required'}), 400

    method_map = {
        'request': {
            'create': client.create_request_rewrite,
            'update': client.update_request_rewrite,
            'delete': client.delete_request_rewrite,
        },
        'response': {
            'create': client.create_response_rewrite,
            'update': client.update_response_rewrite,
            'delete': client.delete_response_rewrite,
        },
        'body': {
            'create': client.create_response_body_rewrite,
            'update': client.update_response_body_rewrite,
            'delete': client.delete_response_body_rewrite,
        },
        'url_translation': {
            'create': client.create_url_translation,
            'update': client.update_url_translation,
            'delete': client.delete_url_translation,
        },
    }

    try:
        if action == 'create':
            result = method_map[rewrite_type]['create'](app_id, data)
        elif action == 'update':
            rule_name = data.get('rule_name')
            fields = data.get('fields', {})
            if not rule_name:
                return jsonify({'success': False, 'error': 'rule_name required'}), 400
            result = method_map[rewrite_type]['update'](app_id, rule_name, fields)
        elif action == 'delete':
            rule_name = data.get('rule_name')
            if not rule_name:
                return jsonify({'success': False, 'error': 'rule_name required'}), 400
            method_map[rewrite_type]['delete'](app_id, rule_name)
            result = None
        else:
            return jsonify({'success': False, 'error': 'Unknown action'}), 400

        AuditLog.log(
            user_id=current_user.id,
            action=f'{rewrite_type}_rewrite_{action}',
            resource_type='application',
            resource_id=app_id,
            details=f'{action.title()} {rewrite_type} rewrite for app {app_id} on account {account.account_name}',
            ip_address=request.remote_addr
        )

        return jsonify({'success': True, 'data': result})
    except WaasApiError as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/<int:account_id>/<app_id>/rewrites/request/create', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def create_request_rewrite(account_id, app_id):
    return _rewrite_crud(account_id, app_id, 'request', 'create')


@bp.route('/<int:account_id>/<app_id>/rewrites/request/update', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def update_request_rewrite(account_id, app_id):
    return _rewrite_crud(account_id, app_id, 'request', 'update')


@bp.route('/<int:account_id>/<app_id>/rewrites/request/delete', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def delete_request_rewrite(account_id, app_id):
    return _rewrite_crud(account_id, app_id, 'request', 'delete')


@bp.route('/<int:account_id>/<app_id>/rewrites/response/create', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def create_response_rewrite(account_id, app_id):
    return _rewrite_crud(account_id, app_id, 'response', 'create')


@bp.route('/<int:account_id>/<app_id>/rewrites/response/update', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def update_response_rewrite(account_id, app_id):
    return _rewrite_crud(account_id, app_id, 'response', 'update')


@bp.route('/<int:account_id>/<app_id>/rewrites/response/delete', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def delete_response_rewrite(account_id, app_id):
    return _rewrite_crud(account_id, app_id, 'response', 'delete')


@bp.route('/<int:account_id>/<app_id>/rewrites/body/create', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def create_body_rewrite(account_id, app_id):
    return _rewrite_crud(account_id, app_id, 'body', 'create')


@bp.route('/<int:account_id>/<app_id>/rewrites/body/update', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def update_body_rewrite(account_id, app_id):
    return _rewrite_crud(account_id, app_id, 'body', 'update')


@bp.route('/<int:account_id>/<app_id>/rewrites/body/delete', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def delete_body_rewrite(account_id, app_id):
    return _rewrite_crud(account_id, app_id, 'body', 'delete')


@bp.route('/<int:account_id>/<app_id>/rewrites/url-translation/create', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def create_url_translation(account_id, app_id):
    return _rewrite_crud(account_id, app_id, 'url_translation', 'create')


@bp.route('/<int:account_id>/<app_id>/rewrites/url-translation/update', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def update_url_translation(account_id, app_id):
    return _rewrite_crud(account_id, app_id, 'url_translation', 'update')


@bp.route('/<int:account_id>/<app_id>/rewrites/url-translation/delete', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def delete_url_translation(account_id, app_id):
    return _rewrite_crud(account_id, app_id, 'url_translation', 'delete')


# ---- Response Pages ----

@bp.route('/<int:account_id>/<app_id>/response-pages')
@login_required
def response_pages(account_id, app_id):
    """Response pages management for an application."""
    client, account, perm = get_client_for_account(account_id)
    if not client:
        flash(_('Account not found or access denied.'), 'danger')
        return redirect(url_for('applications.list_applications'))

    pages = []
    error = None
    try:
        result = client.get_response_pages(app_id)
        if isinstance(result, list):
            pages = result
        elif isinstance(result, dict):
            pages = result.get('results', result.get('data', []))
    except WaasApiError as e:
        error = str(e)

    return render_template(
        'applications/response_pages.html',
        account=account,
        app_id=app_id,
        pages=pages,
        error=error,
        user_can_write=current_user.role != 'viewer',
    )


@bp.route('/<int:account_id>/<app_id>/response-pages/create', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def create_response_page(account_id, app_id):
    client, account, perm = get_client_for_account(account_id, min_permission='write')
    if not client or not can_write(perm):
        return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'Request body required'}), 400

    try:
        result = client.create_response_page(app_id, data)
        AuditLog.log(
            user_id=current_user.id,
            action='response_page_create',
            resource_type='application',
            resource_id=app_id,
            details=f'Created response page for app {app_id} on account {account.account_name}',
            ip_address=request.remote_addr
        )
        return jsonify({'success': True, 'data': result})
    except WaasApiError as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/<int:account_id>/<app_id>/response-pages/update', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def update_response_page(account_id, app_id):
    client, account, perm = get_client_for_account(account_id, min_permission='write')
    if not client or not can_write(perm):
        return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403

    data = request.get_json()
    if not data or 'page_name' not in data:
        return jsonify({'success': False, 'error': 'page_name required'}), 400

    page_name = data.pop('page_name')
    try:
        result = client.update_response_page(app_id, page_name, data)
        AuditLog.log(
            user_id=current_user.id,
            action='response_page_update',
            resource_type='application',
            resource_id=app_id,
            details=f'Updated response page "{page_name}" for app {app_id} on account {account.account_name}',
            ip_address=request.remote_addr
        )
        return jsonify({'success': True, 'data': result})
    except WaasApiError as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/<int:account_id>/<app_id>/response-pages/delete', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def delete_response_page(account_id, app_id):
    client, account, perm = get_client_for_account(account_id, min_permission='write')
    if not client or not can_write(perm):
        return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403

    data = request.get_json()
    if not data or 'page_name' not in data:
        return jsonify({'success': False, 'error': 'page_name required'}), 400

    page_name = data['page_name']
    try:
        client.delete_response_page(app_id, page_name)
        AuditLog.log(
            user_id=current_user.id,
            action='response_page_delete',
            resource_type='application',
            resource_id=app_id,
            details=f'Deleted response page "{page_name}" for app {app_id} on account {account.account_name}',
            ip_address=request.remote_addr
        )
        return jsonify({'success': True})
    except WaasApiError as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Config Transformer — offline JSON filter/clean tool (no account required)
# ---------------------------------------------------------------------------

@bp.route('/config-transformer')
@login_required
def config_transformer():
    from app.config_transformer import (
        SECTION_DEFINITIONS,
        SERVER_RUNTIME_STRIP,
        ENDPOINT_CERT_ALWAYS_STRIP,
        ENDPOINT_PORT_ALWAYS_STRIP,
    )
    strip_constants = {
        'server_runtime': sorted(SERVER_RUNTIME_STRIP),
        'endpoint_cert': sorted(ENDPOINT_CERT_ALWAYS_STRIP),
        'endpoint_port': sorted(ENDPOINT_PORT_ALWAYS_STRIP),
    }
    return render_template('applications/config_transformer.html',
                           section_definitions=SECTION_DEFINITIONS,
                           strip_constants=strip_constants)


@bp.route('/config-transformer/parse', methods=['POST'])
@login_required
def config_transformer_parse():
    """Parse a pasted WaaS export JSON and return section metadata for the UI."""
    body = request.get_json(silent=True) or {}
    json_content = body.get('json_content', '').lstrip('﻿').strip()
    if not json_content:
        return jsonify({'error': 'No JSON provided.'}), 400
    try:
        parsed = json.loads(json_content)
    except json.JSONDecodeError as e:
        from app.config_transformer import json_error_excerpt
        return jsonify({
            'error': f'JSON syntax error at line {e.lineno}, column {e.colno}: {e.msg}',
            'detail': {'line': e.lineno, 'col': e.colno, 'excerpt': json_error_excerpt(json_content, e.pos)},
        }), 400
    if not isinstance(parsed, dict):
        return jsonify({'error': 'Expected a JSON object "{…}", not an array or scalar.'}), 400

    from app.config_transformer import get_section_metadata
    sections = get_section_metadata(parsed)
    return jsonify({'sections': sections, 'section_count': len(sections)})


@bp.route('/config-transformer/transform', methods=['POST'])
@login_required
def config_transformer_transform():
    """Apply user selections to a WaaS export JSON and return clean, importable JSON."""
    body = request.get_json(silent=True) or {}
    json_content = body.get('json_content', '').strip()
    selections = body.get('selections', {})
    if not json_content:
        return jsonify({'error': 'No JSON provided.'}), 400
    try:
        parsed = json.loads(json_content)
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid JSON: {e}'}), 400

    from app.config_transformer import transform_config
    result = transform_config(parsed, selections)
    return jsonify({'result': json.dumps(result, indent=2), 'section_count': len(result)})
