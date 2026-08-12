"""
Log viewer routes — WAF logs, access logs, and false-positive analysis.

Uses the v4 unified logs API which returns both WAF (LogType=WF) and
access/traffic (LogType=TR) entries in a single response.  Applications
are listed via the v2 API.
"""
import csv
import io
import json
from math import ceil
from flask import Blueprint, render_template, request, flash, redirect, url_for, make_response, Response, stream_with_context
from flask_login import login_required, current_user
from flask_babel import gettext as _
from app.models import WaasAccount, AuditLog, get_user_accounts, get_account_for_user
from app.waas_client import WaasClient, WaasApiError

bp = Blueprint('logs', __name__, url_prefix='/logs')

# Valid quick-range values accepted by the v4 API
QUICK_RANGES = [
    ('r_1h', 'Last 1 Hour'),
    ('r_24h', 'Last 24 Hours'),
    ('r_7d', 'Last 7 Days'),
    ('r_14d', 'Last 14 Days'),
    ('r_30d', 'Last 30 Days'),
    ('r_45d', 'Last 45 Days'),
    ('r_60d', 'Last 60 Days'),
]

SEVERITY_LABELS = {
    'EMER': ('Emergency', 'bg-danger'),
    'CRIT': ('Critical', 'bg-danger'),
    'ALER': ('Alert', 'bg-danger'),
    'ERRO': ('Error', 'bg-warning text-dark'),
    'WARN': ('Warning', 'bg-warning text-dark'),
    'NOTI': ('Notice', 'bg-info'),
    'INFO': ('Info', 'bg-info'),
    'DEBU': ('Debug', 'bg-secondary'),
}


def _get_account(account_id):
    """Load an active account accessible by the current user, or 404."""
    from flask import abort
    account, perm = get_account_for_user(account_id, current_user)
    if not account:
        abort(404)
    return account


def _get_applications(account):
    """Fetch application list via v2 API.  Returns list of dicts or []."""
    try:
        client = WaasClient.from_account(account)
        result = client.list_applications_v2()
        return result.get('results', [])
    except WaasApiError as e:
        flash(_('Failed to load applications: %(error)s', error=str(e)), 'danger')
        return []


WAF_CSV_FIELDS = [
    'EpochTime', 'Severity', 'Action', 'AttackGroup', 'Attack', 'AttackType',
    'AttackDetails', 'RuleID', 'RuleType', 'URL', 'Method', 'ClientIP',
    'ClientIP_country_code', 'countryName', 'owasp', 'cwe',
    'owasp_api_top_ten', 'owasp_risk_score',
]

ACCESS_CSV_FIELDS = [
    'EpochTime', 'ClientIP', 'ClientIP_country_code', 'countryName',
    'Method', 'URL', 'HTTPStatus', 'BytesSent', 'TimeTaken',
    'Protocol', 'Protected', 'ResponseType',
]


def _export_logs_as_csv(logs, log_type):
    """Export log entries as a CSV string."""
    fields = WAF_CSV_FIELDS if log_type == 'waf' else ACCESS_CSV_FIELDS
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
    writer.writeheader()
    for entry in logs:
        writer.writerow({f: entry.get(f, '') for f in fields})
    return output.getvalue()


def _export_logs_as_json(logs):
    """Export log entries as a JSON string."""
    return json.dumps(logs, indent=2, default=str)


def _make_export_response(logs, log_type, fmt, app_name, account_id):
    """Build a file download response for log export and create audit entry."""
    if fmt == 'csv':
        data = _export_logs_as_csv(logs, log_type)
        mimetype = 'text/csv'
        ext = 'csv'
    else:
        data = _export_logs_as_json(logs)
        mimetype = 'application/json'
        ext = 'json'

    filename = f'{log_type}_logs_{app_name}.{ext}'
    response = make_response(data)
    response.headers['Content-Type'] = mimetype
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'

    AuditLog.log(
        user_id=current_user.id,
        action='log_export',
        resource_type=f'{log_type}_logs',
        resource_id=account_id,
        details=f'Exported {len(logs)} {log_type} log entries as {fmt.upper()} for {app_name}',
        ip_address=request.remote_addr,
    )

    return response


def _build_waf_filters():
    """Build filter_fields dict for WAF logs from query params."""
    filter_fields = {'LogType': [{'condition': 'is', 'value': 'WF'}]}
    client_ip = request.args.get('client_ip', '').strip()
    if client_ip:
        filter_fields['ClientIP'] = [{'condition': 'is', 'value': client_ip}]
    severity = request.args.get('severity', '').strip()
    if severity:
        filter_fields['Severity'] = [{'condition': 'is', 'value': severity}]
    action = request.args.get('action', '').strip()
    if action:
        filter_fields['Action'] = [{'condition': 'is', 'value': action}]
    attack_group = request.args.get('attack_group', '').strip()
    if attack_group:
        filter_fields['AttackGroup'] = [{'condition': 'is', 'value': attack_group}]
    method = request.args.get('method', '').strip()
    if method:
        filter_fields['Method'] = [{'condition': 'is', 'value': method}]
    return filter_fields, client_ip


def _build_access_filters():
    """Build filter_fields dict for access logs from query params."""
    filter_fields = {'LogType': [{'condition': 'is', 'value': 'TR'}]}
    client_ip = request.args.get('client_ip', '').strip()
    if client_ip:
        filter_fields['ClientIP'] = [{'condition': 'is', 'value': client_ip}]
    method = request.args.get('method', '').strip()
    if method:
        filter_fields['Method'] = [{'condition': 'is', 'value': method}]
    http_status = request.args.get('http_status', '').strip()
    if http_status:
        filter_fields['HTTPStatus'] = [{'condition': 'is', 'value': http_status}]
    return filter_fields, client_ip


def _active_filters(log_type):
    """Return list of (label, value) for currently active non-default filters."""
    active = []
    if request.args.get('client_ip', '').strip():
        active.append((_('Client IP'), request.args['client_ip'].strip()))
    if log_type == 'waf':
        if request.args.get('severity', '').strip():
            raw = request.args['severity'].strip()
            label, _ = SEVERITY_LABELS.get(raw, (raw, ''))
            active.append((_('Severity'), label))
        if request.args.get('action', '').strip():
            active.append((_('Action'), request.args['action'].strip()))
        if request.args.get('attack_group', '').strip():
            active.append((_('Attack Group'), request.args['attack_group'].strip()))
    if request.args.get('method', '').strip():
        active.append((_('Method'), request.args['method'].strip()))
    if log_type == 'access' and request.args.get('http_status', '').strip():
        active.append((_('HTTP Status'), request.args['http_status'].strip()))
    return active


# ------------------------------------------------------------------
# Index / Launcher
# ------------------------------------------------------------------
@bp.route('/')
@login_required
def index():
    """Launcher page: account → application → log-type selector."""
    accounts = get_user_accounts(current_user)

    account_id = request.args.get('account_id', type=int)
    selected_account = None
    applications = []

    if account_id:
        selected_account, perm = get_account_for_user(account_id, current_user)
        if selected_account:
            applications = _get_applications(selected_account)

    return render_template(
        'logs/index.html',
        accounts=accounts,
        selected_account=selected_account,
        applications=applications,
    )


# ------------------------------------------------------------------
# WAF Logs
# ------------------------------------------------------------------
@bp.route('/<int:account_id>/<path:app_name>/waf')
@login_required
def waf_logs(account_id, app_name):
    """WAF (firewall) log viewer with filtering."""
    account = _get_account(account_id)

    quick_range = request.args.get('quick_range', 'r_24h')
    page = request.args.get('page', 1, type=int)
    items_per_page = request.args.get('per_page', 50, type=int)
    export_fmt = request.args.get('format', '').lower()

    filter_fields, client_ip = _build_waf_filters()

    logs = []
    total = 0
    error = None

    try:
        client = WaasClient.from_account(account)
        result = client.get_logs(
            app_name,
            quick_range=quick_range,
            page=page,
            items_per_page=items_per_page,
            filter_fields=filter_fields,
        )
        logs = result.get('results', [])
        total = result.get('count', len(logs))
    except WaasApiError as e:
        error = str(e)

    if export_fmt in ('csv', 'json') and logs:
        return _make_export_response(logs, 'waf', export_fmt, app_name, account.id)

    total_pages = max(1, ceil(total / items_per_page)) if total else 1

    return render_template(
        'logs/waf.html',
        account=account,
        app_name=app_name,
        logs=logs,
        total=total,
        page=page,
        per_page=items_per_page,
        total_pages=total_pages,
        quick_range=quick_range,
        client_ip=client_ip,
        severity=request.args.get('severity', ''),
        action_filter=request.args.get('action', ''),
        attack_group=request.args.get('attack_group', ''),
        method=request.args.get('method', ''),
        quick_ranges=QUICK_RANGES,
        severity_labels=SEVERITY_LABELS,
        active_filters=_active_filters('waf'),
        error=error,
    )


# ------------------------------------------------------------------
# Access Logs
# ------------------------------------------------------------------
@bp.route('/<int:account_id>/<path:app_name>/access')
@login_required
def access_logs(account_id, app_name):
    """Access / traffic log viewer with filtering."""
    account = _get_account(account_id)

    quick_range = request.args.get('quick_range', 'r_24h')
    page = request.args.get('page', 1, type=int)
    items_per_page = request.args.get('per_page', 50, type=int)
    export_fmt = request.args.get('format', '').lower()

    filter_fields, client_ip = _build_access_filters()

    logs = []
    total = 0
    error = None

    try:
        client = WaasClient.from_account(account)
        result = client.get_logs(
            app_name,
            quick_range=quick_range,
            page=page,
            items_per_page=items_per_page,
            filter_fields=filter_fields,
        )
        logs = result.get('results', [])
        total = result.get('count', len(logs))
    except WaasApiError as e:
        error = str(e)

    if export_fmt in ('csv', 'json') and logs:
        return _make_export_response(logs, 'access', export_fmt, app_name, account.id)

    total_pages = max(1, ceil(total / items_per_page)) if total else 1

    return render_template(
        'logs/access.html',
        account=account,
        app_name=app_name,
        logs=logs,
        total=total,
        page=page,
        per_page=items_per_page,
        total_pages=total_pages,
        quick_range=quick_range,
        client_ip=client_ip,
        method=request.args.get('method', ''),
        http_status=request.args.get('http_status', ''),
        quick_ranges=QUICK_RANGES,
        active_filters=_active_filters('access'),
        error=error,
    )


# ------------------------------------------------------------------
# Export All (streaming)
# ------------------------------------------------------------------
@bp.route('/<int:account_id>/<path:app_name>/export-all/<log_type>')
@login_required
def export_all(account_id, app_name, log_type):
    """Stream all matching log entries as CSV or JSON download."""
    account = _get_account(account_id)
    fmt = request.args.get('format', 'csv').lower()
    quick_range = request.args.get('quick_range', 'r_24h')

    if log_type == 'waf':
        filter_fields, _ = _build_waf_filters()
        fields = WAF_CSV_FIELDS
    else:
        filter_fields, _ = _build_access_filters()
        fields = ACCESS_CSV_FIELDS

    client = WaasClient.from_account(account)

    def generate_csv():
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)

        pg = 1
        while True:
            result = client.get_logs(
                app_name, quick_range=quick_range, page=pg,
                items_per_page=1000, filter_fields=filter_fields,
            )
            rows = result.get('results', [])
            if not rows:
                break
            for entry in rows:
                writer.writerow({f: entry.get(f, '') for f in fields})
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
            if len(rows) < 1000:
                break
            pg += 1

    def generate_json():
        yield '[\n'
        pg = 1
        first = True
        while True:
            result = client.get_logs(
                app_name, quick_range=quick_range, page=pg,
                items_per_page=1000, filter_fields=filter_fields,
            )
            rows = result.get('results', [])
            if not rows:
                break
            for entry in rows:
                prefix = '  ' if first else ',\n  '
                first = False
                yield prefix + json.dumps(entry, default=str)
            if len(rows) < 1000:
                break
            pg += 1
        yield '\n]\n'

    filename = f'{log_type}_logs_{app_name}_all.{fmt}'

    if fmt == 'json':
        resp = Response(stream_with_context(generate_json()), mimetype='application/json')
    else:
        resp = Response(stream_with_context(generate_csv()), mimetype='text/csv')

    resp.headers['Content-Disposition'] = f'attachment; filename="{filename}"'

    AuditLog.log(
        user_id=current_user.id,
        action='log_export_all',
        resource_type=f'{log_type}_logs',
        resource_id=account_id,
        details=f'Export-all {log_type} logs as {fmt.upper()} for {app_name}',
        ip_address=request.remote_addr,
    )

    return resp


# ------------------------------------------------------------------
# False-Positive Analysis
# ------------------------------------------------------------------
@bp.route('/<int:account_id>/<path:app_name>/fp-analysis')
@login_required
def fp_analysis(account_id, app_name):
    """False-positive analysis — groups blocked WAF entries by attack type."""
    account = _get_account(account_id)

    quick_range = request.args.get('quick_range', 'r_7d')

    logs = []
    total_from_api = 0
    error = None

    try:
        client = WaasClient.from_account(account)
        filter_fields = {
            'LogType': [{'condition': 'is', 'value': 'WF'}],
        }
        result = client.get_logs(
            app_name,
            quick_range=quick_range,
            page=1,
            items_per_page=1000,
            filter_fields=filter_fields,
        )
        logs = result.get('results', [])
        total_from_api = result.get('count', len(logs))
    except WaasApiError as e:
        error = str(e)

    # Group by AttackType + RuleID
    attack_groups = {}
    for entry in logs:
        attack_type = entry.get('AttackType', entry.get('Attack', 'Unknown'))
        rule_id = entry.get('RuleID', 'unknown')
        group_key = f'{attack_type}|{rule_id}'

        if group_key not in attack_groups:
            attack_groups[group_key] = {
                'attack_type': attack_type,
                'attack_name': entry.get('Attack', attack_type),
                'attack_group': entry.get('AttackGroup', '—'),
                'rule_id': rule_id,
                'rule_type': entry.get('RuleType', '—'),
                'owasp': entry.get('owasp', '—'),
                'cwe': entry.get('cwe', '—'),
                'owasp_api': entry.get('owasp_api_top_ten', '—'),
                'owasp_risk_score': entry.get('owasp_risk_score', '—'),
                'count': 0,
                'deny_count': 0,
                'log_count': 0,
                'samples': [],
                'unique_ips': set(),
                'unique_urls': set(),
            }

        group = attack_groups[group_key]
        group['count'] += 1
        action = entry.get('Action', '')
        if action == 'DENY':
            group['deny_count'] += 1
        else:
            group['log_count'] += 1
        if len(group['samples']) < 5:
            group['samples'].append(entry)
        group['unique_ips'].add(entry.get('ClientIP', 'unknown'))
        group['unique_urls'].add(entry.get('URL', 'unknown'))

    # Convert sets to counts for template serialisation
    for group in attack_groups.values():
        group['unique_ip_count'] = len(group['unique_ips'])
        group['unique_url_count'] = len(group['unique_urls'])
        del group['unique_ips']
        del group['unique_urls']

    # Sort by count descending
    sorted_groups = sorted(attack_groups.values(), key=lambda g: g['count'], reverse=True)

    total_deny = sum(1 for e in logs if e.get('Action') == 'DENY')
    total_log = sum(1 for e in logs if e.get('Action') != 'DENY')

    return render_template(
        'logs/fp_analysis.html',
        account=account,
        app_name=app_name,
        attack_groups=sorted_groups,
        total_events=len(logs),
        total_from_api=total_from_api,
        total_deny=total_deny,
        total_log=total_log,
        quick_range=quick_range,
        quick_ranges=QUICK_RANGES,
        error=error,
    )
