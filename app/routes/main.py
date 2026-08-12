from collections import Counter, defaultdict
from datetime import datetime, date, timedelta
from flask import Blueprint, render_template, redirect, url_for, jsonify, request
from flask_login import login_required, current_user
import logging

logger = logging.getLogger(__name__)


def _parse_cert_expiry(value):
    """Try to parse a certificate expiry string into a date object."""
    if not value or value in ('-', '"-"', ''):
        return None
    for fmt in ('%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S.%fZ',
                '%b %d %H:%M:%S %Y GMT', '%d/%m/%Y', '%m/%d/%Y'):
        try:
            return datetime.strptime(str(value).strip(), fmt).date()
        except ValueError:
            continue
    # Try ISO format as fallback
    try:
        return datetime.fromisoformat(str(value).strip()).date()
    except (ValueError, TypeError):
        return None

bp = Blueprint('main', __name__)


@bp.route('/')
def index():
    """Landing page - redirect to dashboard if logged in"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard view"""
    from app.models import WaasAccount, AuditLog, get_user_accounts
    from flask import request
    accounts = get_user_accounts(current_user)
    recent_activity = AuditLog.query.filter_by(user_id=current_user.id)\
        .order_by(AuditLog.timestamp.desc()).limit(10).all()
    any_verified = any(a.last_verified for a in accounts)
    show_onboarding = len(accounts) == 0 or not any_verified or request.args.get('onboarding') == '1'
    return render_template('dashboard.html', accounts=accounts, recent_activity=recent_activity,
                           show_onboarding=show_onboarding, any_verified=any_verified)


@bp.route('/dashboard/counts')
@login_required
def dashboard_counts():
    """AJAX endpoint returning per-account application/certificate counts and cert expiry warnings."""
    from app.models import WaasAccount, get_user_accounts
    from app.waas_client import WaasClient, WaasApiError

    accounts = get_user_accounts(current_user)

    total_apps = 0
    total_certs = 0
    account_data = []
    expiring_certs = []
    errors = []
    today = date.today()

    for account in accounts:
        acct_info = {
            'id': account.id,
            'name': account.account_name,
            'app_count': 0,
            'cert_count': 0,
            'status': 'ok',
            'has_api_key': account.has_api_key,
            'has_v2_credentials': account.has_v2_credentials,
        }

        try:
            client = WaasClient.from_account(account)
        except WaasApiError as e:
            logger.warning(f'Dashboard counts: cannot create client for account {account.id}: {e}')
            acct_info['status'] = 'error'
            errors.append(str(e))
            account_data.append(acct_info)
            continue

        # Applications
        try:
            apps_resp = client.list_applications()
            if isinstance(apps_resp, list):
                acct_info['app_count'] = len(apps_resp)
            elif isinstance(apps_resp, dict):
                if 'results' in apps_resp:
                    acct_info['app_count'] = len(apps_resp['results'])
                elif 'count' in apps_resp:
                    acct_info['app_count'] = apps_resp['count']
                elif 'applications' in apps_resp:
                    acct_info['app_count'] = len(apps_resp['applications'])
        except WaasApiError as e:
            logger.warning(f'Dashboard counts: failed to list apps for account {account.id}: {e}')
            errors.append(str(e))

        # Certificates
        try:
            certs_resp = client.list_certificates()
            certs_list = []
            if isinstance(certs_resp, list):
                certs_list = certs_resp
            elif isinstance(certs_resp, dict):
                certs_list = certs_resp.get('results',
                             certs_resp.get('certificates',
                             certs_resp.get('data', [])))
            acct_info['cert_count'] = len(certs_list)

            # Check for expiring certs
            for cert in certs_list:
                expiry_str = cert.get('expiry', cert.get('expiryDate'))
                expiry_date = _parse_cert_expiry(expiry_str)
                if expiry_date:
                    days_remaining = (expiry_date - today).days
                    if days_remaining <= 30:
                        expiring_certs.append({
                            'name': cert.get('name', 'Unknown'),
                            'app_name': cert.get('_app_name', ''),
                            'account_id': account.id,
                            'account_name': account.account_name,
                            'expiry': str(expiry_date),
                            'days_remaining': days_remaining,
                        })
        except WaasApiError as e:
            logger.warning(f'Dashboard counts: failed to list certs for account {account.id}: {e}')
            errors.append(str(e))

        total_apps += acct_info['app_count']
        total_certs += acct_info['cert_count']
        account_data.append(acct_info)

    # Check for expiring API keys
    expiring_keys = []
    for account in accounts:
        if account.api_key_expiry:
            days_remaining = (account.api_key_expiry - today).days
            if days_remaining <= 30:
                expiring_keys.append({
                    'account_id': account.id,
                    'account_name': account.account_name,
                    'expiry': str(account.api_key_expiry),
                    'days_remaining': days_remaining,
                })

    # Create in-app notifications for expiring API keys (deduplicated: 1 per account per 24h)
    if expiring_keys:
        try:
            from app.models import Notification
            from app import db as _db
            if current_user.notify_apikey_expiry_inapp is None or current_user.notify_apikey_expiry_inapp:
                cutoff = datetime.utcnow() - timedelta(hours=24)
                for key_info in expiring_keys:
                    dedup_title = f'API key expiring: {key_info["account_name"]}'
                    existing = Notification.query.filter(
                        Notification.user_id == current_user.id,
                        Notification.type == 'api_key_expiry',
                        Notification.title == dedup_title,
                        Notification.created_at >= cutoff,
                    ).first()
                    if not existing:
                        if key_info['days_remaining'] <= 0:
                            msg = f'API key for account {key_info["account_name"]} has expired ({key_info["expiry"]}).'
                        else:
                            msg = f'API key for account {key_info["account_name"]} expires in {key_info["days_remaining"]} days ({key_info["expiry"]}).'
                        Notification.create(
                            user_id=current_user.id,
                            type='api_key_expiry',
                            title=dedup_title,
                            message=msg,
                            link=f'/accounts/{key_info["account_id"]}',
                        )
        except Exception as e:
            logger.warning(f'Failed to create API key expiry notification: {e}')

    # Create in-app notifications for expiring certs (deduplicated: 1 per cert per 24h)
    if expiring_certs:
        try:
            from app.models import Notification
            from app import db
            if current_user.notify_cert_expiry_inapp is None or current_user.notify_cert_expiry_inapp:
                cutoff = datetime.utcnow() - timedelta(hours=24)
                for cert in expiring_certs:
                    dedup_title = f'Certificate expiring: {cert["name"]}'
                    existing = Notification.query.filter(
                        Notification.user_id == current_user.id,
                        Notification.type == 'cert_expiry',
                        Notification.title == dedup_title,
                        Notification.created_at >= cutoff,
                    ).first()
                    if not existing:
                        Notification.create(
                            user_id=current_user.id,
                            type='cert_expiry',
                            title=dedup_title,
                            message=f'{cert["name"]} on account {cert["account_name"]} expires in {cert["days_remaining"]} days ({cert["expiry"]}).',
                            link=f'/certificates/?account_id={cert["account_id"]}',
                        )
        except Exception as e:
            logger.warning(f'Failed to create cert expiry notification: {e}')

    return jsonify({
        'app_count': total_apps,
        'cert_count': total_certs,
        'accounts': account_data,
        'expiring_certs': sorted(expiring_certs, key=lambda c: c['days_remaining']),
        'expiring_keys': sorted(expiring_keys, key=lambda k: k['days_remaining']),
        'errors': errors,
    })


@bp.route('/dashboard/chart-data')
@login_required
def dashboard_chart_data():
    """AJAX endpoint returning aggregated WAF log data for dashboard charts.

    Query params:
        account_id (optional): Limit to one account
        range: quick_range value (default r_24h)

    Returns JSON with attack_timeline, top_ips, top_attack_types, server_health.
    """
    from app.models import get_user_accounts
    from app.waas_client import WaasClient, WaasApiError

    accounts = get_user_accounts(current_user)
    quick_range = request.args.get('range', 'r_24h')
    filter_account_id = request.args.get('account_id', type=int)

    attack_timeline = defaultdict(int)  # hour_label -> count
    top_ips = Counter()
    top_attack_types = Counter()
    server_health = {'up': 0, 'down': 0, 'unknown': 0}
    total_requests = 0
    total_attacks = 0
    apps_checked = 0

    for account in accounts:
        if filter_account_id and account.id != filter_account_id:
            continue
        try:
            client = WaasClient.from_account(account)
        except WaasApiError:
            continue

        # Get app list for server health
        try:
            apps_resp = client.list_applications()
            if isinstance(apps_resp, list):
                app_list = apps_resp
            elif isinstance(apps_resp, dict):
                app_list = apps_resp.get('results', apps_resp.get('data', apps_resp.get('applications', [])))
            else:
                app_list = []
        except WaasApiError:
            app_list = []

        # Fetch logs for each app (limit to first 5 apps to avoid slow responses)
        for app in app_list[:5]:
            app_name = app.get('name', '') if isinstance(app, dict) else ''
            if not app_name:
                continue
            apps_checked += 1

            # Collect server health from app export
            try:
                app_detail = client.get_application(app_name)
                for srv in app_detail.get('servers', []):
                    h = (srv.get('health') or '').lower()
                    if h == 'up':
                        server_health['up'] += 1
                    elif h == 'down':
                        server_health['down'] += 1
                    else:
                        server_health['unknown'] += 1
            except WaasApiError:
                pass

            # Fetch WAF/access logs for charts
            try:
                logs_resp = client.get_logs(app_name, quick_range=quick_range, items_per_page=200)
                results = []
                if isinstance(logs_resp, dict):
                    results = logs_resp.get('results', [])
                    total_requests += logs_resp.get('count', len(results))

                for entry in results:
                    # Attack timeline — group by hour
                    # WaaS API uses 'EpochTime' field with epoch milliseconds
                    ts = entry.get('EpochTime')
                    if ts:
                        try:
                            epoch_ms = int(ts)
                            dt = datetime.utcfromtimestamp(epoch_ms / 1000.0)
                            hour_label = dt.strftime('%m-%d %H:00')
                            attack_timeline[hour_label] += 1
                        except (ValueError, TypeError, OSError):
                            pass

                    # Top client IPs
                    ip = entry.get('ClientIP')
                    if ip:
                        top_ips[ip] += 1

                    # Top attack/event types — prefer AttackGroup for WAF,
                    # fall back to Action (Blocked/Allowed/etc.)
                    attack_type = entry.get('AttackGroup') or entry.get('Action')
                    if attack_type and attack_type != '-':
                        top_attack_types[attack_type] += 1
                        total_attacks += 1

            except WaasApiError:
                pass

    # Sort timeline by label (chronological)
    sorted_timeline = sorted(attack_timeline.items())

    return jsonify({
        'attack_timeline': {
            'labels': [t[0] for t in sorted_timeline],
            'data': [t[1] for t in sorted_timeline],
        },
        'top_ips': {
            'labels': [ip for ip, _ in top_ips.most_common(10)],
            'data': [count for _, count in top_ips.most_common(10)],
        },
        'top_attack_types': {
            'labels': [t for t, _ in top_attack_types.most_common(8)],
            'data': [count for _, count in top_attack_types.most_common(8)],
        },
        'server_health': server_health,
        'summary': {
            'total_requests': total_requests,
            'total_attacks': total_attacks,
            'apps_checked': apps_checked,
        },
    })


@bp.route('/about')
def about():
    """About page"""
    return render_template('about.html')
