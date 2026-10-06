from collections import Counter, defaultdict
from functools import partial
from datetime import datetime, date, timedelta
from flask import Blueprint, render_template, redirect, url_for, jsonify, request, send_from_directory, current_app
from flask_login import login_required, current_user
import logging
import os
import time

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


@bp.route('/favicon.ico')
def favicon():
    """Serve /favicon.ico for browsers that auto-fetch it from the site
    root. Base.html also declares the SVG icon explicitly; this route
    handles the automatic-request case so it stops 404-ing in the log."""
    return send_from_directory(
        os.path.join(current_app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/x-icon',
    )


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
    """AJAX endpoint returning per-account application/certificate counts and cert expiry warnings.

    The per-account fetches run one greenlet each under a wall-clock budget.
    Serially this was the dashboard's slowest call by far — list_certificates()
    with no app name does its own per-app fan-out (one SNI call per app), so an
    8-account, 194-app user came to ~210 sequential requests and ~28s.
    """
    from app.models import WaasAccount, get_user_accounts
    from app.waas_client import WaasClient, WaasApiError
    from app.overview_dashboard import COUNTS_FETCH_BUDGET_SECONDS, run_in_pool

    accounts = get_user_accounts(current_user)

    total_apps = 0
    total_certs = 0
    account_data = []
    expiring_certs = []
    errors = []
    today = date.today()

    # See dashboard_chart_data() for why clients are built serially here and
    # why each greenlet pushes its own app context.
    flask_app = current_app._get_current_object()
    fetched = {}          # account.id -> {'app_count', 'certs', 'complete'}
    clients = []          # (client, account) for accounts we can actually call

    for account in accounts:
        try:
            clients.append((WaasClient.from_account(account), account))
        except WaasApiError as e:
            logger.warning(f'Dashboard counts: cannot create client for account {account.id}: {e}')
            errors.append(str(e))

    def fetch_account(client, account):
        with flask_app.app_context():
            # Published incrementally so a greenlet killed at the deadline
            # still contributes what it got; 'complete' is only set once both
            # calls are done, so a half-filled entry cannot pass as a real one.
            result = fetched.setdefault(
                account.id, {'app_count': 0, 'certs': [], 'complete': False}
            )

            try:
                apps_resp = client.list_applications()
                if isinstance(apps_resp, list):
                    result['app_count'] = len(apps_resp)
                elif isinstance(apps_resp, dict):
                    if 'results' in apps_resp:
                        result['app_count'] = len(apps_resp['results'])
                    elif 'count' in apps_resp:
                        result['app_count'] = apps_resp['count']
                    elif 'applications' in apps_resp:
                        result['app_count'] = len(apps_resp['applications'])
            except WaasApiError as e:
                logger.warning(f'Dashboard counts: failed to list apps for account {account.id}: {e}')
                errors.append(str(e))

            try:
                certs_resp = client.list_certificates()
                if isinstance(certs_resp, list):
                    result['certs'] = certs_resp
                elif isinstance(certs_resp, dict):
                    result['certs'] = certs_resp.get('results',
                                      certs_resp.get('certificates',
                                      certs_resp.get('data', [])))
            except WaasApiError as e:
                logger.warning(f'Dashboard counts: failed to list certs for account {account.id}: {e}')
                errors.append(str(e))

            result['complete'] = True

    started = time.monotonic()
    finished = run_in_pool(
        [partial(fetch_account, client, account) for client, account in clients],
        COUNTS_FETCH_BUDGET_SECONDS,
    )
    if finished < len(clients):
        errors.append(f'{len(clients) - finished} account(s) did not answer in time.')
    logger.info(
        f'Dashboard counts: {finished}/{len(clients)} account(s) in '
        f'{time.monotonic() - started:.1f}s'
    )

    # Accounts in `accounts` order, so every card on the page gets an entry —
    # including ones we never managed to call, which would otherwise sit on
    # their loading spinner forever.
    for account in accounts:
        result = fetched.get(account.id)
        certs_list = result['certs'] if result else []
        acct_info = {
            'id': account.id,
            'name': account.account_name,
            'app_count': result['app_count'] if result else 0,
            'cert_count': len(certs_list),
            # Missing or half-filled means the account never finished — flag
            # it so the card does not quietly read as a real zero.
            'status': 'ok' if result and result['complete'] else 'error',
            'has_api_key': account.has_api_key,
            'has_v2_credentials': account.has_v2_credentials,
        }

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

    Server health covers every application the user can see and costs nothing
    extra — it comes straight off the application list response. The
    log-derived charts sample up to MAX_APPS_PER_ACCOUNT apps per account.
    Both passes fan out one greenlet per account under a wall-clock budget, so
    the endpoint returns partial data rather than running past nginx's 60s
    proxy timeout (which is what used to surface as "Failed to load").
    """
    from app.models import get_user_accounts
    from app.waas_client import WaasClient, WaasApiError
    from app.overview_dashboard import (
        LIST_FETCH_BUDGET_SECONDS, LOG_FETCH_BUDGET_SECONDS,
        LOG_REQUEST_TIMEOUT_SECONDS, MAX_APPS_PER_ACCOUNT,
        accumulate_log_entries, app_names, build_chart_payload, extract_app_list,
        run_in_pool, tally_server_health,
    )

    accounts = get_user_accounts(current_user)
    quick_range = request.args.get('range', 'r_24h')
    filter_account_id = request.args.get('account_id', type=int)

    started = time.monotonic()
    server_health = {'up': 0, 'down': 0, 'unknown': 0}
    errors = []

    # Greenlets do not inherit the request's Flask context, and the API calls
    # below need one: _make_request() re-reads account.api_key, which decrypts
    # against current_app.config['SECRET_KEY']. Each worker pushes its own.
    flask_app = current_app._get_current_object()

    # Clients are still built here, serially, rather than inside the greenlets:
    # from_account() is the step that can refresh a v2 token and write it back
    # to the DB, and that belongs in the request greenlet where the session the
    # account instances are attached to lives.
    clients = []
    for account in accounts:
        if filter_account_id and account.id != filter_account_id:
            continue
        try:
            clients.append((WaasClient.from_account(account), account))
        except WaasApiError as e:
            logger.warning(f'Chart data: cannot create client for account {account.id}: {e}')
            errors.append(f'{account.account_name}: {e}')

    # Pass 1 — one list call per account, in parallel. Gives complete server
    # health plus the app names the log sampling will draw from.
    app_lists = {}

    def list_apps(client, account):
        with flask_app.app_context():
            try:
                app_lists[account.id] = extract_app_list(client.list_applications())
            except WaasApiError as e:
                logger.warning(f'Chart data: failed to list apps for account {account.id}: {e}')
                errors.append(f'{account.account_name}: {e}')

    run_in_pool(
        [partial(list_apps, client, account) for client, account in clients],
        LIST_FETCH_BUDGET_SECONDS,
    )

    apps_total = 0
    sampling_plan = []
    for client, account in clients:
        app_list = app_lists.get(account.id, [])
        apps_total += len(app_list)
        tally_server_health(app_list, server_health)
        names = app_names(app_list, limit=MAX_APPS_PER_ACCOUNT)
        if names:
            sampling_plan.append((client, account, names))

    # Pass 2 — per-app log calls, one greenlet per account. Each greenlet owns
    # its account's client exclusively and checks the deadline between calls,
    # appending as it goes so a greenlet killed at the deadline still keeps
    # whatever it already collected.
    deadline = started + LOG_FETCH_BUDGET_SECONDS
    collected = []

    def collect_logs(client, account, names):
        with flask_app.app_context():
            for app_name in names:
                if time.monotonic() >= deadline:
                    return
                try:
                    collected.append(client.get_logs(
                        app_name, quick_range=quick_range, items_per_page=200,
                        timeout=LOG_REQUEST_TIMEOUT_SECONDS,
                    ))
                except WaasApiError as e:
                    logger.warning(f'Chart data: log fetch failed for "{app_name}": {e}')
                    errors.append(f'{account.account_name}/{app_name}: {e}')

    run_in_pool(
        [partial(collect_logs, client, account, names)
         for client, account, names in sampling_plan],
        max(deadline - time.monotonic(), 0.0),
    )

    attack_timeline = defaultdict(int)  # hour_label -> count
    top_ips = Counter()
    top_attack_types = Counter()
    total_requests = 0
    total_attacks = 0
    apps_sampled = 0

    for logs_resp in collected:
        apps_sampled += 1
        if not isinstance(logs_resp, dict):
            continue
        results = logs_resp.get('results', [])
        total_requests += logs_resp.get('count', len(results))
        _, _, _, attack_count = accumulate_log_entries(
            results, attack_timeline, top_ips, top_attack_types
        )
        total_attacks += attack_count

    planned = sum(len(names) for _, _, names in sampling_plan)
    truncated = apps_sampled < planned
    logger.info(
        f'Chart data: {quick_range} over {len(sampling_plan)} account(s) in '
        f'{time.monotonic() - started:.1f}s — {apps_sampled} of {planned} sampled '
        f'app(s) answered, {apps_total} app(s) total'
    )

    return jsonify(build_chart_payload(
        attack_timeline, top_ips, top_attack_types, server_health,
        total_requests, total_attacks, apps_sampled, apps_total, truncated, errors,
    ))


@bp.route('/about')
def about():
    """About page"""
    return render_template('about.html')
