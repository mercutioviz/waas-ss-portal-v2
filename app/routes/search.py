"""Global search backing the command palette (goal 5).

Local DB resources (accounts, templates, raw configs, reports, users) are
searched directly. Applications/certificates live only in the upstream WaaS
API with no local cache table, so they're only searched when a current
account is in scope, and the raw list is cached in-process for a short TTL
so repeated keystrokes in the palette don't re-hit the API.
"""
import time
from flask import Blueprint, jsonify, request, url_for, g
from flask_login import login_required, current_user
from flask_babel import gettext as _

from app.models import ConfigTemplate, Feature, ScheduledReport, User, get_user_accounts
from app.waas_client import WaasClient, WaasApiError

bp = Blueprint('search', __name__, url_prefix='/search')

MAX_PER_CATEGORY = 5
_CACHE_TTL_SECONDS = 30
_account_resource_cache = {}  # (account_id, resource_type) -> (fetched_at, items)


def _cached_fetch(account_id, resource_type, fetch_fn):
    key = (account_id, resource_type)
    cached = _account_resource_cache.get(key)
    now = time.time()
    if cached and now - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]
    try:
        items = fetch_fn()
    except WaasApiError:
        items = []
    _account_resource_cache[key] = (now, items)
    return items


def _search_accounts(q):
    """Account results switch the persistent scope rather than navigating —
    that's almost always why someone searches an account name from the palette."""
    matches = [a for a in get_user_accounts(current_user) if q in a.account_name.lower()]
    return [{
        'category': 'Accounts',
        'title': a.account_name,
        'subtitle': _('Switch to this account'),
        'action': 'switch_account',
        'account_id': a.id,
        'url': None,
    } for a in matches[:MAX_PER_CATEGORY]]


def _search_templates(q):
    templates = ConfigTemplate.query.filter(
        (ConfigTemplate.user_id == current_user.id) | (ConfigTemplate.is_global == True)  # noqa: E712
    ).all()
    matches = [
        t for t in templates
        if q in t.name.lower() or (t.description and q in t.description.lower())
    ]
    return [{
        'category': 'Templates',
        'title': t.name,
        'subtitle': t.description,
        'url': url_for('templates.view_template', template_id=t.id),
    } for t in matches[:MAX_PER_CATEGORY]]


def _search_raw_configs(q):
    features = Feature.query.filter(
        (Feature.user_id == current_user.id) | (Feature.is_global == True)  # noqa: E712
    ).all()
    matches = [
        f for f in features
        if q in f.name.lower() or (f.description and q in f.description.lower())
    ]
    return [{
        'category': 'Raw Configs',
        'title': f.name,
        'subtitle': f.category,
        'url': url_for('features.view_feature', feature_id=f.id),
    } for f in matches[:MAX_PER_CATEGORY]]


def _search_reports(q):
    reports = ScheduledReport.query.filter_by(user_id=current_user.id).all()
    matches = [r for r in reports if q in r.name.lower()]
    return [{
        'category': 'Reports',
        'title': r.name,
        'subtitle': r.report_type,
        'url': url_for('reports.view_report', report_id=r.id),
    } for r in matches[:MAX_PER_CATEGORY]]


def _search_users(q):
    if current_user.role != 'admin':
        return []
    users = User.query.all()
    matches = [
        u for u in users
        if q in u.username.lower() or q in u.email.lower() or q in u.display_name.lower()
    ]
    return [{
        'category': 'Users',
        'title': u.display_name,
        'subtitle': u.email,
        'url': url_for('admin.edit_user', user_id=u.id),
    } for u in matches[:MAX_PER_CATEGORY]]


def _search_applications(q, account):
    apps = _cached_fetch(account.id, 'applications', lambda: _fetch_app_list(account))
    matches = [a for a in apps if q in a.get('name', '').lower()]
    return [{
        'category': 'Applications',
        'title': a.get('name', ''),
        'subtitle': account.account_name,
        'url': url_for('applications.view_application', account_id=account.id, app_id=a.get('name', '')),
    } for a in matches[:MAX_PER_CATEGORY]]


def _fetch_app_list(account):
    client = WaasClient.from_account(account)
    result = client.list_applications()
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        return result.get('results', result.get('data', []))
    return []


def _search_certificates(q, account):
    certs = _cached_fetch(account.id, 'certificates', lambda: _fetch_cert_list(account))

    def _cert_name(c):
        return c.get('friendly_name') or c.get('common_name') or c.get('name') or ''

    matches = [c for c in certs if q in _cert_name(c).lower()]
    return [{
        'category': 'Certificates',
        'title': _cert_name(c),
        'subtitle': account.account_name,
        'url': url_for('certificates.list_certificates', account_id=account.id),
    } for c in matches[:MAX_PER_CATEGORY]]


def _fetch_cert_list(account):
    client = WaasClient.from_account(account)
    result = client.list_certificates()
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        return result.get('results', result.get('data', []))
    return []


@bp.route('/api')
@login_required
def search_api():
    """Global search across local resources and the current account's
    applications/certificates. Returns a flat, category-tagged result list."""
    q = request.args.get('q', '').strip().lower()
    if len(q) < 2:
        return jsonify({'results': []})

    results = []
    results.extend(_search_accounts(q))
    results.extend(_search_templates(q))
    results.extend(_search_raw_configs(q))
    results.extend(_search_reports(q))
    results.extend(_search_users(q))

    account = getattr(g, 'current_account', None)
    if account:
        results.extend(_search_applications(q, account))
        results.extend(_search_certificates(q, account))

    return jsonify({'results': results})
