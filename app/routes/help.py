"""Help system blueprint — contextual documentation pages."""

from flask import Blueprint, render_template
from flask_login import login_required

bp = Blueprint('help', __name__, url_prefix='/help')


@bp.route('/')
@login_required
def index():
    """Main help page with topic overview."""
    return render_template('help/index.html')


@bp.route('/accounts')
@login_required
def accounts():
    """Help for WaaS account management."""
    return render_template('help/accounts.html')


@bp.route('/applications')
@login_required
def applications():
    """Help for application management."""
    return render_template('help/applications.html')


@bp.route('/security')
@login_required
def security():
    """Help for security configuration."""
    return render_template('help/security.html')


@bp.route('/certificates')
@login_required
def certificates():
    """Help for certificate management."""
    return render_template('help/certificates.html')


@bp.route('/logs')
@login_required
def logs():
    """Help for log analysis."""
    return render_template('help/logs.html')


@bp.route('/templates')
@login_required
def templates():
    """Help for config templates."""
    return render_template('help/templates.html')


@bp.route('/raw-configs')
@login_required
def raw_configs():
    """Help for raw config management."""
    return render_template('help/raw_configs.html')


@bp.route('/reports')
@login_required
def reports():
    """Help for scheduled reports."""
    return render_template('help/reports.html')


@bp.route('/bulk-operations')
@login_required
def bulk_operations():
    """Help for bulk operations."""
    return render_template('help/bulk_operations.html')
