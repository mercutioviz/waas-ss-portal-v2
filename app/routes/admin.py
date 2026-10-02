from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from flask_babel import gettext as _
from functools import wraps
from app import db
from app.models import User, WaasAccount, AuditLog
from app.forms import UserCreateForm, UserEditForm
from app import limiter

bp = Blueprint('admin', __name__, url_prefix='/admin')


def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash(_('You do not have permission to access the admin area.'), 'danger')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return decorated_function


@bp.route('/')
@login_required
@admin_required
def index():
    """Admin dashboard"""
    user_count = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    account_count = WaasAccount.query.count()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()

    from flask import current_app
    from app.logpull.store import corpus_bytes

    return render_template(
        'admin/index.html',
        user_count=user_count,
        active_users=active_users,
        account_count=account_count,
        recent_logs=recent_logs,
        logpull_bytes=corpus_bytes(current_app.instance_path),
    )


@bp.route('/users')
@login_required
@admin_required
def list_users():
    """List all users"""
    users = User.query.order_by(User.username).all()
    return render_template('admin/users.html', users=users)


@bp.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
@limiter.limit("10 per minute", methods=["POST"])
def create_user():
    """Create a new user"""
    form = UserCreateForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            first_name=form.display_name.data or form.username.data,
            role=form.role.data,
            is_active=True
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='user_create',
            resource_type='user',
            resource_id=user.id,
            details=f'Created user: {user.username} (role: {user.role})',
            ip_address=request.remote_addr
        )

        flash(_('User "%(username)s" created successfully.', username=user.username), 'success')
        return redirect(url_for('admin.list_users'))

    return render_template('admin/user_create.html', form=form)


@bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
@limiter.limit("20 per minute", methods=["POST"])
def edit_user(user_id):
    """Edit a user"""
    user = User.query.get_or_404(user_id)
    form = UserEditForm(obj=user)

    if form.validate_on_submit():
        user.email = form.email.data
        user.first_name = form.display_name.data
        user.role = form.role.data
        user.is_active = form.is_active.data

        if form.new_password.data:
            user.set_password(form.new_password.data)

        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='user_edit',
            resource_type='user',
            resource_id=user.id,
            details=f'Edited user: {user.username}',
            ip_address=request.remote_addr
        )

        flash(_('User "%(username)s" updated.', username=user.username), 'success')
        return redirect(url_for('admin.list_users'))

    return render_template('admin/user_edit.html', form=form, edit_user=user)


@bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
@limiter.limit("20 per minute")
def toggle_user(user_id):
    """Enable/disable a user"""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash(_('You cannot disable your own account.'), 'danger')
        return redirect(url_for('admin.list_users'))

    user.is_active = not user.is_active
    db.session.commit()

    action = 'enabled' if user.is_active else 'disabled'
    AuditLog.log(
        user_id=current_user.id,
        action=f'user_{action}',
        resource_type='user',
        resource_id=user.id,
        details=f'User {user.username} {action}',
        ip_address=request.remote_addr
    )

    if user.is_active:
        flash(_('User "%(username)s" has been enabled.', username=user.username), 'success')
    else:
        flash(_('User "%(username)s" has been disabled.', username=user.username), 'success')
    return redirect(url_for('admin.list_users'))


@bp.route('/audit-log')
@login_required
@admin_required
def audit_log():
    """View audit log"""
    page = request.args.get('page', 1, type=int)
    per_page = 50

    # Optional filters
    user_filter = request.args.get('user_id', type=int)
    action_filter = request.args.get('action')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    query = AuditLog.query

    if user_filter:
        query = query.filter_by(user_id=user_filter)
    if action_filter:
        query = query.filter_by(action=action_filter)
    if date_from:
        from datetime import datetime
        try:
            query = query.filter(AuditLog.timestamp >= datetime.strptime(date_from, '%Y-%m-%d'))
        except ValueError:
            pass
    if date_to:
        from datetime import datetime, timedelta
        try:
            query = query.filter(AuditLog.timestamp < datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1))
        except ValueError:
            pass

    logs = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    users = User.query.order_by(User.username).all()
    actions = db.session.query(AuditLog.action).distinct().order_by(AuditLog.action).all()
    actions = [a[0] for a in actions]

    return render_template(
        'admin/audit_log.html',
        logs=logs,
        users=users,
        actions=actions,
        user_filter=user_filter,
        action_filter=action_filter,
        date_from=date_from,
        date_to=date_to,
    )


# --- Storage utilities -----------------------------------------------------

@bp.route('/storage')
@login_required
@admin_required
def storage():
    """Disk usage for log pulls, with manual cleanup.

    Pulled log rows are the only thing the portal writes that reaches
    gigabytes, so this is where an admin goes when the disk is filling. The
    retention sweep runs nightly; this page is the manual override.
    """
    import shutil

    from flask import current_app
    from app.background_tasks import (
        LOG_PULL_RAW_RETENTION_DAYS,
        LOG_PULL_RESULT_RETENTION_DAYS,
    )
    from app.logpull.preflight import MAX_TOTAL_BYTES
    from app.logpull.store import PullStore, corpus_bytes
    from app.models import LogPull

    pulls = LogPull.query.order_by(LogPull.created_at.desc()).all()
    rows = []
    for pull in pulls:
        store = PullStore(current_app.instance_path, pull.id)
        rows.append({'pull': pull, 'size': store.size_bytes()})

    usage = shutil.disk_usage(current_app.instance_path)
    total = corpus_bytes(current_app.instance_path)

    return render_template(
        'admin/storage.html',
        rows=rows,
        corpus_bytes=total,
        corpus_max_bytes=MAX_TOTAL_BYTES,
        disk_free=usage.free,
        disk_total=usage.total,
        raw_retention_days=LOG_PULL_RAW_RETENTION_DAYS,
        result_retention_days=LOG_PULL_RESULT_RETENTION_DAYS,
    )


@bp.route('/storage/<int:pull_id>/delete-raw', methods=['POST'])
@login_required
@admin_required
def storage_delete_raw(pull_id):
    """Drop the bulk rows but keep the pull and its analysis."""
    from flask import current_app
    from app.logpull.store import PullStore
    from app.models import LogPull

    pull = LogPull.query.get_or_404(pull_id)
    if pull.is_active:
        flash(_('That pull is still running. Cancel it first.'), 'warning')
        return redirect(url_for('admin.storage'))

    freed = PullStore(current_app.instance_path, pull.id).delete_raw()
    pull.raw_deleted = True
    pull.bytes_on_disk = PullStore(current_app.instance_path, pull.id).size_bytes()
    db.session.commit()

    AuditLog.log(user_id=current_user.id, action='logpull_delete_raw',
                 details=f'Deleted raw rows for log pull #{pull.id} '
                         f'({freed / 1e6:.1f} MB freed)')
    flash(_('Freed %(mb).1f MB. The analysis for that pull is still available.',
            mb=freed / 1e6), 'success')
    return redirect(url_for('admin.storage'))


@bp.route('/storage/<int:pull_id>/delete', methods=['POST'])
@login_required
@admin_required
def storage_delete_pull(pull_id):
    from flask import current_app
    from app.logpull.store import PullStore
    from app.models import LogPull

    pull = LogPull.query.get_or_404(pull_id)
    if pull.is_active:
        flash(_('That pull is still running. Cancel it first.'), 'warning')
        return redirect(url_for('admin.storage'))

    freed = PullStore(current_app.instance_path, pull.id).delete_all()
    label = f'#{pull.id} ({pull.app_name})'
    db.session.delete(pull)
    db.session.commit()

    AuditLog.log(user_id=current_user.id, action='logpull_delete',
                 details=f'Deleted log pull {label} ({freed / 1e6:.1f} MB freed)')
    flash(_('Deleted pull %(label)s and freed %(mb).1f MB.', label=label,
            mb=freed / 1e6), 'success')
    return redirect(url_for('admin.storage'))


@bp.route('/storage/reap', methods=['POST'])
@login_required
@admin_required
def storage_reap():
    """Run the retention sweep now instead of waiting for the nightly cron."""
    from flask import current_app
    from app.background_tasks import run_log_pull_cleanup

    affected = run_log_pull_cleanup(current_app._get_current_object())
    AuditLog.log(user_id=current_user.id, action='logpull_reap',
                 details=f'Manual retention sweep affected {affected} pull(s)')
    flash(_('Retention sweep complete: %(n)s pull(s) affected.', n=affected), 'success')
    return redirect(url_for('admin.storage'))
