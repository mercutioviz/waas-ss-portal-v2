from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_babel import gettext as _
from datetime import datetime
from app import db
from app.models import User, AuditLog, Notification
from app.forms import LoginForm, ChangePasswordForm, NotificationPreferencesForm
from app import limiter

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        # Account lockout check
        if user and (user.failed_login_attempts or 0) >= 5 and user.last_failed_login:
            lockout_duration = 15  # minutes
            elapsed = (datetime.utcnow() - user.last_failed_login).total_seconds() / 60
            if elapsed < lockout_duration:
                remaining = int(lockout_duration - elapsed) + 1
                flash(_('Account locked due to too many failed attempts. Try again in %(remaining)s minutes.', remaining=remaining), 'danger')
                return render_template('auth/login.html', form=form)
            else:
                # Lockout expired — reset counter
                user.failed_login_attempts = 0
                db.session.commit()

        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash(_('Your account has been disabled. Contact an administrator.'), 'danger')
                return render_template('auth/login.html', form=form)

            login_user(user, remember=form.remember_me.data)
            session.permanent = True

            # Update login tracking
            user.last_login = datetime.utcnow()
            user.login_count = (user.login_count or 0) + 1
            user.failed_login_attempts = 0
            db.session.commit()

            # Audit log
            AuditLog.log(
                user_id=user.id,
                action='login',
                details='Successful login',
                ip_address=request.remote_addr,
                user_agent=str(request.user_agent)[:255]
            )

            flash(_('Welcome back, %(name)s!', name=user.display_name), 'success')

            # Redirect to requested page or dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('main.dashboard'))
        else:
            # Track failed login
            if user:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                user.last_failed_login = datetime.utcnow()
                db.session.commit()

            flash(_('Invalid username or password.'), 'danger')

    return render_template('auth/login.html', form=form)


@bp.route('/logout')
@login_required
def logout():
    """User logout"""
    AuditLog.log(
        user_id=current_user.id,
        action='logout',
        details='User logged out',
        ip_address=request.remote_addr
    )
    logout_user()
    flash(_('You have been logged out.'), 'info')
    return redirect(url_for('auth.login'))


@bp.route('/change-password', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute", methods=["POST"])
def change_password():
    """Change current user's password"""
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash(_('Current password is incorrect.'), 'danger')
            return render_template('auth/change_password.html', form=form)

        current_user.set_password(form.new_password.data)
        db.session.commit()

        AuditLog.log(
            user_id=current_user.id,
            action='password_change',
            details='Password changed by user',
            ip_address=request.remote_addr
        )

        flash(_('Your password has been updated.'), 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('auth/change_password.html', form=form)


@bp.route('/keepalive', methods=['POST'])
@login_required
@limiter.limit("100 per minute")
def keepalive():
    """Touch session to keep it alive"""
    session.modified = True
    return jsonify({'status': 'ok'})


@bp.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("3 per minute", methods=["POST"])
def forgot_password():
    """Send password reset email."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user = User.query.filter_by(email=email).first() if email else None
        if user and user.is_active:
            from itsdangerous import URLSafeTimedSerializer
            s = URLSafeTimedSerializer(current_app.secret_key)
            token = s.dumps(user.id, salt='password-reset')
            reset_url = url_for('auth.reset_password', token=token, _external=True)
            try:
                from flask_mail import Message
                from app import mail
                msg = Message(
                    _('WaaS Portal — Password Reset'),
                    recipients=[user.email],
                )
                msg.body = _(
                    'Hi %(name)s,\n\nClick the link below to reset your password:\n\n%(url)s\n\n'
                    'This link expires in 1 hour.\n\nIf you did not request this, ignore this email.',
                    name=user.display_name, url=reset_url
                )
                mail.send(msg)
            except Exception:
                pass
        flash(_('If an account with that email exists, a reset link has been sent.'), 'info')
        return redirect(url_for('auth.login'))
    return render_template('auth/forgot_password.html')


@bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password using a token from the email link."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
    s = URLSafeTimedSerializer(current_app.secret_key)
    try:
        user_id = s.loads(token, salt='password-reset', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash(_('Invalid or expired reset link. Please request a new one.'), 'danger')
        return redirect(url_for('auth.forgot_password'))
    user = User.query.get(user_id)
    if not user or not user.is_active:
        flash(_('User not found.'), 'danger')
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('password_confirm', '')
        if len(password) < 8:
            flash(_('Password must be at least 8 characters.'), 'danger')
            return render_template('auth/reset_password.html')
        if password != confirm:
            flash(_('Passwords do not match.'), 'danger')
            return render_template('auth/reset_password.html')
        from werkzeug.security import generate_password_hash
        user.password_hash = generate_password_hash(password)
        db.session.commit()
        AuditLog.log(
            user_id=user.id, action='password_reset',
            resource_type='user', resource_id=user.id,
            details='Password reset via email link',
            ip_address=request.remote_addr,
        )
        flash(_('Password has been reset. You can now log in.'), 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html')


@bp.route('/profile')
@login_required
def profile():
    """View current user profile"""
    return render_template('auth/profile.html')


@bp.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    """Update user profile fields."""
    from app import db
    current_user.first_name = request.form.get('first_name', '').strip() or None
    current_user.last_name = request.form.get('last_name', '').strip() or None
    email = request.form.get('email', '').strip()
    if email:
        current_user.email = email
    db.session.commit()
    flash(_('Profile updated.'), 'success')
    return redirect(url_for('auth.profile'))


@bp.route('/update-preferences', methods=['POST'])
@login_required
def update_preferences():
    """Toggle display preferences."""
    from app import db
    current_user.show_technical = 'show_technical' in request.form
    db.session.commit()
    flash(_('Preferences updated.'), 'success')
    return redirect(url_for('auth.profile'))


@bp.route('/set-locale', methods=['POST'])
def set_locale():
    """Set the user's preferred locale."""
    locale = request.form.get('locale', 'en')
    supported = current_app.config.get('BABEL_SUPPORTED_LOCALES', ['en', 'es'])
    if locale not in supported:
        locale = 'en'

    session['locale'] = locale

    if current_user.is_authenticated:
        current_user.locale = locale
        db.session.commit()

    next_url = request.form.get('next') or request.referrer or url_for('main.dashboard')
    return redirect(next_url)


@bp.route('/set-theme', methods=['POST'])
def set_theme():
    """Set the user's preferred theme (light/dark)."""
    theme = request.form.get('theme', 'light')
    if theme not in ('light', 'dark'):
        theme = 'light'

    session['theme'] = theme

    if current_user.is_authenticated:
        current_user.theme = theme
        db.session.commit()

    next_url = request.form.get('next') or request.referrer or url_for('main.dashboard')
    return redirect(next_url)


@bp.route('/notification-preferences', methods=['GET', 'POST'])
@login_required
def notification_preferences():
    """View and update notification preferences"""
    form = NotificationPreferencesForm()
    if form.validate_on_submit():
        current_user.notify_report_email = form.notify_report_email.data
        current_user.notify_report_inapp = form.notify_report_inapp.data
        current_user.notify_cert_expiry_email = form.notify_cert_expiry_email.data
        current_user.notify_cert_expiry_inapp = form.notify_cert_expiry_inapp.data
        current_user.notify_apikey_expiry_email = form.notify_apikey_expiry_email.data
        current_user.notify_apikey_expiry_inapp = form.notify_apikey_expiry_inapp.data
        db.session.commit()
        flash(_('Notification preferences saved.'), 'success')
        return redirect(url_for('auth.profile'))

    # Pre-populate form from current user
    if request.method == 'GET':
        form.notify_report_email.data = current_user.notify_report_email if current_user.notify_report_email is not None else True
        form.notify_report_inapp.data = current_user.notify_report_inapp if current_user.notify_report_inapp is not None else True
        form.notify_cert_expiry_email.data = current_user.notify_cert_expiry_email if current_user.notify_cert_expiry_email is not None else True
        form.notify_cert_expiry_inapp.data = current_user.notify_cert_expiry_inapp if current_user.notify_cert_expiry_inapp is not None else True
        form.notify_apikey_expiry_email.data = current_user.notify_apikey_expiry_email if current_user.notify_apikey_expiry_email is not None else True
        form.notify_apikey_expiry_inapp.data = current_user.notify_apikey_expiry_inapp if current_user.notify_apikey_expiry_inapp is not None else True

    return render_template('auth/notification_preferences.html', form=form)


@bp.route('/notifications')
@login_required
def notifications():
    """Full notifications list page"""
    notifs = Notification.get_recent(current_user.id, limit=50)
    return render_template('auth/notifications.html', notifications=notifs)


@bp.route('/notifications/api')
@login_required
def notifications_api():
    """JSON API: recent notifications + unread count for navbar AJAX"""
    notifs = Notification.get_recent(current_user.id, limit=10)
    return jsonify({
        'unread_count': Notification.unread_count(current_user.id),
        'notifications': [
            {
                'id': n.id,
                'type': n.type,
                'title': n.title,
                'message': n.message,
                'link': n.link,
                'is_read': n.is_read,
                'created_at': n.created_at.isoformat() if n.created_at else None,
            }
            for n in notifs
        ],
    })


@bp.route('/notifications/read/<int:id>', methods=['POST'])
@login_required
def notification_mark_read(id):
    """Mark a single notification as read"""
    notif = Notification.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    notif.is_read = True
    db.session.commit()
    return jsonify({'status': 'ok'})


@bp.route('/notifications/read-all', methods=['POST'])
@login_required
def notification_mark_all_read():
    """Mark all notifications as read"""
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'status': 'ok'})
    flash(_('All notifications marked as read.'), 'success')
    return redirect(url_for('auth.notifications'))
