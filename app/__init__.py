import os
import logging
from flask import Flask, render_template, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_babel import Babel
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
from flask_apscheduler import APScheduler
from flask_socketio import SocketIO
from werkzeug.middleware.proxy_fix import ProxyFix
from config import config
from datetime import datetime

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
babel = Babel()
limiter = Limiter(key_func=get_remote_address, default_limits=["60 per minute"], storage_uri="memory://")
mail = Mail()
scheduler = APScheduler()
socketio = SocketIO()


def get_locale():
    """Select locale: user preference → session → Accept-Language header → default."""
    supported = config.get('default', config['default']).BABEL_SUPPORTED_LOCALES

    # Check authenticated user's stored preference
    if current_user and hasattr(current_user, 'locale') and getattr(current_user, 'is_authenticated', False):
        user_locale = getattr(current_user, 'locale', None)
        if user_locale and user_locale in supported:
            return user_locale

    # Check session
    sess_locale = session.get('locale')
    if sess_locale and sess_locale in supported:
        return sess_locale

    # Fall back to browser Accept-Language
    return request.accept_languages.best_match(supported, default='en')


def get_theme():
    """Select theme: user preference -> session -> default 'light'."""
    if current_user and hasattr(current_user, 'theme') and getattr(current_user, 'is_authenticated', False):
        user_theme = getattr(current_user, 'theme', None)
        if user_theme in ('light', 'dark'):
            return user_theme
    sess_theme = session.get('theme')
    if sess_theme in ('light', 'dark'):
        return sess_theme
    return 'light'


def create_app(config_name='default'):
    """Application factory pattern"""
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Trust the nginx reverse proxy headers
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Configure logging - ensure WaaS API client logs are visible
    logging.basicConfig(level=logging.DEBUG if app.debug else logging.INFO)
    # Set WaaS client logger to DEBUG so we see request/response details
    waas_logger = logging.getLogger('app.waas_client')
    waas_logger.setLevel(logging.DEBUG)

    # Initialize config-specific setup
    config[config_name].init_app(app)

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    babel.init_app(app, locale_selector=get_locale)
    limiter.init_app(app)
    mail.init_app(app)
    socketio.init_app(app, async_mode='gevent', cors_allowed_origins='*')

    # Configure Flask-Login
    from flask_babel import lazy_gettext as _l
    login_manager.login_view = 'auth.login'
    login_manager.login_message = _l('Please log in to access this page.')
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        """Load user by ID for Flask-Login"""
        from app.models import User
        return db.session.get(User, int(user_id))

    # Register custom template filters
    @app.template_filter('datetime_format')
    def datetime_format(value, fmt='%Y-%m-%d %H:%M:%S'):
        """Format a datetime object"""
        if value is None:
            return 'N/A'
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except ValueError:
                return value
        return value.strftime(fmt)

    @app.template_filter('filesizeformat')
    def filesizeformat(bytes_val):
        """Format file size in human-readable format"""
        try:
            bytes_val = float(bytes_val)
            if bytes_val < 1024:
                return f"{bytes_val:.0f} B"
            elif bytes_val < 1024 * 1024:
                return f"{bytes_val / 1024:.1f} KB"
            elif bytes_val < 1024 * 1024 * 1024:
                return f"{bytes_val / (1024 * 1024):.1f} MB"
            else:
                return f"{bytes_val / (1024 * 1024 * 1024):.1f} GB"
        except (ValueError, TypeError):
            return '0 B'

    @app.template_filter('epoch_ms')
    def epoch_ms_format(value, fmt='%Y-%m-%d %H:%M:%S'):
        """Convert epoch milliseconds to human-readable datetime string.

        WaaS API returns timestamps as epoch milliseconds (e.g. 1772472596562).
        """
        if value is None:
            return 'N/A'
        try:
            epoch_ms = int(value)
            epoch_s = epoch_ms / 1000.0
            dt = datetime.utcfromtimestamp(epoch_s)
            return dt.strftime(fmt)
        except (ValueError, TypeError, OSError):
            return str(value)

    @app.template_filter('null_dash')
    def null_dash_filter(value):
        """Replace WaaS null marker '"-"' with an em-dash for display."""
        if value is None:
            return '—'
        s = str(value).strip()
        if s in ('"-"', '"-"', '-', ''):
            return '—'
        return s

    # Context processor to inject version and date into all templates
    @app.context_processor
    def inject_version():
        """Make version available to all templates"""
        from config import VERSION
        return {'app_version': VERSION, 'today_date': datetime.utcnow().date()}

    # Context processor to inject locale into all templates
    @app.context_processor
    def inject_locale():
        """Make get_locale available to all templates"""
        return {'get_locale': get_locale}

    # Context processor to inject theme into all templates
    @app.context_processor
    def inject_theme():
        """Make get_theme available to all templates"""
        return {'get_theme': get_theme}

    # Context processor to inject unread notification count
    @app.context_processor
    def inject_notification_count():
        if current_user and getattr(current_user, 'is_authenticated', False):
            from app.models import Notification
            return {'notification_count': Notification.unread_count(current_user.id)}
        return {'notification_count': 0}

    # Context processor to inject CSRF token function
    @app.context_processor
    def inject_csrf_token():
        """Make CSRF token generation available to all templates"""
        from flask_wtf.csrf import generate_csrf
        return {'csrf_token': generate_csrf}

    # Register blueprints
    from app.routes import main, auth, admin, accounts, applications, certificates, logs, proxy, templates, reports, features
    from app.routes import help as help_bp
    app.register_blueprint(main.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(accounts.bp)
    app.register_blueprint(applications.bp)
    app.register_blueprint(certificates.bp)
    app.register_blueprint(logs.bp)
    app.register_blueprint(proxy.bp)
    app.register_blueprint(templates.bp)
    app.register_blueprint(features.bp)
    app.register_blueprint(features.legacy_bp)  # 301 redirect /features/* -> /raw-configs/*
    app.register_blueprint(reports.bp)
    app.register_blueprint(help_bp.bp)

    # Register SocketIO event handlers
    from app import socketio_events  # noqa: F401

    # Register error handlers
    @app.errorhandler(404)
    def handle_404(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(403)
    def handle_403(e):
        return render_template('errors/403.html'), 403

    @app.errorhandler(429)
    def handle_429(e):
        return render_template('errors/429.html'), 429

    @app.errorhandler(500)
    def handle_500(e):
        return render_template('errors/500.html'), 500

    # Create database tables
    with app.app_context():
        db.create_all()

        # Manual ALTER TABLE migrations for SQLite (add columns if missing)
        import sqlite3
        _db_path = app.config.get('SQLALCHEMY_DATABASE_URI', '').replace('sqlite:///', '')
        if _db_path and os.path.exists(_db_path):
            _conn = sqlite3.connect(_db_path)
            _cursor = _conn.cursor()
            _migrations = [
                ('waas_accounts', 'api_key_expiry', 'DATE'),
                ('users', 'notify_apikey_expiry_email', 'BOOLEAN DEFAULT 1'),
                ('users', 'notify_apikey_expiry_inapp', 'BOOLEAN DEFAULT 1'),
            ]
            for _table, _col, _coltype in _migrations:
                try:
                    _cursor.execute(f'ALTER TABLE {_table} ADD COLUMN {_col} {_coltype}')
                except sqlite3.OperationalError:
                    pass  # column already exists
            _conn.commit()
            _conn.close()

        # Initialize default system settings if not present
        from app.models import SystemSettings
        if not SystemSettings.get_setting('app_name'):
            SystemSettings.set_setting(
                'app_name',
                'WaaS Self-Service Portal',
                value_type='string',
                user_id=None
            )

    # Start scheduler (avoid double-start in debug reloader)
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        from app.report_service import run_scheduled_reports

        scheduler.init_app(app)

        @scheduler.task('interval', id='run_scheduled_reports', minutes=15, misfire_grace_time=300)
        def _run_reports_job():
            run_scheduled_reports(app)

        scheduler.start()

    return app