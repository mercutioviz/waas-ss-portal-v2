import os
from datetime import timedelta
from pathlib import Path

basedir = os.path.abspath(os.path.dirname(__file__))

# Application version
VERSION = '2.0.0-dev'


class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        f'sqlite:///{os.path.join(basedir, "instance", "waas-portal-v2.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # WaaS API base URLs (includes version prefix)
    WAAS_API_BASE_URL = os.environ.get('WAAS_API_BASE_URL') or 'https://api.waas.barracudanetworks.com/v4/waasapi'
    WAAS_API_V2_BASE_URL = os.environ.get('WAAS_API_V2_BASE_URL') or 'https://api.waas.barracudanetworks.com/v2/waasapi'

    # WaaS API settings
    WAAS_API_TIMEOUT = 30
    WAAS_API_RETRY_TOTAL = 1

    # Pagination
    ITEMS_PER_PAGE = 20

    # Internationalization
    BABEL_DEFAULT_LOCALE = 'en'
    BABEL_SUPPORTED_LOCALES = ['en', 'es']

    # File upload (for certificate files)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max
    UPLOAD_FOLDER = os.path.join(basedir, 'uploads')

    # Email (Flask-Mail)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'localhost')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'waas-portal@localhost')

    # Rate limiting
    RATELIMIT_STORAGE_URI = 'memory://'
    RATELIMIT_STRATEGY = 'fixed-window'

    # Scheduler (Flask-APScheduler)
    SCHEDULER_API_ENABLED = False

    @classmethod
    def init_app(cls, app):
        """Initialize application-specific configuration"""
        # Ensure upload directory exists
        upload_dir = Path(cls.UPLOAD_FOLDER)
        try:
            upload_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError) as e:
            app.logger.warning(f"Could not create upload directory {upload_dir}: {e}")

        # Ensure instance directory exists for SQLite
        instance_dir = Path(os.path.join(basedir, 'instance'))
        try:
            instance_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError) as e:
            app.logger.warning(f"Could not create instance directory {instance_dir}: {e}")


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}