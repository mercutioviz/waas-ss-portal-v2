import json
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_
from app import db


class User(UserMixin, db.Model):
    """Model for user accounts"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    role = db.Column(db.String(20), nullable=False, default='user')  # admin, user, viewer
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    login_count = db.Column(db.Integer, default=0)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime)
    locale = db.Column(db.String(10), default='en')
    theme = db.Column(db.String(10), default='light')
    show_technical = db.Column(db.Boolean, default=False)

    # Notification preferences
    notify_report_email = db.Column(db.Boolean, default=True)
    notify_report_inapp = db.Column(db.Boolean, default=True)
    notify_cert_expiry_email = db.Column(db.Boolean, default=True)
    notify_cert_expiry_inapp = db.Column(db.Boolean, default=True)
    notify_apikey_expiry_email = db.Column(db.Boolean, default=True)
    notify_apikey_expiry_inapp = db.Column(db.Boolean, default=True)

    # Relationships
    waas_accounts = db.relationship('WaasAccount', backref='owner', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        """Check if user is admin"""
        return self.role == 'admin'

    @property
    def display_name(self):
        """Return display name"""
        if self.first_name and self.last_name:
            return f'{self.first_name} {self.last_name}'
        elif self.first_name:
            return self.first_name
        return self.username

    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'login_count': self.login_count,
            'waas_account_count': self.waas_accounts.count()
        }


class WaasAccount(db.Model):
    """Model for WaaS API accounts linked to a portal user"""
    __tablename__ = 'waas_accounts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    account_name = db.Column(db.String(100), nullable=False)
    api_key_encrypted = db.Column(db.Text, nullable=True)  # v4 API key (optional if v2 creds provided)
    waas_account_id = db.Column(db.String(100))  # Account ID from WaaS API
    is_active = db.Column(db.Boolean, default=True)
    last_verified = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    # API key expiry tracking
    api_key_expiry = db.Column(db.Date, nullable=True)

    # v2 API credentials (email/password login)
    waas_email_encrypted = db.Column(db.Text, nullable=True)
    waas_password_encrypted = db.Column(db.Text, nullable=True)

    # Cached v2 auth token
    v2_auth_token_encrypted = db.Column(db.Text, nullable=True)
    v2_token_expiry = db.Column(db.Integer, nullable=True)  # Unix timestamp

    def __repr__(self):
        return f'<WaasAccount {self.id}: {self.account_name}>'

    @property
    def api_key(self):
        """Decrypt and return API key"""
        if self.api_key_encrypted:
            from app.encryption import decrypt_value
            return decrypt_value(self.api_key_encrypted)
        return None

    @api_key.setter
    def api_key(self, value):
        """Encrypt and store API key"""
        if value:
            from app.encryption import encrypt_value
            self.api_key_encrypted = encrypt_value(value)
        else:
            self.api_key_encrypted = None

    @property
    def waas_email(self):
        """Decrypt and return WaaS email"""
        if self.waas_email_encrypted:
            from app.encryption import decrypt_value
            return decrypt_value(self.waas_email_encrypted)
        return None

    @waas_email.setter
    def waas_email(self, value):
        """Encrypt and store WaaS email"""
        if value:
            from app.encryption import encrypt_value
            self.waas_email_encrypted = encrypt_value(value)
        else:
            self.waas_email_encrypted = None

    @property
    def waas_password(self):
        """Decrypt and return WaaS password"""
        if self.waas_password_encrypted:
            from app.encryption import decrypt_value
            return decrypt_value(self.waas_password_encrypted)
        return None

    @waas_password.setter
    def waas_password(self, value):
        """Encrypt and store WaaS password"""
        if value:
            from app.encryption import encrypt_value
            self.waas_password_encrypted = encrypt_value(value)
        else:
            self.waas_password_encrypted = None

    @property
    def v2_auth_token(self):
        """Decrypt and return cached v2 auth token"""
        if self.v2_auth_token_encrypted:
            from app.encryption import decrypt_value
            return decrypt_value(self.v2_auth_token_encrypted)
        return None

    @v2_auth_token.setter
    def v2_auth_token(self, value):
        """Encrypt and store v2 auth token"""
        if value:
            from app.encryption import encrypt_value
            self.v2_auth_token_encrypted = encrypt_value(value)
        else:
            self.v2_auth_token_encrypted = None

    @property
    def has_api_key(self):
        """Check if v4 API key is configured"""
        return bool(self.api_key_encrypted)

    @property
    def has_v2_credentials(self):
        """Check if v2 email/password credentials are configured"""
        return bool(self.waas_email_encrypted and self.waas_password_encrypted)

    @property
    def v2_token_valid(self):
        """Check if cached v2 auth token is still valid (with 60s buffer)"""
        import time
        if not self.v2_auth_token_encrypted or not self.v2_token_expiry:
            return False
        return self.v2_token_expiry > (int(time.time()) + 60)

    def to_dict(self):
        """Convert to dictionary (no sensitive data)"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'account_name': self.account_name,
            'waas_account_id': self.waas_account_id,
            'is_active': self.is_active,
            'has_api_key': self.has_api_key,
            'has_v2_credentials': self.has_v2_credentials,
            'last_verified': self.last_verified.isoformat() if self.last_verified else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class AuditLog(db.Model):
    """Model for audit logging system actions"""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(50), index=True)
    resource_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Relationship
    user = db.relationship('User', backref='audit_logs')

    def __repr__(self):
        return f'<AuditLog {self.id}: {self.action} by User {self.user_id}>'

    @staticmethod
    def log(user_id, action, resource_type=None, resource_id=None, details=None, ip_address=None, user_agent=None):
        """Convenience method to create audit log entry"""
        log_entry = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.session.add(log_entry)
        db.session.commit()
        return log_entry

    def to_dict(self):
        """Convert audit log to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


class ProxySession(db.Model):
    """Model for noVNC browser proxy sessions"""
    __tablename__ = 'proxy_sessions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    account_id = db.Column(db.Integer, db.ForeignKey('waas_accounts.id'), nullable=False, index=True)
    app_id = db.Column(db.String(200), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    cname = db.Column(db.String(255))
    cname_ip = db.Column(db.String(45))

    # Process resources
    display_number = db.Column(db.Integer)
    vnc_port = db.Column(db.Integer)
    websocket_port = db.Column(db.Integer)

    # Process IDs
    xvfb_pid = db.Column(db.Integer)
    chromium_pid = db.Column(db.Integer)
    vnc_pid = db.Column(db.Integer)
    websockify_pid = db.Column(db.Integer)

    # Status: starting, active, stopped, error
    status = db.Column(db.String(20), nullable=False, default='starting', index=True)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    stopped_at = db.Column(db.DateTime)

    # Relationships
    user = db.relationship('User', backref=db.backref('proxy_sessions', lazy='dynamic'))
    account = db.relationship('WaasAccount', backref=db.backref('proxy_sessions', lazy='dynamic'))

    def __repr__(self):
        return f'<ProxySession {self.id}: {self.domain} [{self.status}]>'

    @property
    def is_active(self):
        """Check if session is currently active"""
        return self.status in ('starting', 'active')

    @property
    def elapsed_seconds(self):
        """Return seconds since session started"""
        if not self.started_at:
            return 0
        end = self.stopped_at or datetime.utcnow()
        return int((end - self.started_at).total_seconds())

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'account_id': self.account_id,
            'app_id': self.app_id,
            'domain': self.domain,
            'cname': self.cname,
            'cname_ip': self.cname_ip,
            'display_number': self.display_number,
            'vnc_port': self.vnc_port,
            'websocket_port': self.websocket_port,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'stopped_at': self.stopped_at.isoformat() if self.stopped_at else None,
            'elapsed_seconds': self.elapsed_seconds,
        }


class SystemSettings(db.Model):
    """Model for storing system-wide settings"""
    __tablename__ = 'system_settings'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.Text)
    value_type = db.Column(db.String(20), default='string')
    description = db.Column(db.String(255))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return f'<SystemSettings {self.key}={self.value}>'

    @staticmethod
    def get_setting(key, default=None):
        """Get a single setting value"""
        setting = SystemSettings.query.filter_by(key=key).first()
        if not setting:
            return default

        if setting.value_type == 'bool':
            return setting.value.lower() == 'true'
        elif setting.value_type == 'int':
            return int(setting.value)
        elif setting.value_type == 'json':
            return json.loads(setting.value)
        return setting.value

    @staticmethod
    def set_setting(key, value, value_type='string', description=None, user_id=None):
        """Set a single setting value"""
        setting = SystemSettings.query.filter_by(key=key).first()

        # Convert value to string for storage
        if value_type == 'bool':
            str_value = 'true' if value else 'false'
        elif value_type == 'json':
            str_value = json.dumps(value)
        else:
            str_value = str(value)

        if setting:
            setting.value = str_value
            setting.value_type = value_type
            setting.updated_at = datetime.utcnow()
            if user_id:
                setting.updated_by = user_id
        else:
            setting = SystemSettings(
                key=key,
                value=str_value,
                value_type=value_type,
                description=description,
                updated_by=user_id
            )
            db.session.add(setting)

        db.session.commit()
        return setting

    @staticmethod
    def get_all_settings():
        """Get all settings as a dictionary"""
        settings = {}
        for setting in SystemSettings.query.all():
            if setting.value_type == 'bool':
                settings[setting.key] = setting.value.lower() == 'true'
            elif setting.value_type == 'int':
                settings[setting.key] = int(setting.value)
            elif setting.value_type == 'json':
                settings[setting.key] = json.loads(setting.value)
            else:
                settings[setting.key] = setting.value
        return settings


class ConfigTemplate(db.Model):
    """Model for reusable WaaS application configuration templates"""
    __tablename__ = 'config_templates'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    config_data = db.Column(db.Text, nullable=False, default='{}')
    is_global = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref=db.backref('config_templates', lazy='dynamic'))
    applications = db.relationship('TemplateApplication', backref='template', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<ConfigTemplate {self.id}: {self.name}>'

    @property
    def config_dict(self):
        """Parse config_data JSON string into a dict"""
        try:
            return json.loads(self.config_data) if self.config_data else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    @config_dict.setter
    def config_dict(self, value):
        """Serialize dict to JSON string for storage"""
        self.config_data = json.dumps(value, indent=2)


class Feature(db.Model):
    """Model for curated, trackable config patches (features)"""
    __tablename__ = 'features'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50), index=True)  # Security Hardening, Performance, Compliance, Network, Custom
    config_data = db.Column(db.Text, nullable=False, default='{}')
    is_global = db.Column(db.Boolean, default=False, index=True)
    is_predefined = db.Column(db.Boolean, default=False, index=True)
    api_endpoint = db.Column(db.String(255), nullable=False, server_default='/applications/{app_id}/import/')
    api_method = db.Column(db.String(10), nullable=False, server_default='PATCH')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref=db.backref('features', lazy='dynamic'))
    applications = db.relationship('FeatureApplication', backref='feature', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Feature {self.id}: {self.name}>'

    @property
    def config_dict(self):
        """Parse config_data JSON string into a dict"""
        try:
            return json.loads(self.config_data) if self.config_data else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    @config_dict.setter
    def config_dict(self, value):
        """Serialize dict to JSON string for storage"""
        self.config_data = json.dumps(value, indent=2)


class FeatureApplication(db.Model):
    """Junction model tracking which apps a feature has been applied to"""
    __tablename__ = 'feature_applications'
    __table_args__ = (
        db.UniqueConstraint('feature_id', 'account_id', 'app_name', name='uq_feature_app'),
    )

    id = db.Column(db.Integer, primary_key=True)
    feature_id = db.Column(db.Integer, db.ForeignKey('features.id', ondelete='CASCADE'), nullable=False, index=True)
    account_id = db.Column(db.Integer, db.ForeignKey('waas_accounts.id', ondelete='CASCADE'), nullable=False, index=True)
    app_name = db.Column(db.String(255), nullable=False)
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)
    applied_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Relationships
    account = db.relationship('WaasAccount', backref=db.backref('feature_applications', lazy='dynamic'))
    applier = db.relationship('User', foreign_keys=[applied_by])

    def __repr__(self):
        return f'<FeatureApplication feature={self.feature_id} app={self.app_name}>'


class TemplateApplication(db.Model):
    """Junction model tracking which apps a template has been applied to"""
    __tablename__ = 'template_applications'
    __table_args__ = (
        db.UniqueConstraint('template_id', 'account_id', 'app_name', name='uq_template_app'),
    )

    id = db.Column(db.Integer, primary_key=True)
    template_id = db.Column(db.Integer, db.ForeignKey('config_templates.id', ondelete='CASCADE'), nullable=False, index=True)
    account_id = db.Column(db.Integer, db.ForeignKey('waas_accounts.id', ondelete='CASCADE'), nullable=False, index=True)
    app_name = db.Column(db.String(255), nullable=False)
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)
    applied_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    account = db.relationship('WaasAccount', backref=db.backref('template_applications', lazy='dynamic'))
    applier = db.relationship('User', foreign_keys=[applied_by])

    def __repr__(self):
        return f'<TemplateApplication template={self.template_id} app={self.app_name}>'


class AccountShare(db.Model):
    """Model for sharing WaaS accounts between portal users"""
    __tablename__ = 'account_shares'
    __table_args__ = (
        db.UniqueConstraint('account_id', 'user_id', name='uq_account_share'),
    )

    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('waas_accounts.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    permission = db.Column(db.String(20), nullable=False, default='read')  # read, write, admin
    granted_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    account = db.relationship('WaasAccount', backref=db.backref('shares', lazy='dynamic', cascade='all, delete-orphan'))
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('shared_accounts', lazy='dynamic'))
    grantor = db.relationship('User', foreign_keys=[granted_by])

    def __repr__(self):
        return f'<AccountShare account={self.account_id} user={self.user_id} perm={self.permission}>'


class ScheduledReport(db.Model):
    """Model for scheduled email reports"""
    __tablename__ = 'scheduled_reports'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    account_id = db.Column(db.Integer, db.ForeignKey('waas_accounts.id'), nullable=False, index=True)
    report_type = db.Column(db.String(50), nullable=False)  # waf_summary, access_summary, security_overview
    frequency = db.Column(db.String(20), nullable=False, default='weekly')  # daily, weekly, monthly
    day_of_week = db.Column(db.Integer, nullable=True)  # 0=Mon..6=Sun (for weekly)
    hour = db.Column(db.Integer, default=8)  # Hour of day (0-23)
    recipients = db.Column(db.Text, nullable=False, default='[]')  # JSON list of email addresses
    is_active = db.Column(db.Boolean, default=True)
    last_run_at = db.Column(db.DateTime, nullable=True)
    next_run_at = db.Column(db.DateTime, nullable=True)
    last_status = db.Column(db.String(20), nullable=True)  # success, failed
    last_error = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref=db.backref('scheduled_reports', lazy='dynamic'))
    account = db.relationship('WaasAccount', backref=db.backref('scheduled_reports', lazy='dynamic'))

    def __repr__(self):
        return f'<ScheduledReport {self.id}: {self.name}>'

    @property
    def recipients_list(self):
        try:
            return json.loads(self.recipients) if self.recipients else []
        except (json.JSONDecodeError, TypeError):
            return []

    @recipients_list.setter
    def recipients_list(self, value):
        self.recipients = json.dumps(value)


class ReportRun(db.Model):
    """Model for report execution history"""
    __tablename__ = 'report_runs'

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('scheduled_reports.id', ondelete='CASCADE'), nullable=False, index=True)
    run_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False)  # success, failed
    recipient_count = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text, nullable=True)
    summary = db.Column(db.Text, nullable=True)  # JSON summary data

    # Relationship
    report = db.relationship('ScheduledReport', backref=db.backref('runs', lazy='dynamic', cascade='all, delete-orphan'))

    def __repr__(self):
        return f'<ReportRun {self.id}: {self.status}>'

    @property
    def summary_dict(self):
        try:
            return json.loads(self.summary) if self.summary else {}
        except (json.JSONDecodeError, TypeError):
            return {}


# ---- Access helper functions ----

PERMISSION_HIERARCHY = {'read': 0, 'write': 1, 'admin': 2, 'owner': 3}


def can_write(permission):
    """True if permission allows write operations."""
    return permission in ('owner', 'admin', 'write')


def can_admin(permission):
    """True if permission allows admin operations (sharing, account management)."""
    return permission in ('owner', 'admin')


def get_user_accounts(user, active_only=True):
    """Return all accounts user owns or has shares for, with _permission annotation."""
    # Owned accounts
    query = WaasAccount.query.filter_by(user_id=user.id)
    if active_only:
        query = query.filter_by(is_active=True)
    owned = query.all()
    for acct in owned:
        acct._permission = 'owner'

    # Shared accounts
    share_query = db.session.query(WaasAccount, AccountShare.permission).join(
        AccountShare, AccountShare.account_id == WaasAccount.id
    ).filter(AccountShare.user_id == user.id)
    if active_only:
        share_query = share_query.filter(WaasAccount.is_active == True)
    shared = share_query.all()

    owned_ids = {a.id for a in owned}
    for acct, perm in shared:
        if acct.id not in owned_ids:
            acct._permission = perm
            owned.append(acct)

    return owned


def get_account_for_user(account_id, user, require_active=True, min_permission='read'):
    """Return (account, permission) tuple or (None, None).

    Checks ownership first, then shares. Enforces min_permission level.
    """
    query = WaasAccount.query.filter_by(id=account_id)
    if require_active:
        query = query.filter_by(is_active=True)
    account = query.first()
    if not account:
        return None, None

    # Owner check
    if account.user_id == user.id:
        return account, 'owner'

    # Share check
    share = AccountShare.query.filter_by(account_id=account_id, user_id=user.id).first()
    if share:
        perm_level = PERMISSION_HIERARCHY.get(share.permission, 0)
        min_level = PERMISSION_HIERARCHY.get(min_permission, 0)
        if perm_level >= min_level:
            return account, share.permission

    return None, None


class Notification(db.Model):
    """Model for in-app user notifications"""
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    type = db.Column(db.String(50), nullable=False)  # 'report', 'cert_expiry'
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    link = db.Column(db.String(500), nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Relationship
    user = db.relationship('User', backref=db.backref('notifications', lazy='dynamic'))

    def __repr__(self):
        return f'<Notification {self.id}: {self.type} for User {self.user_id}>'

    @staticmethod
    def create(user_id, type, title, message, link=None):
        """Create and persist a new notification."""
        n = Notification(
            user_id=user_id,
            type=type,
            title=title,
            message=message,
            link=link,
        )
        db.session.add(n)
        db.session.commit()
        return n

    @staticmethod
    def unread_count(user_id):
        """Return count of unread notifications for user."""
        return Notification.query.filter_by(user_id=user_id, is_read=False).count()

    @staticmethod
    def get_recent(user_id, limit=20):
        """Return recent notifications for user, newest first."""
        return Notification.query.filter_by(user_id=user_id)\
            .order_by(Notification.created_at.desc()).limit(limit).all()


class SiteProfile(db.Model):
    """Result of a Web App Profiler run against a customer URL."""
    __tablename__ = 'site_profiles'

    STATUS_PENDING = 'pending'
    STATUS_PROBING = 'probing'
    STATUS_COMPLETE = 'complete'
    STATUS_ERROR = 'error'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                        nullable=False, index=True)
    account_id = db.Column(db.Integer, db.ForeignKey('waas_accounts.id', ondelete='CASCADE'),
                           nullable=False, index=True)
    target_url = db.Column(db.String(2048), nullable=False)
    status = db.Column(db.String(20), nullable=False, default=STATUS_PENDING, index=True)
    # UUID reused as SocketIO room name for progress streaming.
    session_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    profile_data = db.Column(db.Text, nullable=True)         # JSON blob: raw probe result
    recommendation_data = db.Column(db.Text, nullable=True)  # JSON blob: form_fields + advisories
    error_message = db.Column(db.Text, nullable=True)

    user = db.relationship('User', backref=db.backref('site_profiles', lazy='dynamic'))
    account = db.relationship('WaasAccount', backref=db.backref('site_profiles', lazy='dynamic'))

    def __repr__(self):
        return f'<SiteProfile {self.id}: {self.target_url} [{self.status}]>'

    @property
    def profile(self):
        """Deserialize profile_data JSON blob (None if unset)."""
        if not self.profile_data:
            return None
        return json.loads(self.profile_data)

    @profile.setter
    def profile(self, value):
        self.profile_data = json.dumps(value) if value is not None else None

    @property
    def recommendation(self):
        """Deserialize recommendation_data JSON blob (None if unset)."""
        if not self.recommendation_data:
            return None
        return json.loads(self.recommendation_data)

    @recommendation.setter
    def recommendation(self, value):
        self.recommendation_data = json.dumps(value) if value is not None else None

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'account_id': self.account_id,
            'target_url': self.target_url,
            'status': self.status,
            'session_id': self.session_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'error_message': self.error_message,
        }