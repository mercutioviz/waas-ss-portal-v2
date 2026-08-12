from flask_wtf import FlaskForm
from flask_babel import lazy_gettext as _l
from wtforms import StringField, PasswordField, BooleanField, SelectField, SubmitField, TextAreaField, IntegerField, SelectMultipleField, DateField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional, Regexp, NumberRange
from flask_wtf.file import FileField, FileAllowed


class LoginForm(FlaskForm):
    """Form for user login"""
    username = StringField(
        _l('Username'),
        validators=[DataRequired(), Length(min=3, max=80)],
        render_kw={'placeholder': _l('Enter your username'), 'class': 'form-control', 'autocomplete': 'username'}
    )
    password = PasswordField(
        _l('Password'),
        validators=[DataRequired()],
        render_kw={'placeholder': _l('Enter your password'), 'class': 'form-control', 'autocomplete': 'current-password'}
    )
    remember_me = BooleanField(_l('Remember Me'), default=False, render_kw={'class': 'form-check-input'})
    submit = SubmitField(_l('Login'), render_kw={'class': 'btn btn-primary w-100'})


class RegistrationForm(FlaskForm):
    """Form for user registration (admin only)"""
    username = StringField(
        _l('Username'),
        validators=[
            DataRequired(), Length(min=3, max=80),
            Regexp(r'^[a-zA-Z0-9_-]+$', message=_l('Username can only contain letters, numbers, underscores, and hyphens'))
        ],
        render_kw={'placeholder': _l('Enter username'), 'class': 'form-control'}
    )
    email = StringField(
        _l('Email'),
        validators=[DataRequired(), Email(), Length(max=120)],
        render_kw={'placeholder': 'user@example.com', 'class': 'form-control'}
    )
    first_name = StringField(
        _l('First Name'),
        validators=[Length(max=100)],
        render_kw={'placeholder': _l('First name (optional)'), 'class': 'form-control'}
    )
    last_name = StringField(
        _l('Last Name'),
        validators=[Length(max=100)],
        render_kw={'placeholder': _l('Last name (optional)'), 'class': 'form-control'}
    )
    password = PasswordField(
        _l('Password'),
        validators=[DataRequired(), Length(min=8, message=_l('Password must be at least 8 characters'))],
        render_kw={'placeholder': _l('Enter password'), 'class': 'form-control'}
    )
    password_confirm = PasswordField(
        _l('Confirm Password'),
        validators=[DataRequired(), EqualTo('password', message=_l('Passwords must match'))],
        render_kw={'placeholder': _l('Confirm password'), 'class': 'form-control'}
    )
    role = SelectField(
        _l('Role'),
        choices=[
            ('user', _l('User - Can manage own WaaS accounts and applications')),
            ('admin', _l('Admin - Full system access')),
            ('viewer', _l('Viewer - Read-only access'))
        ],
        default='user',
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    is_active = BooleanField(_l('Account Active'), default=True, render_kw={'class': 'form-check-input'})
    submit = SubmitField(_l('Create User'), render_kw={'class': 'btn btn-primary'})

    def validate_username(self, username):
        from app.models import User
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(_l('Username already exists.'))

    def validate_email(self, email):
        from app.models import User
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(_l('Email already registered.'))


class NotificationPreferencesForm(FlaskForm):
    """Form for user notification preferences"""
    notify_report_email = BooleanField(_l('Email notifications'), default=True, render_kw={'class': 'form-check-input'})
    notify_report_inapp = BooleanField(_l('In-app notifications'), default=True, render_kw={'class': 'form-check-input'})
    notify_cert_expiry_email = BooleanField(_l('Email notifications'), default=True, render_kw={'class': 'form-check-input'})
    notify_cert_expiry_inapp = BooleanField(_l('In-app notifications'), default=True, render_kw={'class': 'form-check-input'})
    notify_apikey_expiry_email = BooleanField(_l('Email notifications'), default=True, render_kw={'class': 'form-check-input'})
    notify_apikey_expiry_inapp = BooleanField(_l('In-app notifications'), default=True, render_kw={'class': 'form-check-input'})
    submit = SubmitField(_l('Save Preferences'), render_kw={'class': 'btn btn-primary'})


class ChangePasswordForm(FlaskForm):
    """Form for changing password"""
    current_password = PasswordField(
        _l('Current Password'),
        validators=[DataRequired()],
        render_kw={'placeholder': _l('Enter current password'), 'class': 'form-control'}
    )
    new_password = PasswordField(
        _l('New Password'),
        validators=[DataRequired(), Length(min=8)],
        render_kw={'placeholder': _l('Enter new password'), 'class': 'form-control'}
    )
    new_password_confirm = PasswordField(
        _l('Confirm New Password'),
        validators=[DataRequired(), EqualTo('new_password', message=_l('Passwords must match'))],
        render_kw={'placeholder': _l('Confirm new password'), 'class': 'form-control'}
    )
    submit = SubmitField(_l('Change Password'), render_kw={'class': 'btn btn-primary'})


class WaasAccountForm(FlaskForm):
    """Form for adding/editing a WaaS API account.

    At least one credential type is required: API key (v4) or email+password (v2).
    """
    account_name = StringField(
        _l('Account Name'),
        validators=[DataRequired(), Length(min=2, max=100)],
        render_kw={'placeholder': _l('e.g., Production Account'), 'class': 'form-control'}
    )
    api_key = StringField(
        _l('API Key / Token (v4)'),
        validators=[Optional(), Length(min=10, max=500)],
        render_kw={'placeholder': _l('Paste WaaS API key here'), 'class': 'form-control', 'type': 'password'}
    )
    api_key_expiry = DateField(
        _l('API Key Expiry Date'),
        validators=[Optional()],
        render_kw={'type': 'date', 'class': 'form-control'}
    )
    waas_email = StringField(
        _l('WaaS Email (v2)'),
        validators=[Optional(), Email(), Length(max=120)],
        render_kw={'placeholder': 'user@example.com', 'class': 'form-control'}
    )
    waas_password = PasswordField(
        _l('WaaS Password (v2)'),
        validators=[Optional(), Length(max=255)],
        render_kw={'placeholder': _l('Enter WaaS password'), 'class': 'form-control'}
    )
    submit = SubmitField(_l('Save Account'), render_kw={'class': 'btn btn-primary'})

    def validate(self, extra_validators=None, is_edit=False, account=None):
        """Custom validation: require at least one credential type.

        Args:
            is_edit: If True, blank credential fields are allowed (means "keep existing").
            account: The existing WaasAccount being edited (used to check existing credentials).
        """
        if not super().validate(extra_validators=extra_validators):
            return False

        has_api_key = bool(self.api_key.data and self.api_key.data.strip())
        has_v2_creds = bool(
            self.waas_email.data and self.waas_email.data.strip()
            and self.waas_password.data and self.waas_password.data.strip()
        )

        # On edit, existing credentials count as "having" them
        if is_edit and account:
            existing_api_key = account.has_api_key
            existing_v2_creds = account.has_v2_credentials
        else:
            existing_api_key = False
            existing_v2_creds = False

        if not has_api_key and not has_v2_creds and not existing_api_key and not existing_v2_creds:
            self.api_key.errors.append(
                _l('At least one credential type is required: API key or WaaS email + password.')
            )
            return False

        # If email provided without password (or vice versa), flag it — but only for new values
        has_email_only = bool(self.waas_email.data and self.waas_email.data.strip()) and not bool(self.waas_password.data and self.waas_password.data.strip())
        has_pass_only = bool(self.waas_password.data and self.waas_password.data.strip()) and not bool(self.waas_email.data and self.waas_email.data.strip())

        # On edit, having only email without new password is OK if v2 creds already exist
        if has_email_only and not (is_edit and existing_v2_creds):
            self.waas_password.errors.append(_l('Password is required when email is provided.'))
            return False
        if has_pass_only and not (is_edit and existing_v2_creds):
            self.waas_email.errors.append(_l('Email is required when password is provided.'))
            return False

        return True


class UserCreateForm(FlaskForm):
    """Form for admin to create a new user"""
    username = StringField(
        _l('Username'),
        validators=[
            DataRequired(), Length(min=3, max=80),
            Regexp(r'^[a-zA-Z0-9_-]+$', message=_l('Username can only contain letters, numbers, underscores, and hyphens'))
        ],
        render_kw={'placeholder': _l('Enter username'), 'class': 'form-control'}
    )
    email = StringField(
        _l('Email'),
        validators=[DataRequired(), Email(), Length(max=120)],
        render_kw={'placeholder': 'user@example.com', 'class': 'form-control'}
    )
    display_name = StringField(
        _l('Display Name'),
        validators=[Optional(), Length(max=200)],
        render_kw={'placeholder': _l('Display name (optional)'), 'class': 'form-control'}
    )
    password = PasswordField(
        _l('Password'),
        validators=[DataRequired(), Length(min=8, message=_l('Password must be at least 8 characters'))],
        render_kw={'placeholder': _l('Enter password'), 'class': 'form-control'}
    )
    password_confirm = PasswordField(
        _l('Confirm Password'),
        validators=[DataRequired(), EqualTo('password', message=_l('Passwords must match'))],
        render_kw={'placeholder': _l('Confirm password'), 'class': 'form-control'}
    )
    role = SelectField(
        _l('Role'),
        choices=[('user', _l('User')), ('admin', _l('Admin')), ('viewer', _l('Viewer'))],
        default='user',
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    submit = SubmitField(_l('Create User'), render_kw={'class': 'btn btn-primary'})

    def validate_username(self, username):
        from app.models import User
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(_l('Username already exists.'))

    def validate_email(self, email):
        from app.models import User
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(_l('Email already registered.'))


class UserEditForm(FlaskForm):
    """Form for admin to edit an existing user"""
    email = StringField(
        _l('Email'),
        validators=[DataRequired(), Email(), Length(max=120)],
        render_kw={'class': 'form-control'}
    )
    display_name = StringField(
        _l('Display Name'),
        validators=[Optional(), Length(max=200)],
        render_kw={'class': 'form-control'}
    )
    role = SelectField(
        _l('Role'),
        choices=[('user', _l('User')), ('admin', _l('Admin')), ('viewer', _l('Viewer'))],
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    is_active = BooleanField(_l('Account Active'), render_kw={'class': 'form-check-input'})
    new_password = PasswordField(
        _l('New Password (leave blank to keep current)'),
        validators=[Optional(), Length(min=8)],
        render_kw={'placeholder': _l('Leave blank to keep current password'), 'class': 'form-control'}
    )
    submit = SubmitField(_l('Update User'), render_kw={'class': 'btn btn-primary'})


class CertificateUploadForm(FlaskForm):
    """Form for uploading SSL/TLS certificates"""
    certificate_file = FileField(
        _l('Certificate File (PEM or PFX)'),
        validators=[
            DataRequired(message=_l('Certificate file is required')),
            FileAllowed(['pem', 'pfx', 'p12', 'crt', 'cer', 'key'], _l('Only certificate files are allowed'))
        ],
        render_kw={'class': 'form-control', 'accept': '.pem,.pfx,.p12,.crt,.cer,.key'}
    )
    certificate_key_file = FileField(
        _l('Private Key File (PEM, optional for PFX)'),
        validators=[
            Optional(),
            FileAllowed(['pem', 'key'], _l('Only PEM/KEY files are allowed'))
        ],
        render_kw={'class': 'form-control', 'accept': '.pem,.key'}
    )
    pfx_password = PasswordField(
        _l('PFX Password (if applicable)'),
        validators=[Optional(), Length(max=255)],
        render_kw={'placeholder': _l('Enter PFX password if uploading PFX file'), 'class': 'form-control'}
    )
    friendly_name = StringField(
        _l('Friendly Name'),
        validators=[Optional(), Length(max=255)],
        render_kw={'placeholder': _l('Optional label for this certificate'), 'class': 'form-control'}
    )
    submit = SubmitField(_l('Upload Certificate'), render_kw={'class': 'btn btn-primary'})


class ApplicationCreateForm(FlaskForm):
    """Form for creating a new WaaS application via v2 API."""
    application_name = StringField(
        _l('Application Name'),
        validators=[DataRequired(), Length(min=1, max=200)],
        render_kw={'placeholder': _l('e.g., My Web App'), 'class': 'form-control'}
    )
    hostname = StringField(
        _l('Hostname / Domain'),
        validators=[DataRequired(), Length(min=1, max=255)],
        render_kw={'placeholder': _l('e.g., www.example.com'), 'class': 'form-control'}
    )
    backend_ip = StringField(
        _l('Backend Server IP / Hostname'),
        validators=[DataRequired(), Length(min=1, max=255)],
        render_kw={'placeholder': _l('e.g., 10.0.0.1 or origin.example.com'), 'class': 'form-control'}
    )
    backend_port = IntegerField(
        _l('Backend Port'),
        validators=[DataRequired()],
        default=443,
        render_kw={'placeholder': '443', 'class': 'form-control'}
    )
    backend_type = SelectField(
        _l('Backend Protocol'),
        choices=[('HTTPS', 'HTTPS'), ('HTTP', 'HTTP')],
        default='HTTPS',
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    malicious_traffic = SelectField(
        _l('Protection Mode'),
        choices=[
            ('Passive', _l('Passive — Monitor only (recommended for initial setup)')),
            ('Active', _l('Active — Block malicious traffic'))
        ],
        default='Passive',
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    use_https = BooleanField(_l('Create HTTPS Endpoint'), default=True, render_kw={'class': 'form-check-input'})
    use_http = BooleanField(_l('Create HTTP Endpoint'), default=True, render_kw={'class': 'form-check-input'})
    redirect_http = BooleanField(_l('Redirect HTTP to HTTPS'), default=True, render_kw={'class': 'form-check-input'})
    submit = SubmitField(_l('Create Application'), render_kw={'class': 'btn btn-primary'})


class RotateApiKeyForm(FlaskForm):
    """Form for rotating an API key on a WaaS account"""
    new_api_key = StringField(
        _l('New API Key'),
        validators=[DataRequired(), Length(min=10, max=500)],
        render_kw={'placeholder': _l('Paste new WaaS API key here'), 'class': 'form-control', 'type': 'password'}
    )
    api_key_expiry = DateField(
        _l('New Key Expiry Date'),
        validators=[Optional()],
        render_kw={'type': 'date', 'class': 'form-control'}
    )
    verify_key = BooleanField(_l('Verify new key before saving'), default=True, render_kw={'class': 'form-check-input'})
    submit = SubmitField(_l('Rotate API Key'), render_kw={'class': 'btn btn-primary'})


class ConfigTemplateForm(FlaskForm):
    """Form for creating/editing a config template"""
    name = StringField(
        _l('Template Name'),
        validators=[DataRequired(), Length(max=100)],
        render_kw={'placeholder': _l('e.g., Hardened Security Profile'), 'class': 'form-control'}
    )
    description = TextAreaField(
        _l('Description'),
        validators=[Optional(), Length(max=500)],
        render_kw={'placeholder': _l('Describe what this template configures...'), 'class': 'form-control', 'rows': '3'}
    )
    is_global = BooleanField(
        _l('Global Template (visible to all users)'),
        default=False,
        render_kw={'class': 'form-check-input'}
    )
    submit = SubmitField(_l('Save Template'), render_kw={'class': 'btn btn-primary'})


class ShareAccountForm(FlaskForm):
    """Form for sharing a WaaS account with another user"""
    username = StringField(
        _l('Username or Email'),
        validators=[DataRequired(), Length(max=120)],
        render_kw={'placeholder': _l('Enter username or email'), 'class': 'form-control'}
    )
    permission = SelectField(
        _l('Permission Level'),
        choices=[
            ('read', _l('Read — View only')),
            ('write', _l('Write — View + modify')),
            ('admin', _l('Admin — Full access + reshare')),
        ],
        default='read',
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    submit = SubmitField(_l('Share Account'), render_kw={'class': 'btn btn-primary'})

    def validate_username(self, username):
        from app.models import User
        user = User.query.filter(
            (User.username == username.data) | (User.email == username.data)
        ).first()
        if not user:
            raise ValidationError(_l('User not found.'))
        if not user.is_active:
            raise ValidationError(_l('User account is inactive.'))


class ScheduledReportForm(FlaskForm):
    """Form for creating/editing a scheduled report"""
    name = StringField(
        _l('Report Name'),
        validators=[DataRequired(), Length(max=200)],
        render_kw={'placeholder': _l('e.g., Weekly WAF Summary'), 'class': 'form-control'}
    )
    account_id = SelectField(
        _l('WaaS Account'),
        coerce=int,
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    report_type = SelectField(
        _l('Report Type'),
        choices=[
            ('waf_summary', _l('WAF Summary — Top attacks, IPs, severity')),
            ('access_summary', _l('Access Summary — Request totals, URLs, status codes')),
            ('security_overview', _l('Security Overview — Current config state')),
        ],
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    frequency = SelectField(
        _l('Frequency'),
        choices=[
            ('daily', _l('Daily')),
            ('weekly', _l('Weekly')),
            ('monthly', _l('Monthly')),
        ],
        default='weekly',
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    day_of_week = SelectField(
        _l('Day of Week'),
        choices=[
            ('', _l('— Select —')),
            ('0', _l('Monday')),
            ('1', _l('Tuesday')),
            ('2', _l('Wednesday')),
            ('3', _l('Thursday')),
            ('4', _l('Friday')),
            ('5', _l('Saturday')),
            ('6', _l('Sunday')),
        ],
        default='0',
        validators=[Optional()],
        render_kw={'class': 'form-select'}
    )
    hour = IntegerField(
        _l('Hour (0-23)'),
        default=8,
        validators=[DataRequired(), NumberRange(min=0, max=23)],
        render_kw={'class': 'form-control', 'min': '0', 'max': '23'}
    )
    recipients = StringField(
        _l('Recipients (comma-separated emails)'),
        validators=[DataRequired(), Length(max=1000)],
        render_kw={'placeholder': _l('user@example.com, admin@example.com'), 'class': 'form-control'}
    )
    submit = SubmitField(_l('Save Report'), render_kw={'class': 'btn btn-primary'})


class CloneApplicationForm(FlaskForm):
    """Form for cloning an existing WaaS application."""
    new_name = StringField(
        _l('New Application Name'),
        validators=[DataRequired(), Length(min=1, max=200)],
        render_kw={'placeholder': _l('e.g., My Web App (Clone)'), 'class': 'form-control'}
    )
    new_hostname = StringField(
        _l('New Hostname / Domain'),
        validators=[DataRequired(), Length(min=1, max=255)],
        render_kw={'placeholder': _l('e.g., www2.example.com'), 'class': 'form-control'}
    )
    backend_ip = StringField(
        _l('Backend Server IP / Hostname'),
        validators=[DataRequired(), Length(min=1, max=255)],
        render_kw={'class': 'form-control'}
    )
    backend_port = IntegerField(
        _l('Backend Port'),
        validators=[DataRequired()],
        default=443,
        render_kw={'class': 'form-control'}
    )
    backend_type = SelectField(
        _l('Backend Protocol'),
        choices=[('HTTPS', 'HTTPS'), ('HTTP', 'HTTP')],
        default='HTTPS',
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    clone_security = BooleanField(_l('Clone Security Configuration'), default=True, render_kw={'class': 'form-check-input'})
    clone_servers = BooleanField(_l('Clone Backend Servers'), default=True, render_kw={'class': 'form-check-input'})
    clone_endpoints = BooleanField(_l('Clone Endpoint Configuration'), default=False, render_kw={'class': 'form-check-input'})
    submit = SubmitField(_l('Clone Application'), render_kw={'class': 'btn btn-primary'})


class FeatureForm(FlaskForm):
    """Form for creating/editing a feature"""
    name = StringField(
        _l('Feature Name'),
        validators=[DataRequired(), Length(max=100)],
        render_kw={'placeholder': _l('e.g., Harden TLS 1.2+'), 'class': 'form-control'}
    )
    description = TextAreaField(
        _l('Description'),
        validators=[Optional(), Length(max=500)],
        render_kw={'placeholder': _l('Describe what this feature does...'), 'class': 'form-control', 'rows': '3'}
    )
    category = SelectField(
        _l('Category'),
        choices=[
            ('Security Hardening', _l('Security Hardening')),
            ('Performance', _l('Performance')),
            ('Compliance', _l('Compliance')),
            ('Network', _l('Network')),
            ('Custom', _l('Custom')),
        ],
        default='Custom',
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    api_endpoint = SelectField(
        _l('API Endpoint'),
        choices=[
            ('/applications/{app_id}/basic_security/', _l('Basic Security')),
            ('/applications/{app_id}/request_limits/', _l('Request Limits')),
            ('/applications/{app_id}/clickjacking_protection/', _l('Clickjacking Protection')),
            ('/applications/{app_id}/data_theft_protection/', _l('Data Theft Protection')),
            ('/applications/{app_id}/endpoints/', _l('Endpoints (TLS/Ports)')),
            ('/applications/{app_id}/import/', _l('Import (Generic)')),
            ('/applications/{app_id}/url_access_redirects/rules/', _l('URL Access & Redirects')),
        ],
        default='/applications/{app_id}/import/',
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    api_method = SelectField(
        _l('API Method'),
        choices=[('PATCH', 'PATCH'), ('PUT', 'PUT'), ('POST', 'POST')],
        default='PATCH',
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    is_global = BooleanField(
        _l('Global Feature (visible to all users)'),
        default=False,
        render_kw={'class': 'form-check-input'}
    )
    submit = SubmitField(_l('Save Feature'), render_kw={'class': 'btn btn-primary'})


class FeatureFromAppForm(FlaskForm):
    """Form for creating a feature from a live application export"""
    name = StringField(
        _l('Feature Name'),
        validators=[DataRequired(), Length(max=100)],
        render_kw={'placeholder': _l('e.g., Harden TLS 1.2+'), 'class': 'form-control'}
    )
    description = TextAreaField(
        _l('Description'),
        validators=[Optional(), Length(max=500)],
        render_kw={'placeholder': _l('Describe what this feature does...'), 'class': 'form-control', 'rows': '3'}
    )
    category = SelectField(
        _l('Category'),
        choices=[
            ('Security Hardening', _l('Security Hardening')),
            ('Performance', _l('Performance')),
            ('Compliance', _l('Compliance')),
            ('Network', _l('Network')),
            ('Custom', _l('Custom')),
        ],
        default='Custom',
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )
    is_global = BooleanField(
        _l('Global Feature (visible to all users)'),
        default=False,
        render_kw={'class': 'form-check-input'}
    )
    include_basic_security = BooleanField(_l('Basic Security (protection mode)'), default=True, render_kw={'class': 'form-check-input'})
    include_request_limits = BooleanField(_l('Request Limits'), default=True, render_kw={'class': 'form-check-input'})
    include_clickjacking = BooleanField(_l('Clickjacking Protection'), default=True, render_kw={'class': 'form-check-input'})
    include_data_theft = BooleanField(_l('Data Theft Protection'), default=True, render_kw={'class': 'form-check-input'})
    include_servers = BooleanField(_l('Backend Servers'), default=False, render_kw={'class': 'form-check-input'})
    include_endpoints = BooleanField(_l('Endpoints Configuration'), default=False, render_kw={'class': 'form-check-input'})
    submit = SubmitField(_l('Create Feature'), render_kw={'class': 'btn btn-primary'})


class TemplateFromAppForm(FlaskForm):
    """Form for creating a template from a live application export"""
    name = StringField(
        _l('Template Name'),
        validators=[DataRequired(), Length(max=100)],
        render_kw={'placeholder': _l('e.g., Hardened Security Profile'), 'class': 'form-control'}
    )
    description = TextAreaField(
        _l('Description'),
        validators=[Optional(), Length(max=500)],
        render_kw={'placeholder': _l('Describe what this template configures...'), 'class': 'form-control', 'rows': '3'}
    )
    is_global = BooleanField(
        _l('Global Template (visible to all users)'),
        default=False,
        render_kw={'class': 'form-check-input'}
    )
    include_basic_security = BooleanField(_l('Basic Security (protection mode)'), default=True, render_kw={'class': 'form-check-input'})
    include_request_limits = BooleanField(_l('Request Limits'), default=True, render_kw={'class': 'form-check-input'})
    include_clickjacking = BooleanField(_l('Clickjacking Protection'), default=True, render_kw={'class': 'form-check-input'})
    include_data_theft = BooleanField(_l('Data Theft Protection'), default=True, render_kw={'class': 'form-check-input'})
    include_servers = BooleanField(_l('Backend Servers'), default=False, render_kw={'class': 'form-check-input'})
    include_endpoints = BooleanField(_l('Endpoints Configuration'), default=False, render_kw={'class': 'form-check-input'})
    submit = SubmitField(_l('Create Template'), render_kw={'class': 'btn btn-primary'})
