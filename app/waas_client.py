"""
WaaS API Client
Handles communication with the Barracuda WaaS REST API (v2 and v4).

Auth priority:
  1. If a v4 API key is available, use it as Bearer token (default).
  2. If v2 email/password credentials are available, obtain (or refresh)
     a v2 auth token via POST /api_login/ and use it as Bearer token.
"""
import logging
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from flask import current_app
import json

logger = logging.getLogger(__name__)


class WaasApiError(Exception):
    """Custom exception for WaaS API errors"""
    def __init__(self, message, status_code=None, response_data=None,
                 request_method=None, request_url=None, request_data=None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data
        self.request_method = request_method
        self.request_url = request_url
        self.request_data = request_data


class WaasClient:
    """Client for interacting with the WaaS API (v2 and v4)."""

    def __init__(self, api_key, base_url=None, base_url_v2=None):
        """Create a client with an explicit auth token.

        For building a client from a WaasAccount (with auto token refresh),
        use the class method ``from_account()`` instead.
        """
        self.api_key = api_key
        self._account = None  # set by from_account()
        self.base_url = base_url or current_app.config.get(
            'WAAS_API_BASE_URL',
            'https://api.waas.barracudanetworks.com/v4/waasapi'
        )
        self.base_url_v2 = base_url_v2 or current_app.config.get(
            'WAAS_API_V2_BASE_URL',
            'https://api.waas.barracudanetworks.com/v2/waasapi'
        )
        # Strip trailing slash from base URLs to avoid double slashes
        self.base_url = self.base_url.rstrip('/')
        self.base_url_v2 = self.base_url_v2.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        })
        self._set_auth()

        # Configure retry and timeout from app config
        retry_total = current_app.config.get('WAAS_API_RETRY_TOTAL', 1)
        self.default_timeout = current_app.config.get('WAAS_API_TIMEOUT', 30)
        retry = Retry(
            total=retry_total,
            status_forcelist=[502, 503, 504],
            backoff_factor=1,
            allowed_methods=['GET', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'POST', 'PATCH'],
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------
    @classmethod
    def from_account(cls, account):
        """Build a WaasClient from a WaasAccount model instance.

        Auth priority:
          - If the account has an api_key, use it directly.
          - Otherwise, obtain/refresh a v2 auth token from email+password.

        The returned client stores a reference to the account so it can
        transparently refresh the v2 token when it expires.
        """
        if account.has_api_key:
            logger.info(f'from_account: using v4 API key for account "{account.account_name}" (id={account.id})')
            client = cls(api_key=account.api_key)
        elif account.has_v2_credentials:
            logger.info(f'from_account: using v2 credentials for account "{account.account_name}" (id={account.id})')
            token = cls._resolve_v2_token(account)
            client = cls(api_key=token)
        else:
            raise WaasApiError('Account has no API key and no v2 credentials configured.')

        client._account = account
        return client

    # ------------------------------------------------------------------
    # v2 Login
    # ------------------------------------------------------------------
    @staticmethod
    def v2_login(email, password, base_url_v2=None):
        """Authenticate against the v2 API and return (token, expiry).

        Sends ``POST /v2/waasapi/api_login/`` with form-urlencoded
        ``email`` and ``password``.

        Returns:
            tuple: (key: str, expiry: int) — the auth token and its
            Unix-epoch expiry timestamp.

        Raises:
            WaasApiError on any failure.
        """
        v2_base = base_url_v2 or current_app.config.get(
            'WAAS_API_V2_BASE_URL',
            'https://api.waas.barracudanetworks.com/v2/waasapi'
        )
        v2_base = v2_base.rstrip('/')
        url = f'{v2_base}/api_login/'

        logger.info(f'WaaS v2 Login Request: POST {url} (email={email})')

        try:
            response = requests.post(
                url,
                data={'email': email, 'password': password},
                headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                timeout=30,
            )

            logger.info(f'WaaS v2 Login Response: {response.status_code} {response.reason}')

            try:
                response_data = response.json()
            except (json.JSONDecodeError, ValueError):
                response_data = {'raw': response.text}
                logger.warning(f'  v2 Login response not JSON: {response.text[:500]}')

            if not response.ok:
                error_msg = (response_data.get('message')
                             or response_data.get('error')
                             or response_data.get('errors')
                             or response_data.get('detail')
                             or f'HTTP {response.status_code}')
                logger.error(f'WaaS v2 Login Error: {response.status_code} - {error_msg}')
                raise WaasApiError(
                    f'v2 login failed: {error_msg}',
                    status_code=response.status_code,
                    response_data=response_data,
                )

            key = response_data.get('key')
            expiry = response_data.get('expiry')
            if not key:
                raise WaasApiError('v2 login succeeded but no auth token returned.', response_data=response_data)

            logger.info(f'WaaS v2 Login succeeded. Token expires at {expiry}.')
            return key, expiry

        except requests.exceptions.ConnectionError as e:
            logger.error(f'WaaS v2 Login Connection Error: {e}')
            raise WaasApiError(f'Cannot connect to WaaS v2 API for login: {e}')
        except requests.exceptions.Timeout as e:
            logger.error(f'WaaS v2 Login Timeout: {e}')
            raise WaasApiError(f'WaaS v2 login timed out: {e}')
        except requests.exceptions.RequestException as e:
            logger.error(f'WaaS v2 Login Request Error: {e}')
            raise WaasApiError(f'WaaS v2 login request failed: {e}')

    @classmethod
    def _resolve_v2_token(cls, account):
        """Return a valid v2 auth token for the given account.

        Uses cached token if still valid; otherwise performs a fresh login
        and caches the new token on the account model.
        """
        if account.v2_token_valid:
            logger.debug('Using cached v2 auth token.')
            return account.v2_auth_token

        logger.info('v2 auth token missing or expired — refreshing via login.')
        key, expiry = cls.v2_login(account.waas_email, account.waas_password)

        # Cache on the account (caller should commit the session)
        account.v2_auth_token = key
        account.v2_token_expiry = expiry

        from app import db
        db.session.commit()

        return key

    def _ensure_auth(self, force_v2=False):
        """Refresh the Bearer token if it came from a v2 login and has expired.

        Args:
            force_v2: If True, switch to a v2 auth token even when an API key
                      is available.  Used for v2-only endpoints like /accounts/.
        """
        if not self._account:
            return

        need_v2 = force_v2 or (not self._account.has_api_key and self._account.has_v2_credentials)

        if need_v2 and self._account.has_v2_credentials:
            if force_v2 or not self._account.v2_token_valid:
                logger.info('_ensure_auth: obtaining/refreshing v2 auth token')
                new_token = self._resolve_v2_token(self._account)
                self.api_key = new_token
                self._set_auth()
            elif self._account.v2_token_valid and self._account.v2_auth_token:
                # We have a cached valid v2 token — use it
                logger.debug('_ensure_auth: switching to cached v2 auth token for v2 request')
                self.api_key = self._account.v2_auth_token
                self._set_auth()
        elif not force_v2 and self._account.has_api_key:
            # Restore API key for v4 calls (may have been swapped to v2 token earlier)
            if self.api_key != self._account.api_key:
                logger.debug('_ensure_auth: restoring v4 API key for v4 request')
                self.api_key = self._account.api_key
                self._set_auth()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _set_auth(self, api_version='v4'):
        """Set authentication header.

        v4 uses ``Authorization: Bearer <token>``.
        v2 uses ``auth-api: <token>`` (no Bearer prefix).
        """
        if api_version == 'v2':
            self.session.headers.pop('Authorization', None)
            self.session.headers['auth-api'] = self.api_key
        else:
            self.session.headers.pop('auth-api', None)
            self.session.headers['Authorization'] = f'Bearer {self.api_key}'

    def _make_request(self, method, endpoint, data=None, params=None, files=None, timeout=None, api_version='v4', _retried=False):
        """Make an API request and handle response.

        Args:
            api_version: 'v4' (default) or 'v2' to select the base URL.
        """
        # Refresh token if necessary — force v2 token for v2 API calls
        self._ensure_auth(force_v2=(api_version == 'v2'))

        # Set correct auth header format for the API version
        self._set_auth(api_version=api_version)

        # Ensure endpoint starts with / and ends with /
        if not endpoint.startswith('/'):
            endpoint = f'/{endpoint}'
        if not endpoint.endswith('/'):
            endpoint = f'{endpoint}/'

        base = self.base_url_v2 if api_version == 'v2' else self.base_url
        url = f'{base}{endpoint}'

        # Debug logging - redact auth tokens
        redacted_headers = dict(self.session.headers)
        if 'Authorization' in redacted_headers:
            token = redacted_headers['Authorization']
            if len(token) > 17:  # "Bearer " + at least 10 chars
                redacted_headers['Authorization'] = token[:17] + '...[REDACTED]'
        if 'auth-api' in redacted_headers:
            token = redacted_headers['auth-api']
            if len(token) > 10:
                redacted_headers['auth-api'] = token[:10] + '...[REDACTED]'

        logger.info(f'WaaS API Request: {method} {url}')
        logger.debug(f'  Headers: {redacted_headers}')
        if params:
            logger.debug(f'  Params: {params}')
        if data:
            logger.debug(f'  Data: {json.dumps(data, default=str)[:500]}')

        try:
            kwargs = {
                'params': params,
                'timeout': timeout or self.default_timeout,
            }
            if files:
                # Remove Content-Type for multipart uploads
                headers = dict(self.session.headers)
                headers.pop('Content-Type', None)
                kwargs['headers'] = headers
                kwargs['files'] = files
                logger.debug(f'  Files: {list(files.keys()) if isinstance(files, dict) else "provided"}')
            elif data:
                kwargs['json'] = data

            if api_version == 'v2':
                # Use a clean request for v2 calls to avoid session/cookie
                # contamination from prior v4 calls, which causes the v2 API
                # to reject the token with a "does not match current session" 403.
                v2_headers = {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'auth-api': self.api_key,
                }
                if files:
                    v2_headers.pop('Content-Type', None)
                kwargs.pop('headers', None)
                response = requests.request(method, url, headers=v2_headers, **kwargs)
            else:
                response = self.session.request(method, url, **kwargs)

            logger.info(f'WaaS API Response: {response.status_code} {response.reason} for {method} {url}')

            # Parse response
            try:
                response_data = response.json()
                logger.debug(f'  Response body (first 500 chars): {json.dumps(response_data, default=str)[:500]}')
            except (json.JSONDecodeError, ValueError):
                response_data = {'raw': response.text}
                logger.warning(f'  Response not JSON. Raw (first 500 chars): {response.text[:500]}')

            if not response.ok:
                error_msg = (response_data.get('message')
                             or response_data.get('error')
                             or response_data.get('errors')
                             or response_data.get('detail')
                             or f'HTTP {response.status_code}')

                # v2 API returns 403 when cached token is invalidated by a
                # concurrent session (e.g. WaaS web UI login).  Invalidate
                # the cached token and retry once with a fresh login.
                if (response.status_code == 403 and api_version == 'v2'
                        and not _retried and self._account
                        and self._account.has_v2_credentials):
                    logger.warning('v2 API 403 — cached token rejected; forcing re-login and retry.')
                    self._account.v2_token_expiry = 0
                    from app import db
                    db.session.commit()
                    return self._make_request(
                        method, endpoint, data=data, params=params,
                        files=files, timeout=timeout,
                        api_version=api_version, _retried=True,
                    )

                logger.error(f'WaaS API Error: {response.status_code} - {error_msg}')
                logger.error(f'  Full response: {json.dumps(response_data, default=str)[:1000]}')
                raise WaasApiError(
                    f'WaaS API error: {error_msg}',
                    status_code=response.status_code,
                    response_data=response_data,
                    request_method=method,
                    request_url=url,
                    request_data=data,
                )

            return response_data

        except requests.exceptions.ConnectionError as e:
            logger.error(f'WaaS API Connection Error: {e}')
            raise WaasApiError(f'Cannot connect to WaaS API: {e}',
                               request_method=method, request_url=url, request_data=data)
        except requests.exceptions.Timeout as e:
            logger.error(f'WaaS API Timeout: {e}')
            raise WaasApiError(f'WaaS API request timed out: {e}',
                               request_method=method, request_url=url, request_data=data)
        except requests.exceptions.RequestException as e:
            logger.error(f'WaaS API Request Error: {e}')
            raise WaasApiError(f'WaaS API request failed: {e}',
                               request_method=method, request_url=url, request_data=data)

    # === Curl Command Generation ===
    def generate_curl_command(self, method, endpoint, data=None, params=None, api_version='v4'):
        """Build a curl command string for display purposes (no API call made).

        Tokens are redacted to first 10 characters + ...[REDACTED].
        """
        if not endpoint.startswith('/'):
            endpoint = f'/{endpoint}'
        if not endpoint.endswith('/'):
            endpoint = f'{endpoint}/'

        base = self.base_url_v2 if api_version == 'v2' else self.base_url
        url = f'{base}{endpoint}'

        if params:
            qs = '&'.join(f'{k}={v}' for k, v in params.items())
            url = f'{url}?{qs}'

        # Build header flags
        if api_version == 'v2':
            token = self.api_key or ''
            redacted = (token[:10] + '...[REDACTED]') if len(token) > 10 else token
            headers = [
                f"-H 'Accept: application/json'",
                f"-H 'Content-Type: application/json'",
                f"-H 'auth-api: {redacted}'",
            ]
        else:
            token = self.api_key or ''
            redacted = ('Bearer ' + token[:10] + '...[REDACTED]') if len(token) > 10 else f'Bearer {token}'
            headers = [
                f"-H 'Accept: application/json'",
                f"-H 'Content-Type: application/json'",
                f"-H 'Authorization: {redacted}'",
            ]

        parts = [f"curl -X {method}"]
        parts.extend(headers)

        if data:
            json_str = json.dumps(data, indent=2)
            parts.append(f"-d '{json_str}'")

        parts.append(f"'{url}'")

        return ' \\\n  '.join(parts)

    # === Account / Verify (v2 API) ===
    def verify_account(self):
        """Verify auth and get account info (uses v2 API).

        Returns the full v2 response including the ``accounts`` list.
        """
        return self._make_request('GET', '/accounts/', api_version='v2')

    # === Applications ===
    def list_applications(self, params=None):
        """List all applications"""
        return self._make_request('GET', '/applications/', params=params)

    def get_application(self, app_id):
        """Get a single application export (full config) by name"""
        return self._make_request('GET', f'/applications/{app_id}/export/', params={
            'include_servers': 'true',
            'include_endpoints': 'true'
        })

    def update_application_endpoints(self, app_id, data):
        """Update endpoint configuration for an application.

        Uses PATCH /applications/{appName}/endpoints/ to directly update
        the endpoint settings (TLS, ports, etc.).
        """
        return self._make_request('PATCH', f'/applications/{app_id}/endpoints/', data=data)

    def call_api(self, method, endpoint_template, app_id, data):
        """Call an arbitrary WaaS API endpoint, substituting {app_id}."""
        endpoint = endpoint_template.replace('{app_id}', app_id)
        return self._make_request(method, endpoint, data=data)

    def import_application(self, app_id, data, include_servers=False, include_endpoints=False):
        """Import (merge) partial config into an existing application.

        Uses PATCH /applications/{appName}/import/ which merges the provided
        JSON into the app config without replacing missing fields with defaults.
        """
        params = {
            'include_servers': 'true' if include_servers else 'false',
            'include_endpoints': 'true' if include_endpoints else 'false'
        }
        return self._make_request('PATCH', f'/applications/{app_id}/import/', data=data, params=params)

    def create_application(self, data):
        """Create a new application"""
        return self._make_request('POST', '/applications/', data=data)

    def update_application(self, app_id, data):
        """Update an application"""
        return self._make_request('PUT', f'/applications/{app_id}/', data=data)

    def delete_application(self, app_id):
        """Delete an application"""
        return self._make_request('DELETE', f'/applications/{app_id}/')

    # === Application Security Config ===
    def get_basic_security(self, app_id):
        """Get basic security configuration (protection mode) (v4 API).

        Endpoint: GET /applications/{appName}/basic_security/
        """
        return self._make_request('GET', f'/applications/{app_id}/basic_security/')

    def get_request_limits(self, app_id):
        """Get request limits configuration (v4 API).

        Endpoint: GET /applications/{appName}/request_limits/
        """
        return self._make_request('GET', f'/applications/{app_id}/request_limits/')

    def get_clickjacking_protection(self, app_id):
        """Get clickjacking protection configuration (v4 API).

        Endpoint: GET /applications/{appName}/clickjacking_protection/
        """
        return self._make_request('GET', f'/applications/{app_id}/clickjacking_protection/')

    def get_data_theft_protection(self, app_id):
        """Get data theft protection configuration (v4 API).

        Endpoint: GET /applications/{appName}/data_theft_protection/
        """
        return self._make_request('GET', f'/applications/{app_id}/data_theft_protection/')

    def get_security_config(self, app_id):
        """Get combined security configuration for an application (v4 API).

        Fetches from multiple v4 endpoints and merges into a single dict:
        - /basic_security/ — protection_mode
        - /request_limits/ — max_request_length, etc.
        - /clickjacking_protection/ — clickjacking settings
        - /data_theft_protection/ — data theft settings
        """
        config = {}

        # Basic security (protection mode)
        try:
            basic = self.get_basic_security(app_id)
            config.update(basic if isinstance(basic, dict) else {})
        except WaasApiError:
            pass

        # Request limits
        try:
            limits = self.get_request_limits(app_id)
            config['request_limits'] = limits if isinstance(limits, dict) else {}
        except WaasApiError:
            pass

        # Clickjacking protection
        try:
            clickjack = self.get_clickjacking_protection(app_id)
            config['clickjacking_protection'] = clickjack if isinstance(clickjack, dict) else {}
        except WaasApiError:
            pass

        # Data theft protection
        try:
            dtp = self.get_data_theft_protection(app_id)
            config['data_theft_protection'] = dtp if isinstance(dtp, dict) else {}
        except WaasApiError:
            pass

        return config

    def update_security_config(self, app_id, data):
        """Update basic security configuration (v4 API).

        Endpoint: PATCH /applications/{appName}/basic_security/
        """
        return self._make_request('PATCH', f'/applications/{app_id}/basic_security/', data=data)

    def update_request_limits(self, app_id, data):
        """Update request limits configuration (v4 API).

        Endpoint: PATCH /applications/{appName}/request_limits/
        """
        return self._make_request('PATCH', f'/applications/{app_id}/request_limits/', data=data)

    def update_clickjacking_protection(self, app_id, data):
        """Update clickjacking protection configuration (v4 API).

        Endpoint: PATCH /applications/{appName}/clickjacking_protection/
        """
        return self._make_request('PATCH', f'/applications/{app_id}/clickjacking_protection/', data=data)

    def update_data_theft_protection(self, app_id, data):
        """Update data theft protection configuration (v4 API).

        Endpoint: PATCH /applications/{appName}/data_theft_protection/
        """
        return self._make_request('PATCH', f'/applications/{app_id}/data_theft_protection/', data=data)

    # === Certificates (v4 — per-application SNI certificates) ===
    def list_certificates(self, app_name=None):
        """List certificates.

        If ``app_name`` is provided, returns SNI certificates for that
        application via v4 API.  If omitted, aggregates certificates
        across all applications on the account.
        """
        if app_name:
            return self._make_request('GET', f'/applications/{app_name}/sni_certificates/')

        # Aggregate across all apps
        apps = self.list_applications()
        if isinstance(apps, dict):
            apps = apps.get('results', apps.get('data', apps.get('applications', [])))
        all_certs = []
        for app in (apps if isinstance(apps, list) else []):
            name = app.get('name')
            if not name:
                continue
            try:
                certs = self._make_request('GET', f'/applications/{name}/sni_certificates/')
                if isinstance(certs, list):
                    for c in certs:
                        c['_app_name'] = name
                    all_certs.extend(certs)
                elif isinstance(certs, dict):
                    items = certs.get('results', certs.get('data', []))
                    if isinstance(items, list):
                        for c in items:
                            c['_app_name'] = name
                        all_certs.extend(items)
            except WaasApiError:
                pass  # skip apps where cert listing fails
        return all_certs

    def get_certificate(self, app_name, cert_name):
        """Get a single SNI certificate (v4 API)."""
        return self._make_request('GET', f'/applications/{app_name}/sni_certificates/{cert_name}/')

    def upload_certificate(self, app_name, files, data=None):
        """Upload an SNI certificate to an application (v4 API)."""
        return self._make_request('POST', f'/applications/{app_name}/sni_certificates/', files=files, data=data)

    def delete_certificate(self, app_name, cert_name):
        """Delete an SNI certificate (v4 API)."""
        return self._make_request('DELETE', f'/applications/{app_name}/sni_certificates/{cert_name}/')

    # === Logs ===
    def get_logs(self, app_name, quick_range='r_24h', page=1, items_per_page=50,
                 from_epoch=None, to_epoch=None, filter_fields=None):
        """Get logs (WAF + access combined) for an application via v4 API.

        Args:
            app_name: Application name/domain (e.g. 'bank.darklab.cudalabx.net')
            quick_range: Quick time range shortcut. One of:
                r_1h, r_24h, r_7d, r_14d, r_30d, r_45d, r_60d.
                Ignored if from_epoch/to_epoch are provided.
            page: Page number (default 1)
            items_per_page: Items per page (default 50, max 1000)
            from_epoch: Start time as epoch seconds (overrides quick_range)
            to_epoch: End time as epoch seconds (overrides quick_range)
            filter_fields: Dict of filter fields, e.g.
                {"ClientIP": [{"condition": "is", "value": "1.2.3.4"}]}

        Returns:
            dict with 'results' (list of log entries) and 'count' (int)
        """
        params = {
            'page': page,
            'itemsPerPage': items_per_page,
        }

        if from_epoch and to_epoch:
            params['from'] = str(int(from_epoch))
            params['to'] = str(int(to_epoch))
        else:
            params['quickRange'] = quick_range

        if filter_fields:
            params['filterFields'] = json.dumps(filter_fields)

        return self._make_request('GET', f'/applications/{app_name}/logs/', params=params)

    def get_access_logs(self, app_id, params=None):
        """Get access logs for an application (v2 API, legacy).

        Prefer get_logs() for richer v4 data.
        """
        return self._make_request('GET', f'/applications/{app_id}/logs/access/', params=params, api_version='v2')

    def get_waf_logs(self, app_id, params=None):
        """Get WAF logs for an application (v2 API, legacy).

        Prefer get_logs() for richer v4 data.
        """
        return self._make_request('GET', f'/applications/{app_id}/logs/waf/', params=params, api_version='v2')

    def get_audit_logs(self, params=None):
        """Get audit/system logs"""
        return self._make_request('GET', '/logs/audit/', params=params)

    # === Applications (v2) ===
    def list_applications_v2(self):
        """List all applications via v2 API.

        Returns the paginated response with 'results' containing application
        objects with fields: id, name, basic_security, servers, app_group,
        license_plan, etc.
        """
        return self._make_request('GET', '/applications/', api_version='v2')

    def create_application_v2(self, data):
        """Create a new application via v2 API.

        Required fields in ``data``:
            hostnames (list[dict]): e.g. [{"hostname": "example.com"}]
            backendIp (str): Backend server IP or hostname
            backendPort (int): Backend server port
            backendType (str): "HTTP" or "HTTPS"
            useExistingIp (bool): Use an existing Barracuda IP or allocate new
            maliciousTraffic (str): "Active" (block) or "Passive" (monitor)

        Optional fields:
            applicationName, useHttp, useHttps, httpServicePort,
            httpsServicePort, redirectHTTP, serviceIp

        Returns the created application data from the API.
        """
        return self._make_request('POST', '/applications/', data=data, api_version='v2', timeout=120)

    def delete_application_v2(self, app_id):
        """Delete an application via v2 API.

        Args:
            app_id: The v2 integer application ID.

        Returns 204 on success (empty response).
        """
        return self._make_request('DELETE', f'/applications/{app_id}/', api_version='v2')

    def get_account_ips(self):
        """Get available account IPs via v2 API.

        Used when creating applications with useExistingIp=True.
        """
        return self._make_request('GET', '/account_ips/', api_version='v2')

    # === Public IP lookup ===
    _cached_public_ip = None
    _cached_public_ip_time = 0

    @classmethod
    def get_public_ip(cls, cache_ttl=300):
        """Look up this server's public IP address.

        Caches the result for ``cache_ttl`` seconds (default 5 minutes)
        to avoid hitting ipinfo.io on every request.

        Returns:
            str: Public IP address, or None on failure.
        """
        now = time.time()
        if cls._cached_public_ip and (now - cls._cached_public_ip_time) < cache_ttl:
            return cls._cached_public_ip

        try:
            resp = requests.get('https://ipinfo.io/ip', timeout=5)
            if resp.ok:
                ip = resp.text.strip()
                cls._cached_public_ip = ip
                cls._cached_public_ip_time = now
                logger.info(f'Public IP lookup: {ip}')
                return ip
            else:
                logger.warning(f'Public IP lookup failed: HTTP {resp.status_code}')
                return cls._cached_public_ip  # return stale cache if available
        except Exception as e:
            logger.warning(f'Public IP lookup error: {e}')
            return cls._cached_public_ip  # return stale cache if available

    # === DNS / CNAME ===
    def get_dns_info(self, app_id):
        """Get DNS/CNAME information for an application.

        The v4 API does not have a per-application /dns/ endpoint.
        DNS data (CNAME, domains) is embedded in the application export,
        so we extract it from the endpoints section of the export.
        """
        export = self.get_application(app_id)
        endpoints = export.get('endpoints', {})
        return {
            'cname': endpoints.get('cname', ''),
            'domains': endpoints.get('domains', []),
            'deployment': endpoints.get('deployment', {}),
        }

    def list_dns_zones(self):
        """List all DNS zones (v4 API).

        Endpoint: GET /dns_zones/
        """
        return self._make_request('GET', '/dns_zones/')

    # === Proxy ===
    def get_proxy_settings(self, app_id):
        """Get reverse proxy settings for an application"""
        return self._make_request('GET', f'/applications/{app_id}/proxy/')

    def update_proxy_settings(self, app_id, data):
        """Update reverse proxy settings"""
        return self._make_request('PUT', f'/applications/{app_id}/proxy/', data=data)

    # === URL Access & Redirects ===
    def get_url_access_rules(self, app_id):
        """List all URL access redirect rules for an application."""
        return self._make_request('GET', f'/applications/{app_id}/url_access_redirects/rules/')

    def create_url_access_rule(self, app_id, data):
        """Create a new URL access redirect rule."""
        return self._make_request('POST', f'/applications/{app_id}/url_access_redirects/rules/', data=data)

    def get_url_access_rule(self, app_id, rule_name):
        """Get a single URL access redirect rule."""
        return self._make_request('GET', f'/applications/{app_id}/url_access_redirects/rules/{rule_name}/')

    def update_url_access_rule(self, app_id, rule_name, data):
        """Update an existing URL access redirect rule."""
        return self._make_request('PATCH', f'/applications/{app_id}/url_access_redirects/rules/{rule_name}/', data=data)

    def delete_url_access_rule(self, app_id, rule_name):
        """Delete a URL access redirect rule."""
        return self._make_request('DELETE', f'/applications/{app_id}/url_access_redirects/rules/{rule_name}/')

    # === Request Rewrites ===
    def get_request_rewrites(self, app_id):
        return self._make_request('GET', f'/applications/{app_id}/request_rewrite/rules/')

    def create_request_rewrite(self, app_id, data):
        return self._make_request('POST', f'/applications/{app_id}/request_rewrite/rules/', data=data)

    def get_request_rewrite(self, app_id, rule_name):
        return self._make_request('GET', f'/applications/{app_id}/request_rewrite/rules/{rule_name}/')

    def update_request_rewrite(self, app_id, rule_name, data):
        return self._make_request('PATCH', f'/applications/{app_id}/request_rewrite/rules/{rule_name}/', data=data)

    def delete_request_rewrite(self, app_id, rule_name):
        return self._make_request('DELETE', f'/applications/{app_id}/request_rewrite/rules/{rule_name}/')

    # === Response Rewrites ===
    def get_response_rewrites(self, app_id):
        return self._make_request('GET', f'/applications/{app_id}/response_rewrite/rules/')

    def create_response_rewrite(self, app_id, data):
        return self._make_request('POST', f'/applications/{app_id}/response_rewrite/rules/', data=data)

    def get_response_rewrite(self, app_id, rule_name):
        return self._make_request('GET', f'/applications/{app_id}/response_rewrite/rules/{rule_name}/')

    def update_response_rewrite(self, app_id, rule_name, data):
        return self._make_request('PATCH', f'/applications/{app_id}/response_rewrite/rules/{rule_name}/', data=data)

    def delete_response_rewrite(self, app_id, rule_name):
        return self._make_request('DELETE', f'/applications/{app_id}/response_rewrite/rules/{rule_name}/')

    # === Response Body Rewrites ===
    def get_response_body_rewrites(self, app_id):
        return self._make_request('GET', f'/applications/{app_id}/response_body_rewrite/rules/')

    def create_response_body_rewrite(self, app_id, data):
        return self._make_request('POST', f'/applications/{app_id}/response_body_rewrite/rules/', data=data)

    def get_response_body_rewrite(self, app_id, rule_name):
        return self._make_request('GET', f'/applications/{app_id}/response_body_rewrite/rules/{rule_name}/')

    def update_response_body_rewrite(self, app_id, rule_name, data):
        return self._make_request('PATCH', f'/applications/{app_id}/response_body_rewrite/rules/{rule_name}/', data=data)

    def delete_response_body_rewrite(self, app_id, rule_name):
        return self._make_request('DELETE', f'/applications/{app_id}/response_body_rewrite/rules/{rule_name}/')

    # === URL Translations ===
    def get_url_translations(self, app_id):
        return self._make_request('GET', f'/applications/{app_id}/url_translation/rules/')

    def create_url_translation(self, app_id, data):
        return self._make_request('POST', f'/applications/{app_id}/url_translation/rules/', data=data)

    def get_url_translation(self, app_id, rule_name):
        return self._make_request('GET', f'/applications/{app_id}/url_translation/rules/{rule_name}/')

    def update_url_translation(self, app_id, rule_name, data):
        return self._make_request('PATCH', f'/applications/{app_id}/url_translation/rules/{rule_name}/', data=data)

    def delete_url_translation(self, app_id, rule_name):
        return self._make_request('DELETE', f'/applications/{app_id}/url_translation/rules/{rule_name}/')

    # === Response Pages ===
    def get_response_pages(self, app_id):
        return self._make_request('GET', f'/applications/{app_id}/response_page_component/pages/')

    def get_response_page(self, app_id, page_name):
        return self._make_request('GET', f'/applications/{app_id}/response_page_component/pages/{page_name}/')

    def create_response_page(self, app_id, data):
        return self._make_request('POST', f'/applications/{app_id}/response_page_component/pages/', data=data)

    def update_response_page(self, app_id, page_name, data):
        return self._make_request('PUT', f'/applications/{app_id}/response_page_component/pages/{page_name}/', data=data)

    def delete_response_page(self, app_id, page_name):
        return self._make_request('DELETE', f'/applications/{app_id}/response_page_component/pages/{page_name}/')