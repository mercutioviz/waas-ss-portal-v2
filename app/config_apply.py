"""Routing for template / raw-config apply.

PATCH /applications/{app}/import/ only accepts the top-level components that
GET /applications/{app}/export/ emits. Several settings the portal lets you
capture into a template are not among them — they live on their own v4
endpoints and are merged into one flat dict by
``WaasClient.get_security_config``:

    protection_mode             -> PATCH /basic_security/
    clickjacking_protection     -> PATCH /clickjacking_protection/
    data_theft_protection       -> PATCH /data_theft_protection/

Feeding those to /import/ fails the whole call with
``Component named "protection_mode" not found.`` — and because the API rejects
on the first unknown key, nothing at all is written.

``apply_config`` splits a stored config by key: section keys go to their own
endpoint, everything else goes to /import/ in a single call. Each part is
attempted independently so one bad section cannot block the rest, and the
per-part outcome is reported back to the caller.

Note ``request_limits`` is deliberately NOT a section key. It appears in the
export document with the same shape the dedicated endpoint returns, so it rides
along in the import payload and stays consistent with how templates that
contain only importable keys have always applied.
"""

from app.waas_client import WaasApiError

#: Config key -> (WaasClient method, human label). Keys here are sent to their
#: own endpoint; anything else is passed through to import_application().
SECTION_ROUTES = {
    'protection_mode': ('update_security_config', 'Basic Security'),
    'clickjacking_protection': ('update_clickjacking_protection', 'Clickjacking Protection'),
    'data_theft_protection': ('update_data_theft_protection', 'Data Theft Protection'),
}

#: Label used for the /import/ portion in results.
IMPORT_LABEL = 'Application Config'


def split_config(config):
    """Split a stored config into (section_payloads, import_payload).

    section_payloads is an ordered list of (key, label, payload) for keys that
    must go to a dedicated endpoint. import_payload holds the remaining keys,
    or {} if there are none.
    """
    sections = []
    import_payload = {}

    for key, value in (config or {}).items():
        route = SECTION_ROUTES.get(key)
        if route is None:
            import_payload[key] = value
            continue
        _, label = route
        # basic_security takes {'protection_mode': ...}; the others are already
        # whole-body payloads for their endpoint.
        payload = {key: value} if key == 'protection_mode' else value
        sections.append((key, label, payload))

    return sections, import_payload


def apply_config(client, app_id, config, include_servers=False, include_endpoints=False):
    """Apply a stored config to an app, routing each part to its endpoint.

    Returns a list of result dicts, one per attempted part:
        {'part': <label>, 'success': bool, 'error': str|None}

    Parts are independent: a failure in one is recorded and the rest still run.
    Raises nothing for API errors — inspect the results. Callers that need an
    overall verdict can use apply_succeeded()/apply_error_summary().
    """
    sections, import_payload = split_config(config)
    results = []

    for _key, label, payload in sections:
        method_name, _ = SECTION_ROUTES[_key]
        try:
            getattr(client, method_name)(app_id, payload)
            results.append({'part': label, 'success': True, 'error': None})
        except WaasApiError as e:
            results.append({'part': label, 'success': False, 'error': str(e)})

    if import_payload:
        try:
            client.import_application(
                app_id, import_payload,
                include_servers=include_servers,
                include_endpoints=include_endpoints,
            )
            results.append({'part': IMPORT_LABEL, 'success': True, 'error': None})
        except WaasApiError as e:
            results.append({'part': IMPORT_LABEL, 'success': False, 'error': str(e)})

    return results


#: Config key -> WaasClient read method, for capturing pre-apply state.
SECTION_READS = {
    'protection_mode': 'get_basic_security',
    'clickjacking_protection': 'get_clickjacking_protection',
    'data_theft_protection': 'get_data_theft_protection',
}


def capture_before(client, app_id, config):
    """Capture the app state a config apply is about to overwrite.

    GET /export/ alone is not enough: it omits the section-only settings, so a
    snapshot taken from it cannot restore protection_mode or the clickjacking /
    data-theft sections. Read those separately for whichever sections this
    config actually touches, and merge them in under the same keys apply uses —
    revert_snapshot routes the result back through apply_config.

    Raises WaasApiError if the export itself fails; section reads are
    best-effort, since a section we cannot read is one we also cannot restore.
    """
    before = client.get_application(app_id)

    for key in (config or {}):
        read_method = SECTION_READS.get(key)
        if read_method is None:
            continue
        try:
            value = getattr(client, read_method)(app_id)
        except WaasApiError:
            continue
        if key == 'protection_mode':
            # get_basic_security returns {'protection_mode': ...}
            if isinstance(value, dict) and key in value:
                before[key] = value[key]
        else:
            before[key] = value

    return before


def apply_succeeded(results):
    """True if every attempted part succeeded (and at least one ran)."""
    return bool(results) and all(r['success'] for r in results)


def apply_error_summary(results):
    """Human-readable summary of failed parts, or None if all succeeded."""
    failures = [r for r in results if not r['success']]
    if not failures:
        return None
    return '; '.join(f"{r['part']}: {r['error']}" for r in failures)
