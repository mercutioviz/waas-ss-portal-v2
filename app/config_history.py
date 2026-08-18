"""Revert dispatch logic for ConfigSnapshot rollback.

Given a ConfigSnapshot's resource_type/section, replays the captured
payload_before through the matching WaasClient write method.
"""
from datetime import datetime
from app import db
from app.models import ConfigSnapshot, AuditLog

IMPORT_REPLAY_TYPES = {'template_apply', 'raw_config_apply', 'template_bulk_apply', 'raw_config_bulk_apply'}

SECTION_UPDATE_METHODS = {
    'basic_security': 'update_security_config',
    'request_limits': 'update_request_limits',
    'clickjacking_protection': 'update_clickjacking_protection',
    'data_theft_protection': 'update_data_theft_protection',
}


def revert_snapshot(snapshot, client, user_id):
    """Replay a ConfigSnapshot's payload_before via the WaasClient.

    Raises ValueError if the snapshot was already reverted, or
    WaasApiError (propagated from the client call) on API failure.
    Returns the new ConfigSnapshot recording the revert action.
    """
    if snapshot.reverted_at:
        raise ValueError('This snapshot has already been reverted.')

    payload_before = snapshot.payload_before_dict
    app_id = snapshot.app_id

    if snapshot.resource_type in IMPORT_REPLAY_TYPES:
        client.import_application(app_id, payload_before, include_servers=True, include_endpoints=True)

    elif snapshot.resource_type == 'security_config_update':
        method_name = SECTION_UPDATE_METHODS.get(snapshot.section)
        if not method_name:
            raise ValueError(f'Unknown security config section "{snapshot.section}" — cannot revert.')
        getattr(client, method_name)(app_id, payload_before)

    elif snapshot.resource_type == 'bulk_security_update':
        if snapshot.section == 'basic_security':
            client.update_security_config(app_id, payload_before)
        elif snapshot.section == 'endpoints':
            client.import_application(app_id, {'endpoints': payload_before}, include_endpoints=True)
        else:
            raise ValueError(f'Unknown bulk security section "{snapshot.section}" — cannot revert.')

    elif snapshot.resource_type == 'server_update':
        client.import_application(app_id, {'servers': payload_before}, include_servers=True)

    elif snapshot.resource_type == 'endpoint_update':
        client.update_application_endpoints(app_id, payload_before)

    else:
        raise ValueError(f'Unknown resource_type "{snapshot.resource_type}" — cannot revert.')

    revert_record = ConfigSnapshot.record(
        user_id=user_id,
        account_id=snapshot.account_id,
        app_id=app_id,
        app_name=snapshot.app_name,
        resource_type=snapshot.resource_type,
        resource_label=snapshot.resource_label,
        section=snapshot.section,
        payload_before=snapshot.payload_applied_dict or {},
        payload_applied=payload_before,
        reverted_from_id=snapshot.id,
    )

    snapshot.reverted_at = datetime.utcnow()
    snapshot.reverted_by_id = user_id
    db.session.commit()

    AuditLog.log(
        user_id=user_id,
        action='config_revert',
        resource_type=snapshot.resource_type,
        resource_id=snapshot.id,
        details=f'Reverted {snapshot.resource_type} on app {app_id} to state from snapshot #{snapshot.id}',
    )

    return revert_record
