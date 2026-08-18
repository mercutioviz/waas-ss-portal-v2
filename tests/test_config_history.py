"""Tests for ConfigSnapshot recording and the revert_snapshot dispatch logic
(app/config_history.py). No real WaasClient calls — a stub client records
which methods were called and with what args."""

import pytest

from app.config_history import revert_snapshot
from app.models import AuditLog, ConfigSnapshot, User, WaasAccount


class StubClient:
    """Records calls instead of hitting the real WaaS API."""

    def __init__(self):
        self.calls = []

    def import_application(self, app_id, payload, include_servers=False, include_endpoints=False):
        self.calls.append(('import_application', app_id, payload, include_servers, include_endpoints))

    def update_security_config(self, app_id, payload):
        self.calls.append(('update_security_config', app_id, payload))

    def update_request_limits(self, app_id, payload):
        self.calls.append(('update_request_limits', app_id, payload))

    def update_clickjacking_protection(self, app_id, payload):
        self.calls.append(('update_clickjacking_protection', app_id, payload))

    def update_data_theft_protection(self, app_id, payload):
        self.calls.append(('update_data_theft_protection', app_id, payload))

    def update_application_endpoints(self, app_id, payload):
        self.calls.append(('update_application_endpoints', app_id, payload))


@pytest.fixture
def user(app, db):
    u = User(username='ch-tester', email='ch@example.com', role='user', is_active=True)
    u.set_password('x')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def account(app, db, user):
    acc = WaasAccount(user_id=user.id, account_name='Acme WaaS', is_active=True)
    acc.api_key = 'v4-key'
    db.session.add(acc)
    db.session.commit()
    return acc


@pytest.fixture
def client_stub():
    return StubClient()


class TestConfigSnapshotRecord:
    def test_creates_row_with_serialized_payloads(self, app, db, user, account):
        snap = ConfigSnapshot.record(
            user_id=user.id,
            account_id=account.id,
            app_id='app-1.example.com',
            resource_type='template_apply',
            payload_before={'servers': [{'ip': '1.2.3.4'}]},
            resource_label='My Template',
            payload_applied={'servers': [{'ip': '5.6.7.8'}]},
        )
        assert snap.id is not None
        assert snap.payload_before_dict == {'servers': [{'ip': '1.2.3.4'}]}
        assert snap.payload_applied_dict == {'servers': [{'ip': '5.6.7.8'}]}
        assert snap.is_reverted is False

    def test_payload_applied_defaults_to_none(self, app, db, user, account):
        snap = ConfigSnapshot.record(
            user_id=user.id,
            account_id=account.id,
            app_id='app-1.example.com',
            resource_type='server_update',
            payload_before={'servers': []},
        )
        assert snap.payload_applied is None
        assert snap.payload_applied_dict is None

    def test_batch_id_groups_rows(self, app, db, user, account):
        batch_id = 'batch-123'
        s1 = ConfigSnapshot.record(
            user_id=user.id, account_id=account.id, app_id='app-1.example.com',
            resource_type='template_bulk_apply', payload_before={}, batch_id=batch_id,
        )
        s2 = ConfigSnapshot.record(
            user_id=user.id, account_id=account.id, app_id='app-2.example.com',
            resource_type='template_bulk_apply', payload_before={}, batch_id=batch_id,
        )
        rows = ConfigSnapshot.query.filter_by(batch_id=batch_id).all()
        assert {r.id for r in rows} == {s1.id, s2.id}

    def test_malformed_payload_before_returns_empty_dict(self, app, db, user, account):
        snap = ConfigSnapshot.record(
            user_id=user.id, account_id=account.id, app_id='app-1.example.com',
            resource_type='server_update', payload_before={},
        )
        snap.payload_before = 'not json'
        assert snap.payload_before_dict == {}


class TestRevertSnapshotDispatch:
    def _snap(self, db, user, account, **overrides):
        kwargs = dict(
            user_id=user.id,
            account_id=account.id,
            app_id='app-1.example.com',
            resource_type='template_apply',
            payload_before={'servers': [{'ip': '1.2.3.4'}]},
            payload_applied={'servers': [{'ip': '5.6.7.8'}]},
        )
        kwargs.update(overrides)
        return ConfigSnapshot.record(**kwargs)

    @pytest.mark.parametrize('resource_type', [
        'template_apply', 'raw_config_apply', 'template_bulk_apply', 'raw_config_bulk_apply',
    ])
    def test_import_replay_types_call_import_application(self, app, db, user, account, client_stub, resource_type):
        snap = self._snap(db, user, account, resource_type=resource_type)
        revert_snapshot(snap, client_stub, user.id)

        assert len(client_stub.calls) == 1
        name, app_id, payload, include_servers, include_endpoints = client_stub.calls[0]
        assert name == 'import_application'
        assert app_id == 'app-1.example.com'
        assert payload == {'servers': [{'ip': '1.2.3.4'}]}
        assert include_servers is True
        assert include_endpoints is True

    @pytest.mark.parametrize('section,method_name', [
        ('basic_security', 'update_security_config'),
        ('request_limits', 'update_request_limits'),
        ('clickjacking_protection', 'update_clickjacking_protection'),
        ('data_theft_protection', 'update_data_theft_protection'),
    ])
    def test_security_config_update_dispatches_by_section(self, app, db, user, account, client_stub, section, method_name):
        snap = self._snap(
            db, user, account,
            resource_type='security_config_update', section=section,
            payload_before={'enabled': True}, payload_applied={'enabled': False},
        )
        revert_snapshot(snap, client_stub, user.id)

        assert client_stub.calls == [(method_name, 'app-1.example.com', {'enabled': True})]

    def test_security_config_update_unknown_section_raises(self, app, db, user, account, client_stub):
        snap = self._snap(db, user, account, resource_type='security_config_update', section='bogus')
        with pytest.raises(ValueError):
            revert_snapshot(snap, client_stub, user.id)
        assert client_stub.calls == []

    def test_bulk_security_update_basic_security_section(self, app, db, user, account, client_stub):
        snap = self._snap(
            db, user, account,
            resource_type='bulk_security_update', section='basic_security',
            payload_before={'enabled': True},
        )
        revert_snapshot(snap, client_stub, user.id)
        assert client_stub.calls == [('update_security_config', 'app-1.example.com', {'enabled': True})]

    def test_bulk_security_update_endpoints_section(self, app, db, user, account, client_stub):
        snap = self._snap(
            db, user, account,
            resource_type='bulk_security_update', section='endpoints',
            payload_before={'https': {'port': 443}},
        )
        revert_snapshot(snap, client_stub, user.id)
        assert client_stub.calls == [
            ('import_application', 'app-1.example.com', {'endpoints': {'https': {'port': 443}}}, False, True)
        ]

    def test_bulk_security_update_unknown_section_raises(self, app, db, user, account, client_stub):
        snap = self._snap(db, user, account, resource_type='bulk_security_update', section='bogus')
        with pytest.raises(ValueError):
            revert_snapshot(snap, client_stub, user.id)

    def test_server_update_calls_import_application_with_servers(self, app, db, user, account, client_stub):
        snap = self._snap(
            db, user, account, resource_type='server_update',
            payload_before=[{'ip': '1.2.3.4'}],
        )
        revert_snapshot(snap, client_stub, user.id)
        assert client_stub.calls == [
            ('import_application', 'app-1.example.com', {'servers': [{'ip': '1.2.3.4'}]}, True, False)
        ]

    def test_endpoint_update_calls_update_application_endpoints(self, app, db, user, account, client_stub):
        snap = self._snap(
            db, user, account, resource_type='endpoint_update', section='tls',
            payload_before={'https': {'port': 443}},
        )
        revert_snapshot(snap, client_stub, user.id)
        assert client_stub.calls == [
            ('update_application_endpoints', 'app-1.example.com', {'https': {'port': 443}})
        ]

    def test_unknown_resource_type_raises(self, app, db, user, account, client_stub):
        snap = self._snap(db, user, account, resource_type='something_else')
        with pytest.raises(ValueError):
            revert_snapshot(snap, client_stub, user.id)
        assert client_stub.calls == []

    def test_already_reverted_snapshot_raises(self, app, db, user, account, client_stub):
        from datetime import datetime
        snap = self._snap(db, user, account)
        snap.reverted_at = datetime.utcnow()
        db.session.commit()

        with pytest.raises(ValueError):
            revert_snapshot(snap, client_stub, user.id)
        assert client_stub.calls == []


class TestRevertSnapshotLineage:
    def test_successful_revert_creates_new_snapshot_and_marks_original(self, app, db, user, account, client_stub):
        original = ConfigSnapshot.record(
            user_id=user.id, account_id=account.id, app_id='app-1.example.com',
            resource_type='template_apply', resource_label='My Template',
            payload_before={'servers': [{'ip': '1.2.3.4'}]},
            payload_applied={'servers': [{'ip': '5.6.7.8'}]},
        )

        revert_record = revert_snapshot(original, client_stub, user.id)

        assert original.is_reverted is True
        assert original.reverted_by_id == user.id
        assert original.reverted_at is not None

        assert revert_record.id != original.id
        assert revert_record.reverted_from_id == original.id
        # The revert's before-state is what the original applied; its
        # applied-state is what the original had before (i.e. we rolled back to it).
        assert revert_record.payload_before_dict == {'servers': [{'ip': '5.6.7.8'}]}
        assert revert_record.payload_applied_dict == {'servers': [{'ip': '1.2.3.4'}]}
        assert revert_record.resource_type == original.resource_type
        assert revert_record.resource_label == original.resource_label

        assert list(original.reverts) == [revert_record]
        assert revert_record.reverted_from == original

    def test_revert_writes_audit_log_entry(self, app, db, user, account, client_stub):
        original = ConfigSnapshot.record(
            user_id=user.id, account_id=account.id, app_id='app-1.example.com',
            resource_type='server_update', payload_before=[{'ip': '1.2.3.4'}],
        )
        revert_snapshot(original, client_stub, user.id)

        entry = AuditLog.query.filter_by(action='config_revert').first()
        assert entry is not None
        assert entry.resource_id == original.id
        assert entry.user_id == user.id

    def test_revert_of_a_revert_chains_lineage(self, app, db, user, account, client_stub):
        original = ConfigSnapshot.record(
            user_id=user.id, account_id=account.id, app_id='app-1.example.com',
            resource_type='template_apply',
            payload_before={'v': 1}, payload_applied={'v': 2},
        )
        first_revert = revert_snapshot(original, client_stub, user.id)
        second_revert = revert_snapshot(first_revert, client_stub, user.id)

        assert second_revert.reverted_from_id == first_revert.id
        assert first_revert.is_reverted is True
        assert second_revert.payload_applied_dict == {'v': 2}
