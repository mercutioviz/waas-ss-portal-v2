"""Route-level tests for template apply and the ConfigSnapshot it must record.

`test_config_apply.py` covers the split/route/report logic in
`app/config_apply.py`. Nothing covered the route that calls it, which is where
the snapshot gets written — so the one behaviour the rollback feature depends
on was untested.

That gap had teeth. Until `f04e9a0` every template apply failed on the first
unrecognised key, so `wrote_something` was always False and no snapshot was
ever recorded; `config_snapshots` was still empty in production a month after
the feature shipped. These tests pin the contract in both directions: a write
that happened must leave a snapshot, and a write that didn't must not.

No real WaaS calls — a stub client stands in, and the failing variants raise
WaasApiError the way the live API did.
"""

import json

import pytest

from app.models import (
    AuditLog, ConfigSnapshot, ConfigTemplate, TemplateApplication,
    User, WaasAccount,
)
from app.waas_client import WaasApiError


#: A template that exercises both halves of the split: `protection_mode` must
#: go to its own endpoint, `cache_settings` rides along in the import payload.
TEMPLATE_CONFIG = {
    'protection_mode': 'block',
    'cache_settings': {'enabled': True},
}


#: Keys PATCH /import/ does not accept. The live API rejects the whole call on
#: the first one it doesn't recognise, writing nothing — which is precisely how
#: the production failure behaved. The stub enforces this so a test cannot pass
#: against a payload the real endpoint would have refused; without it, a mock
#: that cheerfully accepts anything hides exactly the bug f04e9a0 fixed.
IMPORT_REJECTS = {'protection_mode', 'clickjacking_protection',
                  'data_theft_protection'}


class StubClient:
    """Records calls; optionally fails the parts named in `fail`."""

    def __init__(self, fail=()):
        self.calls = []
        self.fail = set(fail)

    def _maybe_fail(self, name):
        if name in self.fail:
            raise WaasApiError(f'{name} refused by stub')

    # --- read side, used by capture_before -------------------------------
    def get_application(self, app_id):
        self._maybe_fail('get_application')
        return {'name': app_id, 'cache_settings': {'enabled': False}}

    def get_basic_security(self, app_id):
        self._maybe_fail('get_basic_security')
        return {'protection_mode': 'monitor'}

    # --- write side ------------------------------------------------------
    def update_security_config(self, app_id, payload):
        self.calls.append(('update_security_config', app_id, payload))
        self._maybe_fail('update_security_config')

    def import_application(self, app_id, payload, include_servers=False,
                           include_endpoints=False):
        self.calls.append(('import_application', app_id, payload,
                           include_servers, include_endpoints))
        self._maybe_fail('import_application')
        rejected = IMPORT_REJECTS & set(payload or {})
        if rejected:
            raise WaasApiError(
                f'Component named "{sorted(rejected)[0]}" not found.')


@pytest.fixture
def user(app, db):
    u = User(username='apply-tester', email='at@example.com', role='user',
             is_active=True)
    u.set_password('x')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def viewer(app, db):
    u = User(username='apply-viewer', email='av@example.com', role='viewer',
             is_active=True)
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
def template(app, db, user):
    t = ConfigTemplate(user_id=user.id, name='Baseline Hardening',
                       config_data=json.dumps(TEMPLATE_CONFIG))
    db.session.add(t)
    db.session.commit()
    return t


def login(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True
    return client


@pytest.fixture
def apply_post(client, app, account, template, monkeypatch):
    """POST the apply route with a stub client wired in.

    Returns a callable taking the StubClient to use, so each test picks its own
    success/failure shape.
    """
    def _post(stub, as_user=None, data=None):
        if as_user is not None:
            login(client, as_user)
        monkeypatch.setattr(
            'app.routes.templates.get_client_for_account',
            lambda account_id, min_permission=None: (stub, account),
        )
        return client.post(
            f'/templates/{template.id}/apply/{account.id}/app-1.example.com',
            data=data or {}, follow_redirects=False,
        )
    return _post


class TestSnapshotIsRecorded:
    def test_successful_apply_records_a_snapshot(self, db, apply_post, user,
                                                 account, template):
        stub = StubClient()
        apply_post(stub, as_user=user)

        snaps = ConfigSnapshot.query.all()
        assert len(snaps) == 1, 'a successful apply must leave a snapshot'
        snap = snaps[0]
        assert snap.resource_type == 'template_apply'
        assert snap.resource_label == template.name
        assert snap.app_id == 'app-1.example.com'
        assert snap.account_id == account.id
        assert snap.user_id == user.id

    def test_snapshot_captures_the_state_being_overwritten(self, db, apply_post,
                                                           user):
        """payload_before must hold the *old* values, or rollback restores
        whatever the apply just wrote."""
        apply_post(StubClient(), as_user=user)

        before = ConfigSnapshot.query.one().payload_before_dict
        # from get_basic_security, not from the export
        assert before['protection_mode'] == 'monitor'
        assert before['cache_settings'] == {'enabled': False}

    def test_snapshot_records_what_was_applied(self, db, apply_post, user):
        apply_post(StubClient(), as_user=user)
        assert ConfigSnapshot.query.one().payload_applied_dict == TEMPLATE_CONFIG

    def test_template_application_row_is_recorded(self, db, apply_post, user,
                                                  template, account):
        apply_post(StubClient(), as_user=user)

        ta = TemplateApplication.query.one()
        assert ta.template_id == template.id
        assert ta.account_id == account.id
        assert ta.app_name == 'app-1.example.com'
        assert ta.applied_by == user.id

    def test_reapplying_updates_the_existing_row(self, db, apply_post, user):
        apply_post(StubClient(), as_user=user)
        apply_post(StubClient(), as_user=user)

        assert TemplateApplication.query.count() == 1, 'must not duplicate'
        assert ConfigSnapshot.query.count() == 2, 'but each apply is its own snapshot'


class TestPartialAndFailedApplies:
    def test_partial_apply_still_records_a_snapshot(self, db, apply_post, user):
        """One section failing must not lose the rollback point for the part
        that did get written."""
        apply_post(StubClient(fail=['import_application']), as_user=user)

        assert ConfigSnapshot.query.count() == 1

    def test_total_failure_records_no_snapshot(self, db, apply_post, user):
        """Nothing was written, so there is nothing to roll back to — and a
        snapshot here would offer a revert that silently does nothing.

        This is the pre-f04e9a0 production state: every part rejected, table
        empty.
        """
        stub = StubClient(fail=['update_security_config', 'import_application'])
        apply_post(stub, as_user=user)

        assert ConfigSnapshot.query.count() == 0
        assert TemplateApplication.query.count() == 0

    def test_failure_to_read_before_state_aborts_without_writing(self, db,
                                                                 apply_post,
                                                                 user):
        """If the pre-state can't be captured the apply must not proceed:
        writing without a rollback point is how you lose a config."""
        stub = StubClient(fail=['get_application'])
        apply_post(stub, as_user=user)

        assert ConfigSnapshot.query.count() == 0
        assert stub.calls == [], 'nothing should have been written'


class TestRouting:
    def test_each_section_goes_to_its_own_endpoint(self, db, apply_post, user):
        """The f04e9a0 regression guard, at the route level: protection_mode
        must not be handed to /import/."""
        stub = StubClient()
        apply_post(stub, as_user=user)

        by_name = {c[0]: c for c in stub.calls}
        assert set(by_name) == {'update_security_config', 'import_application'}
        assert by_name['update_security_config'][2] == {'protection_mode': 'block'}
        assert 'protection_mode' not in by_name['import_application'][2]

    def test_include_flags_reach_the_import_call(self, db, apply_post, user):
        stub = StubClient()
        apply_post(stub, as_user=user,
                   data={'include_servers': 'on', 'include_endpoints': 'on'})

        call = next(c for c in stub.calls if c[0] == 'import_application')
        assert call[3] is True and call[4] is True


class TestPermissions:
    def test_viewer_cannot_apply(self, db, apply_post, viewer):
        stub = StubClient()
        apply_post(stub, as_user=viewer)

        assert stub.calls == []
        assert ConfigSnapshot.query.count() == 0

    def test_anonymous_cannot_apply(self, client, app, account, template,
                                    monkeypatch):
        stub = StubClient()
        monkeypatch.setattr(
            'app.routes.templates.get_client_for_account',
            lambda account_id, min_permission=None: (stub, account),
        )
        resp = client.post(
            f'/templates/{template.id}/apply/{account.id}/app-1.example.com',
            data={}, follow_redirects=False,
        )
        assert resp.status_code in (302, 401)
        assert stub.calls == []
        assert ConfigSnapshot.query.count() == 0


class TestAuditTrail:
    def test_apply_is_audited(self, db, apply_post, user):
        apply_post(StubClient(), as_user=user)
        assert AuditLog.query.count() >= 1
