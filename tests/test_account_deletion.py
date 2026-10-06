"""Tests for permanently deleting a WaaS account.

app/routes/accounts.py had no tests at all, and its delete_account route did not
work: SQLite runs with PRAGMA foreign_keys=0 so the declared ondelete='CASCADE'
never fired, and only AccountShare had an ORM cascade, so SQLAlchemy tried to
NULL a NOT NULL account_id and raised IntegrityError. Several tests below pin
that regression and the side effects a row-only delete would have orphaned.
"""
import os
from datetime import datetime, timedelta

import pytest

from app import db
from app.account_deletion import (
    CHILD_MODELS,
    account_delete_blockers,
    account_delete_impact,
    delete_waas_account,
)
from app.models import (
    AccountShare, AppTrafficSnapshot, AuditLog, ConfigSnapshot, FeatureApplication,
    LogPull, ProxySession, ReportRun, ScheduledReport, SecurityMetricSnapshot,
    SiteProfile, TemplateApplication, User, WaasAccount,
)


@pytest.fixture(autouse=True)
def _no_rate_limit():
    """The delete route is capped at 10/min and the limiter is live in testing."""
    from app import limiter
    was = limiter.enabled
    limiter.enabled = False
    yield
    limiter.enabled = was


@pytest.fixture
def user(app, db):
    u = User(username='deleter', email='deleter@example.com', role='user', is_active=True)
    u.set_password('x')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def account(app, db, user):
    acc = WaasAccount(user_id=user.id, account_name='Doomed Account', is_active=True)
    acc.api_key = 'v4-key'
    db.session.add(acc)
    db.session.commit()
    return acc


@pytest.fixture
def logged_in_client(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True
    return client


def _populate(account, user, snapshots=3):
    """Put at least one row in every child table, plus a ReportRun grandchild."""
    from app.models import ConfigTemplate, Feature

    sharee = User(username=f'sharee{account.id}', email=f'sharee{account.id}@example.com',
                  role='user', is_active=True)
    sharee.set_password('x')
    db.session.add(sharee)
    db.session.commit()
    db.session.add(AccountShare(account_id=account.id, user_id=sharee.id,
                                permission='read', granted_by=user.id))

    feature = Feature(user_id=user.id, name=f'Feat {account.id}')
    template = ConfigTemplate(user_id=user.id, name=f'Tmpl {account.id}')
    db.session.add_all([feature, template])
    db.session.commit()

    db.session.add(ConfigSnapshot(account_id=account.id, user_id=user.id, app_id='app1',
                                  resource_type='security'))
    db.session.add(ProxySession(user_id=user.id, account_id=account.id,
                                app_id='app1', domain='a.example.com', status='stopped'))
    db.session.add(FeatureApplication(feature_id=feature.id, account_id=account.id,
                                      app_name='app1', applied_by=user.id))
    db.session.add(TemplateApplication(template_id=template.id, account_id=account.id,
                                       app_name='app1', applied_by=user.id))
    db.session.add(SiteProfile(user_id=user.id, account_id=account.id,
                               target_url='https://a.example.com', session_id=f'sess-{account.id}',
                               status=SiteProfile.STATUS_COMPLETE))
    db.session.add(AppTrafficSnapshot(account_id=account.id, app_name='app1'))
    for _i in range(snapshots):
        db.session.add(SecurityMetricSnapshot(account_id=account.id, app_id='app1',
                                              app_name='app1', quick_range='r_1h'))

    report = ScheduledReport(user_id=user.id, account_id=account.id, name='Weekly',
                             report_type='waf_summary', frequency='weekly')
    db.session.add(report)
    db.session.commit()
    db.session.add(ReportRun(report_id=report.id, status='success'))

    pull = _log_pull(account, user, LogPull.STATUS_COMPLETE,
                     session_id=f'pull-sess-{account.id}')
    db.session.add(pull)
    db.session.commit()
    return report, pull


def _log_pull(account, user, status, session_id='pull-sess'):
    now = datetime.utcnow()
    return LogPull(user_id=user.id, account_id=account.id, app_id='app1', app_name='app1',
                   range_start=now - timedelta(days=1), range_end=now,
                   session_id=session_id, status=status)


class TestChildModelCoverage:
    def test_every_account_child_table_is_listed(self, app, db):
        """Walk the mapper registry and fail loudly if someone adds a table with
        an account_id FK without adding it to CHILD_MODELS. Reflection belongs
        here, as a test that names the omission — not in the delete path, where
        it would silently widen the blast radius of an irreversible operation."""
        listed = {model for _key, model, _label in CHILD_MODELS}
        discovered = set()
        for mapper in db.Model.registry.mappers:
            table = mapper.class_.__table__
            for column in table.columns:
                for fk in column.foreign_keys:
                    if fk.column.table.name == 'waas_accounts':
                        discovered.add(mapper.class_)
        assert discovered == listed, (
            f'Child tables not handled by delete_waas_account: '
            f'{sorted(c.__name__ for c in discovered - listed)}'
        )


class TestDeleteWaasAccount:
    def test_account_with_metric_snapshots_deletes_cleanly(self, app, db, account, user):
        """The exact regression: this raised
        IntegrityError: NOT NULL constraint failed: security_metric_snapshots.account_id."""
        for _i in range(5):
            db.session.add(SecurityMetricSnapshot(account_id=account.id, app_id='app1',
                                                  app_name='app1', quick_range='r_1h'))
        db.session.commit()
        account_id = account.id

        delete_waas_account(account, app.instance_path)

        assert WaasAccount.query.get(account_id) is None
        assert SecurityMetricSnapshot.query.filter_by(account_id=account_id).count() == 0

    def test_removes_rows_from_every_child_table(self, app, db, account, user):
        _populate(account, user)
        account_id = account.id

        delete_waas_account(account, app.instance_path)

        assert WaasAccount.query.get(account_id) is None
        for key, model, _label in CHILD_MODELS:
            assert model.query.filter_by(account_id=account_id).count() == 0, key

    def test_report_runs_are_removed(self, app, db, account, user):
        """ReportRun has no account_id; a bulk delete of ScheduledReport bypasses
        the ORM cascade that would normally take it."""
        _populate(account, user)
        assert ReportRun.query.count() == 1

        delete_waas_account(account, app.instance_path)

        assert ReportRun.query.count() == 0

    def test_counts_are_reported(self, app, db, account, user):
        _populate(account, user, snapshots=4)

        result = delete_waas_account(account, app.instance_path)

        assert result['counts']['security_metric_snapshots'] == 4
        assert result['counts']['report_runs'] == 1
        assert result['counts']['scheduled_reports'] == 1

    def test_another_account_is_untouched(self, app, db, account, user):
        """Easy to get wrong with a mis-scoped ReportRun subquery."""
        keeper = WaasAccount(user_id=user.id, account_name='Keeper', is_active=True)
        keeper.api_key = 'k2'
        db.session.add(keeper)
        db.session.commit()
        _populate(account, user)
        _populate(keeper, user)
        keeper_id = keeper.id

        delete_waas_account(account, app.instance_path)

        assert WaasAccount.query.get(keeper_id) is not None
        for key, model, _label in CHILD_MODELS:
            assert model.query.filter_by(account_id=keeper_id).count() > 0, key
        assert ReportRun.query.count() == 1

    def test_shares_are_removed(self, app, db, account, user):
        other = User(username='sharee', email='s@example.com', role='user', is_active=True)
        other.set_password('x')
        db.session.add(other)
        db.session.commit()
        db.session.add(AccountShare(account_id=account.id, user_id=other.id,
                                    permission='read', granted_by=user.id))
        db.session.commit()
        account_id = account.id

        delete_waas_account(account, app.instance_path)

        assert AccountShare.query.filter_by(account_id=account_id).count() == 0

    def test_log_pull_directory_is_removed_and_bytes_reported(self, app, db, account, user):
        """LogPull owns instance/log_pulls/<id>/ on disk; deleting the row alone
        would orphan the directory permanently."""
        from app.logpull.store import PullStore

        _report, pull = _populate(account, user)
        store = PullStore(app.instance_path, pull.id)
        os.makedirs(store.root, exist_ok=True)
        with open(os.path.join(store.root, 'day.jsonl.gz'), 'wb') as fh:
            fh.write(b'x' * 2048)
        assert os.path.isdir(store.root)

        result = delete_waas_account(account, app.instance_path)

        assert not os.path.isdir(store.root)
        assert result['bytes_freed'] >= 2048

    def test_active_proxy_sessions_are_stopped_before_rows_go(self, app, db, account, user, monkeypatch):
        """The row holds four OS pids and is the only handle the reaper has."""
        db.session.add(ProxySession(user_id=user.id, account_id=account.id,
                                    app_id='app1', domain='live.example.com',
                                    status='active'))
        db.session.commit()

        stopped = []
        monkeypatch.setattr('app.proxy_manager.stop_session', lambda sid: stopped.append(sid))

        result = delete_waas_account(account, app.instance_path)

        assert len(stopped) == 1
        assert result['sessions_stopped'] == 1

    def test_stopped_sessions_are_not_restopped(self, app, db, account, user, monkeypatch):
        db.session.add(ProxySession(user_id=user.id, account_id=account.id,
                                    app_id='app1', domain='x.example.com', status='stopped'))
        db.session.commit()
        stopped = []
        monkeypatch.setattr('app.proxy_manager.stop_session', lambda sid: stopped.append(sid))

        delete_waas_account(account, app.instance_path)

        assert stopped == []

    def test_failure_to_stop_a_session_does_not_block_the_delete(self, app, db, account, user, monkeypatch):
        db.session.add(ProxySession(user_id=user.id, account_id=account.id,
                                    app_id='app1', domain='x.example.com', status='active'))
        db.session.commit()
        account_id = account.id

        def boom(_sid):
            raise OSError('no such process')

        monkeypatch.setattr('app.proxy_manager.stop_session', boom)

        delete_waas_account(account, app.instance_path)

        assert WaasAccount.query.get(account_id) is None

    def test_cross_account_revert_link_is_nulled_not_left_dangling(self, app, db, account, user):
        keeper = WaasAccount(user_id=user.id, account_name='Keeper', is_active=True)
        keeper.api_key = 'k2'
        db.session.add(keeper)
        db.session.commit()

        doomed_snap = ConfigSnapshot(account_id=account.id, user_id=user.id, app_id='app1',
                                     resource_type='security')
        db.session.add(doomed_snap)
        db.session.commit()
        # config_history always keeps reverts within one account; this asserts we
        # survive it anyway, since the pragma enforces nothing.
        keeper_snap = ConfigSnapshot(account_id=keeper.id, user_id=user.id, app_id='app1',
                                     resource_type='security',
                                     reverted_from_id=doomed_snap.id)
        db.session.add(keeper_snap)
        db.session.commit()
        keeper_snap_id = keeper_snap.id

        delete_waas_account(account, app.instance_path)

        assert ConfigSnapshot.query.get(keeper_snap_id).reverted_from_id is None


class TestBlockers:
    def test_running_log_pull_blocks(self, app, db, account, user):
        db.session.add(_log_pull(account, user, LogPull.STATUS_RUNNING))
        db.session.commit()

        assert account_delete_blockers(account)

    def test_completed_log_pull_does_not_block(self, app, db, account, user):
        db.session.add(_log_pull(account, user, LogPull.STATUS_COMPLETE))
        db.session.commit()

        assert account_delete_blockers(account) == []

    def test_probing_site_profile_blocks(self, app, db, account, user):
        db.session.add(SiteProfile(user_id=user.id, account_id=account.id,
                                   target_url='https://a.example.com', session_id='s-probing',
                                   status=SiteProfile.STATUS_PROBING))
        db.session.commit()

        assert account_delete_blockers(account)

    def test_clean_account_has_no_blockers(self, app, db, account):
        assert account_delete_blockers(account) == []


class TestImpact:
    def test_counts_match_what_deletion_removes(self, app, db, account, user):
        _populate(account, user, snapshots=7)
        impact = {row['key']: row['count'] for row in account_delete_impact(account)}

        result = delete_waas_account(account, app.instance_path)

        for key, count in impact.items():
            assert result['counts'][key] == count, key

    def test_labels_are_present(self, app, db, account):
        for row in account_delete_impact(account):
            assert row['label']


class TestDeleteRoute:
    def test_owner_can_delete_when_confirmed(self, logged_in_client, account, app, db, user):
        _populate(account, user)
        account_id = account.id

        resp = logged_in_client.post(f'/accounts/{account_id}/delete',
                                     data={'confirm': 'YES'})

        assert resp.status_code == 302
        assert WaasAccount.query.get(account_id) is None

    @pytest.mark.parametrize('value', ['yes', 'Yes', 'no', 'Doomed Account', ''])
    def test_anything_other_than_YES_deletes_nothing(self, logged_in_client, account, value):
        """Case-sensitive: an all-caps word is deliberate in a way that 'yes'
        typed on autopilot is not."""
        account_id = account.id

        resp = logged_in_client.post(f'/accounts/{account_id}/delete',
                                     data={'confirm': value})

        assert resp.status_code == 302
        assert WaasAccount.query.get(account_id) is not None

    def test_missing_confirmation_deletes_nothing(self, logged_in_client, account):
        """A bare POST to the URL must not be enough — the dialog is JS."""
        account_id = account.id

        logged_in_client.post(f'/accounts/{account_id}/delete')

        assert WaasAccount.query.get(account_id) is not None

    def test_surrounding_whitespace_is_tolerated(self, logged_in_client, account):
        account_id = account.id

        logged_in_client.post(f'/accounts/{account_id}/delete', data={'confirm': '  YES  '})

        assert WaasAccount.query.get(account_id) is None

    def test_blocked_account_is_not_deleted(self, logged_in_client, account, app, db, user):
        db.session.add(_log_pull(account, user, LogPull.STATUS_RUNNING))
        db.session.commit()
        account_id = account.id

        logged_in_client.post(f'/accounts/{account_id}/delete',
                              data={'confirm': 'YES'})

        assert WaasAccount.query.get(account_id) is not None

    def test_inactive_account_can_be_deleted(self, logged_in_client, account, db):
        """get_account_for_user filters is_active by default; the route passes
        require_active=False so a deactivated account is not undeletable."""
        account.is_active = False
        db.session.commit()
        account_id = account.id

        logged_in_client.post(f'/accounts/{account_id}/delete',
                              data={'confirm': 'YES'})

        assert WaasAccount.query.get(account_id) is None

    def test_admin_share_cannot_delete(self, client, account, app, db, user):
        other = User(username='admin-share', email='as@example.com', role='user', is_active=True)
        other.set_password('x')
        db.session.add(other)
        db.session.commit()
        db.session.add(AccountShare(account_id=account.id, user_id=other.id,
                                    permission='admin', granted_by=user.id))
        db.session.commit()
        account_id = account.id

        with client.session_transaction() as sess:
            sess['_user_id'] = str(other.id)
            sess['_fresh'] = True
        client.post(f'/accounts/{account_id}/delete', data={'confirm': 'YES'})

        assert WaasAccount.query.get(account_id) is not None

    def test_unrelated_user_cannot_delete(self, client, account, app, db):
        stranger = User(username='stranger', email='st@example.com', role='user', is_active=True)
        stranger.set_password('x')
        db.session.add(stranger)
        db.session.commit()
        account_id = account.id

        with client.session_transaction() as sess:
            sess['_user_id'] = str(stranger.id)
            sess['_fresh'] = True
        client.post(f'/accounts/{account_id}/delete', data={'confirm': 'YES'})

        assert WaasAccount.query.get(account_id) is not None

    def test_get_is_not_allowed(self, logged_in_client, account):
        assert logged_in_client.get(f'/accounts/{account.id}/delete').status_code == 405

    def test_requires_login(self, client, account):
        assert client.post(f'/accounts/{account.id}/delete').status_code == 302

    def test_audit_entry_records_the_name(self, logged_in_client, account, app, db, user):
        """resource_id dangles after the delete (and SQLite reuses rowids), so
        the name has to be in the details text."""
        account_id = account.id

        logged_in_client.post(f'/accounts/{account_id}/delete',
                              data={'confirm': 'YES'})

        entry = AuditLog.query.filter_by(action='account_delete').first()
        assert entry is not None
        assert 'Doomed Account' in entry.details

    def test_scope_is_cleared_when_the_scoped_account_is_deleted(self, logged_in_client, account):
        account_id = account.id
        with logged_in_client.session_transaction() as sess:
            sess['current_account_id'] = account_id

        logged_in_client.post(f'/accounts/{account_id}/delete',
                              data={'confirm': 'YES'})

        with logged_in_client.session_transaction() as sess:
            assert sess.get('current_account_id') != account_id


class TestDeleteImpactEndpoint:
    def test_owner_gets_counts(self, logged_in_client, account, app, db, user):
        _populate(account, user, snapshots=6)

        data = logged_in_client.get(f'/accounts/{account.id}/delete-impact').get_json()

        assert data['account_name'] == 'Doomed Account'
        assert data['blockers'] == []
        counts = {row['key']: row['count'] for row in data['impact']}
        assert counts['security_metric_snapshots'] == 6
        assert 'config_snapshots' in counts
        assert data['total'] > 0

    def test_zero_count_categories_are_omitted(self, logged_in_client, account):
        data = logged_in_client.get(f'/accounts/{account.id}/delete-impact').get_json()

        assert data['impact'] == []
        assert data['total'] == 0

    def test_blockers_are_reported(self, logged_in_client, account, app, db, user):
        db.session.add(_log_pull(account, user, LogPull.STATUS_RUNNING))
        db.session.commit()

        data = logged_in_client.get(f'/accounts/{account.id}/delete-impact').get_json()

        assert data['blockers']

    def test_foreign_account_is_not_an_oracle(self, client, account, app, db):
        stranger = User(username='nosy', email='n@example.com', role='user', is_active=True)
        stranger.set_password('x')
        db.session.add(stranger)
        db.session.commit()

        with client.session_transaction() as sess:
            sess['_user_id'] = str(stranger.id)
            sess['_fresh'] = True
        resp = client.get(f'/accounts/{account.id}/delete-impact')

        assert resp.status_code == 404

    def test_requires_login(self, client, account):
        assert client.get(f'/accounts/{account.id}/delete-impact').status_code == 302
