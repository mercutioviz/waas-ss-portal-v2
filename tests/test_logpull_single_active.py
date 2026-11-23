"""One active log pull at a time, enforced by the database.

`active_pull()` in routes/traffic.py checks before starting, but that is
check-then-act across a gevent yield: `wsgi.py` calls `monkey.patch_all()`, and
`create_pull` runs `preflight()` — which talks to the WaaS API — between its
check and its INSERT. Two overlapping submissions can both pass the check.

These tests cover the backstop: a partial unique index that makes the second
INSERT fail regardless of what the route did or didn't check.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.models import LogPull, User, WaasAccount


INDEX = 'ix_log_pulls_single_active'


@pytest.fixture
def user(app, db):
    u = User(username='pull-tester', email='pt@example.com', role='user',
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


def make_pull(db, user, account, status, app_id='app-1.example.com',
              comparison_id=None):
    now = int(datetime.now(timezone.utc).timestamp())
    pull = LogPull(
        user_id=user.id, account_id=account.id, app_id=app_id,
        app_name=app_id, mode='sample', window_days=7,
        range_start=now - 7 * 86400, range_end=now,
        session_id=f'sess-{status}-{app_id}', status=status,
        comparison_id=comparison_id,
    )
    db.session.add(pull)
    return pull


class TestIndexExists:
    def test_create_all_builds_the_index(self, app, db):
        """The index must come from the models too, not only from the
        migration — wsgi.py calls create_all() at import, so a deployment
        built that way would otherwise have no enforcement at all."""
        names = {row[1] for row in db.session.execute(
            text('PRAGMA index_list(log_pulls)'))}
        assert INDEX in names

    def test_index_predicate_matches_active_statuses(self, app, db):
        """Drift guard. If someone adds a third active-like status to
        ACTIVE_STATUSES without updating the index predicate, the index
        silently stops covering what it was written to cover."""
        sql = db.session.execute(text(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name=:n"
        ), {'n': INDEX}).scalar()
        assert sql, f'{INDEX} not found in sqlite_master'

        for status in LogPull.ACTIVE_STATUSES:
            assert f"'{status}'" in sql, (
                f'{status!r} is in ACTIVE_STATUSES but not in the index '
                f'predicate: {sql}')

        # And nothing extra: a terminal status inside the predicate would
        # wrongly block new pulls once one had finished.
        for status in LogPull.TERMINAL_STATUSES:
            assert f"'{status}'" not in sql, (
                f'{status!r} is terminal but appears in the index predicate')

    def test_index_is_scoped_to_standalone_pulls(self, app, db):
        """Without this clause, arming a comparison with more than one settled
        window fails: its children are all created pending at once."""
        sql = db.session.execute(text(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name=:n"
        ), {'n': INDEX}).scalar()
        assert 'comparison_id IS NULL' in sql


class TestOneActiveAtATime:
    @pytest.mark.parametrize('first', LogPull.ACTIVE_STATUSES)
    @pytest.mark.parametrize('second', LogPull.ACTIVE_STATUSES)
    def test_second_active_pull_is_rejected(self, app, db, user, account,
                                            first, second):
        make_pull(db, user, account, first, 'app-1.example.com')
        db.session.commit()

        make_pull(db, user, account, second, 'app-2.example.com')
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()

    def test_rejection_holds_across_different_accounts(self, app, db, user,
                                                       account):
        """The constraint is the single gevent worker, not the account — a
        pull on another account contends for exactly the same event loop."""
        other = WaasAccount(user_id=user.id, account_name='Other', is_active=True)
        other.api_key = 'k'
        db.session.add(other)
        db.session.commit()
        # Read the id before staging the second pull: touching it afterwards
        # would autoflush the pending INSERT and raise outside the block below.
        other_id = other.id

        make_pull(db, user, account, LogPull.STATUS_RUNNING, 'a.example.com')
        db.session.commit()

        pull = make_pull(db, user, account, LogPull.STATUS_PENDING, 'b.example.com')
        pull.account_id = other_id
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()

    @pytest.mark.parametrize('terminal', LogPull.TERMINAL_STATUSES)
    def test_terminal_pulls_do_not_hold_the_slot(self, app, db, user, account,
                                                 terminal):
        make_pull(db, user, account, terminal, 'done.example.com')
        db.session.commit()

        make_pull(db, user, account, LogPull.STATUS_PENDING, 'next.example.com')
        db.session.commit()  # must not raise

        assert LogPull.query.count() == 2

    def test_interrupted_does_not_hold_the_slot(self, app, db, user, account):
        """`interrupted` is resumable but not active — a pull orphaned by a
        restart must not block every future pull until someone notices."""
        make_pull(db, user, account, LogPull.STATUS_INTERRUPTED, 'old.example.com')
        db.session.commit()

        make_pull(db, user, account, LogPull.STATUS_RUNNING, 'new.example.com')
        db.session.commit()

        assert LogPull.query.count() == 2

    def test_many_completed_pulls_accumulate_freely(self, app, db, user, account):
        for i in range(10):
            make_pull(db, user, account, LogPull.STATUS_COMPLETE, f'app{i}.example.com')
        db.session.commit()
        assert LogPull.query.count() == 10

    def test_slot_frees_when_the_active_pull_finishes(self, app, db, user, account):
        first = make_pull(db, user, account, LogPull.STATUS_RUNNING, 'a.example.com')
        db.session.commit()

        first.status = LogPull.STATUS_COMPLETE
        db.session.commit()

        make_pull(db, user, account, LogPull.STATUS_PENDING, 'b.example.com')
        db.session.commit()  # must not raise

    def test_resuming_into_an_occupied_slot_is_rejected(self, app, db, user,
                                                        account):
        """resume_pull flips an existing row back to pending; the index has to
        catch that UPDATE too, not only INSERTs."""
        make_pull(db, user, account, LogPull.STATUS_RUNNING, 'running.example.com')
        stale = make_pull(db, user, account, LogPull.STATUS_INTERRUPTED,
                          'stale.example.com')
        db.session.commit()

        stale.status = LogPull.STATUS_PENDING
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


class TestComparisonChildrenAreExempt:
    """A comparison arms every immediately-collectable window at once and
    drains them sequentially, so several pending children is the normal,
    correct state — not contention. The first draft of the index did not say
    `comparison_id IS NULL` and broke arming outright.
    """

    def _comparison_id(self, db, user, account):
        from app.models import TrafficComparison
        now = int(datetime.now(timezone.utc).timestamp())
        comp = TrafficComparison(
            user_id=user.id, account_id=account.id,
            app_id='app-1.example.com', app_name='app-1.example.com',
            change_at=datetime.now(timezone.utc) - timedelta(days=1),
            duration_seconds=7200, guard_seconds=180, control_days=3,
            status=TrafficComparison.STATUS_PENDING,
            session_id='cmp-session',
        )
        db.session.add(comp)
        db.session.commit()
        return comp.id

    def test_many_pending_children_coexist(self, app, db, user, account):
        cid = self._comparison_id(db, user, account)
        for label in ('before', 'after', 'control-1', 'control-2', 'control-3'):
            make_pull(db, user, account, LogPull.STATUS_PENDING,
                      f'{label}.example.com', comparison_id=cid)
        db.session.commit()  # must not raise

        assert LogPull.query.filter_by(comparison_id=cid).count() == 5

    def test_a_child_does_not_block_a_standalone_pull_row(self, app, db, user,
                                                          account):
        """The database does not stop it; `create_pull`'s own active_pull()
        check is what keeps the two from running at once."""
        cid = self._comparison_id(db, user, account)
        make_pull(db, user, account, LogPull.STATUS_RUNNING, 'child.example.com',
                  comparison_id=cid)
        db.session.commit()

        make_pull(db, user, account, LogPull.STATUS_PENDING, 'solo.example.com')
        db.session.commit()  # must not raise

    def test_standalone_pulls_are_still_constrained_alongside_children(
            self, app, db, user, account):
        cid = self._comparison_id(db, user, account)
        make_pull(db, user, account, LogPull.STATUS_PENDING, 'child.example.com',
                  comparison_id=cid)
        make_pull(db, user, account, LogPull.STATUS_RUNNING, 'solo-1.example.com')
        db.session.commit()

        make_pull(db, user, account, LogPull.STATUS_PENDING, 'solo-2.example.com')
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


class TestActivePullHelper:
    def test_active_pull_finds_the_holder(self, app, db, user, account):
        from app.routes.traffic import active_pull

        make_pull(db, user, account, LogPull.STATUS_COMPLETE, 'done.example.com')
        running = make_pull(db, user, account, LogPull.STATUS_RUNNING,
                            'live.example.com')
        db.session.commit()

        assert active_pull().id == running.id

    def test_active_pull_is_none_when_slot_is_free(self, app, db, user, account):
        from app.routes.traffic import active_pull

        make_pull(db, user, account, LogPull.STATUS_COMPLETE, 'done.example.com')
        db.session.commit()

        assert active_pull() is None
