"""Enforce at most one active standalone log pull, in the database

Revision ID: e5b2c70f41aa
Revises: d7a4e91c2b08
Create Date: 2026-11-23 00:00:00.000000

`create_pull` and `resume_pull` both call `active_pull()` and refuse if one is
already running, but that is check-then-act across a gevent yield: `wsgi.py`
calls `monkey.patch_all()`, and between the check and the INSERT `create_pull`
runs `get_client_for_account()` and `preflight()`, which make WaaS API calls and
hand the event loop to other greenlets for seconds at a time. Two submissions
that overlap in that window both see no active pull and both proceed.

Two pulls on one gevent worker is not merely slow: they interleave on the same
event loop, contend for the same WaaS API rate budget, and each write
checkpoints under `instance/log_pulls/`, so the fix has to be something the
application cannot race past.

A partial unique index on a constant expression gives SQLite "at most one row
matching this predicate". Non-matching rows are not in the index at all, so
completed pulls accumulate freely.

**Scoped to `comparison_id IS NULL`.** A comparison arms all of its
immediately-collectable windows at once as several child rows in STATUS_PENDING
and drains them one at a time, so pending children are a queue rather than
concurrent work. Without this clause, arming any comparison with more than one
settled window fails outright — which is what the first draft of this migration
did, caught by `test_traffic_comparison.py`.

Mutual exclusion *between* a comparison and a standalone pull stays in the
application, where it already was: `create_pull` refuses while any pull is
active, children included, and `run_due_comparisons` refuses to start while any
pull holds the slot. Neither races itself — the scheduler is a single job — so
only the standalone path needs a database backstop.

The predicate must stay in step with `LogPull.ACTIVE_STATUSES`;
`test_logpull_single_active.py` fails if the two drift apart.

Note the index is reflected through `sqlite_master`, not SQLAlchemy's
inspector: `get_indexes()` skips expression-based indexes entirely ("Skipped
unsupported reflection of expression-based index"), so an inspector-based guard
silently reports the index as absent and makes `downgrade()` a no-op.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e5b2c70f41aa'
down_revision = 'd7a4e91c2b08'
branch_labels = None
depends_on = None

PULLS = 'log_pulls'
INDEX = 'ix_log_pulls_single_active'
ACTIVE = ('pending', 'running')
PREDICATE = ("comparison_id IS NULL AND status IN ("
             + ', '.join(f"'{s}'" for s in ACTIVE) + ")")


def _has_table(bind):
    return bind.execute(sa.text(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=:n"
    ), {'n': PULLS}).scalar() is not None


def _index_sql(bind):
    """Current definition of the index, or None. Reads sqlite_master because
    SQLAlchemy's inspector cannot reflect expression-based indexes."""
    return bind.execute(sa.text(
        "SELECT sql FROM sqlite_master WHERE type='index' AND name=:n"
    ), {'n': INDEX}).scalar()


def upgrade():
    bind = op.get_bind()
    if not _has_table(bind):
        return

    existing = _index_sql(bind)
    if existing is not None:
        if PREDICATE in existing:
            return
        # An earlier, unscoped form of this index is present — from a
        # deployment that ran the first draft, or from `create_all()` building
        # it off a model that predates the scoping. Replace it.
        op.execute(f'DROP INDEX {INDEX}')

    # A deployment interrupted mid-pull can leave rows in an active status that
    # no greenlet is working on any more. Creating a unique index over two such
    # rows would fail outright, so settle them first: anything still 'active'
    # at migration time is by definition not running, because nothing is.
    stale = bind.execute(sa.text(
        f'SELECT COUNT(*) FROM {PULLS} WHERE {PREDICATE}'
    )).scalar()
    if stale > 1:
        # Keep the newest as interrupted-and-resumable and settle the rest the
        # same way. Resuming skips days already checkpointed on disk, so no
        # collected rows are lost either way.
        bind.execute(sa.text(
            f"UPDATE {PULLS} SET status = 'interrupted' "
            f"WHERE {PREDICATE} AND id NOT IN ("
            f"  SELECT id FROM {PULLS} WHERE {PREDICATE} "
            f"  ORDER BY created_at DESC LIMIT 1)"
        ))

    op.execute(f'CREATE UNIQUE INDEX {INDEX} ON {PULLS} ((1)) WHERE {PREDICATE}')


def downgrade():
    bind = op.get_bind()
    if _index_sql(bind) is not None:
        op.execute(f'DROP INDEX {INDEX}')
