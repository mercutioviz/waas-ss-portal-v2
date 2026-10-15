"""Add traffic_comparisons table and the log_pulls columns that join it

Revision ID: c3f81a0b5d47
Revises: a1c4e7b20d93
Create Date: 2026-10-07 00:00:00.000000

Hand-written for the same reason as a1c4e7b20d93: `wsgi.py` calls
`db.create_all()` at import, so autogenerate sees new tables already present
and emits nothing for them while sweeping in unrelated pre-existing drift.

Both halves guard on what is already there. `create_all()` creates the table
and the columns but never the `server_default`s, and an existing deployment
will have `log_pulls` rows predating the three new columns — so the adds carry
defaults and are backfilled rather than left NULL on a NOT NULL column.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c3f81a0b5d47'
down_revision = 'a1c4e7b20d93'
branch_labels = None
depends_on = None

TABLE = 'traffic_comparisons'
PULLS = 'log_pulls'
NEW_PULL_COLUMNS = ('pinned', 'comparison_id', 'window_label')


def _inspector():
    return sa.inspect(op.get_bind())


def _has_table(name):
    return _inspector().has_table(name)


def _pull_columns():
    if not _has_table(PULLS):
        return set()
    return {c['name'] for c in _inspector().get_columns(PULLS)}


def upgrade():
    if not _has_table(TABLE):
        op.create_table(
            TABLE,
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('account_id', sa.Integer(), nullable=False),
            sa.Column('app_id', sa.String(length=255), nullable=False),
            sa.Column('app_name', sa.String(length=255), nullable=False),

            # --- plan ---
            sa.Column('change_at', sa.Integer(), nullable=False),
            sa.Column('duration_seconds', sa.Integer(), nullable=False,
                      server_default='7200'),
            sa.Column('guard_seconds', sa.Integer(), nullable=False,
                      server_default='180'),
            sa.Column('control_days', sa.Integer(), nullable=False,
                      server_default='1'),
            sa.Column('focus_url', sa.String(length=500), nullable=True),
            sa.Column('segments_data', sa.Text(), nullable=True),
            sa.Column('change_note', sa.String(length=500), nullable=True),

            # --- lifecycle ---
            sa.Column('status', sa.String(length=20), nullable=False,
                      server_default='pending'),
            sa.Column('session_id', sa.String(length=36), nullable=False),
            sa.Column('cancel_requested', sa.Boolean(), nullable=False,
                      server_default=sa.false()),
            sa.Column('current_label', sa.String(length=40), nullable=True),
            # Indexed: the scheduler's due-check queries on this every tick.
            sa.Column('after_due_at', sa.DateTime(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('started_at', sa.DateTime(), nullable=True),
            sa.Column('completed_at', sa.DateTime(), nullable=True),
            sa.Column('error_message', sa.Text(), nullable=True),

            # --- progress ---
            sa.Column('rows_expected', sa.Integer(), nullable=False,
                      server_default='0'),
            sa.Column('windows_total', sa.Integer(), nullable=False,
                      server_default='0'),

            # --- retention ---
            sa.Column('pinned', sa.Boolean(), nullable=False,
                      server_default=sa.false()),

            # --- results ---
            sa.Column('result_data', sa.Text(), nullable=True),
            sa.Column('report_data', sa.Text(), nullable=True),

            sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['account_id'], ['waas_accounts.id'],
                                    ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('session_id', name='uq_traffic_comparison_session'),
        )
        with op.batch_alter_table(TABLE, schema=None) as batch_op:
            for column in ('user_id', 'account_id', 'app_id', 'status',
                           'created_at', 'session_id', 'after_due_at'):
                batch_op.create_index(op.f(f'ix_{TABLE}_{column}'),
                                      [column], unique=False)

    existing = _pull_columns()
    if existing and not set(NEW_PULL_COLUMNS) <= existing:
        with op.batch_alter_table(PULLS, schema=None) as batch_op:
            if 'pinned' not in existing:
                batch_op.add_column(sa.Column('pinned', sa.Boolean(),
                                              nullable=False,
                                              server_default=sa.false()))
            if 'comparison_id' not in existing:
                batch_op.add_column(sa.Column('comparison_id', sa.Integer(),
                                              nullable=True))
            if 'window_label' not in existing:
                batch_op.add_column(sa.Column('window_label',
                                              sa.String(length=40),
                                              nullable=True))
        with op.batch_alter_table(PULLS, schema=None) as batch_op:
            if 'comparison_id' not in existing:
                batch_op.create_index(op.f(f'ix_{PULLS}_comparison_id'),
                                      ['comparison_id'], unique=False)
        # No FK from log_pulls.comparison_id: SQLite runs with
        # `PRAGMA foreign_keys = 0`, so the constraint would never be
        # enforced, and adding one on SQLite means a full table rebuild of a
        # table that can hold millions of rows. Teardown is explicit in
        # `app/account_deletion.py` regardless — see its module docstring.


def downgrade():
    existing = _pull_columns()
    if existing & set(NEW_PULL_COLUMNS):
        with op.batch_alter_table(PULLS, schema=None) as batch_op:
            if 'comparison_id' in existing:
                batch_op.drop_index(op.f(f'ix_{PULLS}_comparison_id'))
            for column in NEW_PULL_COLUMNS:
                if column in existing:
                    batch_op.drop_column(column)

    if _has_table(TABLE):
        with op.batch_alter_table(TABLE, schema=None) as batch_op:
            for column in ('after_due_at', 'session_id', 'created_at', 'status',
                           'app_id', 'account_id', 'user_id'):
                batch_op.drop_index(op.f(f'ix_{TABLE}_{column}'))
        op.drop_table(TABLE)
