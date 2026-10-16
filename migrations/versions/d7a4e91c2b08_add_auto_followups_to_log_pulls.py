"""Add log_pulls.auto_followups

Revision ID: d7a4e91c2b08
Revises: c3f81a0b5d47
Create Date: 2026-10-16 00:00:00.000000

Hand-written for the same reason as c3f81a0b5d47: `wsgi.py` calls
`db.create_all()` at import, so autogenerate sees the column already present on
a running deployment and emits nothing for it while sweeping in unrelated
pre-existing drift.

`create_all()` creates the column but never its `server_default`, and existing
`log_pulls` rows predate it, so the add carries a default and is backfilled
rather than left NULL on a NOT NULL column. The default is false: a pull
created before this option existed never had consent to probe the customer's
origin, and must not acquire it retroactively.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd7a4e91c2b08'
down_revision = 'c3f81a0b5d47'
branch_labels = None
depends_on = None

PULLS = 'log_pulls'
COLUMN = 'auto_followups'


def _inspector():
    return sa.inspect(op.get_bind())


def _pull_columns():
    if not _inspector().has_table(PULLS):
        return set()
    return {c['name'] for c in _inspector().get_columns(PULLS)}


def upgrade():
    if COLUMN in _pull_columns():
        return
    with op.batch_alter_table(PULLS) as batch:
        batch.add_column(sa.Column(COLUMN, sa.Boolean(), nullable=False,
                                   server_default=sa.false()))
    op.execute(f'UPDATE {PULLS} SET {COLUMN} = 0 WHERE {COLUMN} IS NULL')


def downgrade():
    if COLUMN not in _pull_columns():
        return
    with op.batch_alter_table(PULLS) as batch:
        batch.drop_column(COLUMN)
