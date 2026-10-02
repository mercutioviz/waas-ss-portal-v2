"""Add app_traffic_snapshots table

Revision ID: a1c4e7b20d93
Revises: 6693db3f1d68
Create Date: 2026-10-02 00:00:00.000000

Hand-written for the same reason as 6693db3f1d68: `wsgi.py` calls
`db.create_all()` at import, so autogenerate sees the table already present
and emits nothing for it while sweeping in unrelated pre-existing drift.
Only this table is here, and the upgrade is a no-op where create_all has
already run.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a1c4e7b20d93'
down_revision = '6693db3f1d68'
branch_labels = None
depends_on = None

TABLE = 'app_traffic_snapshots'


def _exists(name):
    bind = op.get_bind()
    return sa.inspect(bind).has_table(name)


def upgrade():
    if _exists(TABLE):
        return

    op.create_table(
        TABLE,
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('account_id', sa.Integer(), nullable=False),
        sa.Column('app_name', sa.String(length=255), nullable=False),
        sa.Column('window_days', sa.Integer(), nullable=False, server_default='30'),
        sa.Column('captured_at', sa.DateTime(), nullable=False),

        # Independently nullable: requests come from the v4 logs API and are
        # available everywhere; metered_bytes and bad_share come from the v2
        # bandwidth report and need v2 credentials on the account.
        sa.Column('requests', sa.Integer(), nullable=True),
        sa.Column('metered_bytes', sa.BigInteger(), nullable=True),
        sa.Column('bad_share', sa.Float(), nullable=True),
        sa.Column('error', sa.String(length=255), nullable=True),

        sa.ForeignKeyConstraint(['account_id'], ['waas_accounts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('account_id', 'app_name', 'window_days',
                            name='uq_app_traffic_snapshot_scope'),
    )
    with op.batch_alter_table(TABLE, schema=None) as batch_op:
        batch_op.create_index(op.f('ix_app_traffic_snapshots_account_id'),
                              ['account_id'], unique=False)
        batch_op.create_index(op.f('ix_app_traffic_snapshots_app_name'),
                              ['app_name'], unique=False)
        batch_op.create_index(op.f('ix_app_traffic_snapshots_captured_at'),
                              ['captured_at'], unique=False)


def downgrade():
    if not _exists(TABLE):
        return
    with op.batch_alter_table(TABLE, schema=None) as batch_op:
        batch_op.drop_index(op.f('ix_app_traffic_snapshots_captured_at'))
        batch_op.drop_index(op.f('ix_app_traffic_snapshots_app_name'))
        batch_op.drop_index(op.f('ix_app_traffic_snapshots_account_id'))
    op.drop_table(TABLE)
