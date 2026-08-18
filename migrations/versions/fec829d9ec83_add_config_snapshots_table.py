"""add config_snapshots table

Revision ID: fec829d9ec83
Revises: b62bc65e5f2c
Create Date: 2026-08-14 18:33:04.986296

Autogenerate again picked up the same unrelated template_applications /
waas_accounts drift stripped from b62bc65e5f2c — left out here for the
same reason.

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fec829d9ec83'
down_revision = 'b62bc65e5f2c'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('config_snapshots',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('account_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('app_id', sa.String(length=255), nullable=False),
    sa.Column('app_name', sa.String(length=255), nullable=True),
    sa.Column('resource_type', sa.String(length=50), nullable=False),
    sa.Column('resource_label', sa.String(length=255), nullable=True),
    sa.Column('section', sa.String(length=50), nullable=True),
    sa.Column('payload_before', sa.Text(), nullable=False),
    sa.Column('payload_applied', sa.Text(), nullable=True),
    sa.Column('batch_id', sa.String(length=36), nullable=True),
    sa.Column('reverted_at', sa.DateTime(), nullable=True),
    sa.Column('reverted_by_id', sa.Integer(), nullable=True),
    sa.Column('reverted_from_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['account_id'], ['waas_accounts.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['reverted_by_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['reverted_from_id'], ['config_snapshots.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('config_snapshots', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_config_snapshots_account_id'), ['account_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_config_snapshots_app_id'), ['app_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_config_snapshots_batch_id'), ['batch_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_config_snapshots_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_config_snapshots_resource_type'), ['resource_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_config_snapshots_user_id'), ['user_id'], unique=False)


def downgrade():
    with op.batch_alter_table('config_snapshots', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_config_snapshots_user_id'))
        batch_op.drop_index(batch_op.f('ix_config_snapshots_resource_type'))
        batch_op.drop_index(batch_op.f('ix_config_snapshots_created_at'))
        batch_op.drop_index(batch_op.f('ix_config_snapshots_batch_id'))
        batch_op.drop_index(batch_op.f('ix_config_snapshots_app_id'))
        batch_op.drop_index(batch_op.f('ix_config_snapshots_account_id'))

    op.drop_table('config_snapshots')
    # ### end Alembic commands ###
