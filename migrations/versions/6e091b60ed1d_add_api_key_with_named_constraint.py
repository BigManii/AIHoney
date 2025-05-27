"""Add api_key with named constraint

Revision ID: 6e091b60ed1d
Revises: 3cce8d833272
Create Date: 2025-05-23 13:04:17.748502

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6e091b60ed1d'
down_revision = '3cce8d833272'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('honeypots', schema=None) as batch_op:
        batch_op.add_column(sa.Column('api_key', sa.String(length=128), nullable=False))
        batch_op.create_unique_constraint('uq_honeypots_api_key', ['api_key'])


def downgrade():
    with op.batch_alter_table('honeypots', schema=None) as batch_op:
        batch_op.drop_constraint('uq_honeypots_api_key', type_='unique')
        batch_op.drop_column('api_key')
