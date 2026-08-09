"""015_add_device_applied_policy_version

Revision ID: 015_add_device_applied_policy_version
Revises: 014_create_security_policies
Create Date: 2026-08-05 10:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '015_add_device_applied_policy_version'
down_revision: Union[str, None] = '014_create_security_policies'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('devices', sa.Column('applied_policy_version', sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column('devices', 'applied_policy_version')
