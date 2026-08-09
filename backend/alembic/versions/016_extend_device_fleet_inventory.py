"""016_extend_device_fleet_inventory

Revision ID: 016_extend_device_fleet_inventory
Revises: 015_add_device_applied_policy_version
Create Date: 2026-08-07 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '016_extend_device_fleet_inventory'
down_revision: Union[str, None] = '015_add_device_applied_policy_version'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('devices', sa.Column('health_status', sa.String(50), nullable=False, server_default='HEALTHY'))
    op.add_column('devices', sa.Column('last_command_status', sa.String(50), nullable=False, server_default='NONE'))
    op.add_column('devices', sa.Column('last_checkin', sa.DateTime(timezone=True), nullable=True))
    op.add_column('devices', sa.Column('last_heartbeat', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('devices', 'last_heartbeat')
    op.drop_column('devices', 'last_checkin')
    op.drop_column('devices', 'last_command_status')
    op.drop_column('devices', 'health_status')
