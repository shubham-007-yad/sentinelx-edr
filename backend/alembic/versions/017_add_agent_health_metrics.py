"""017_add_agent_health_metrics

Revision ID: 017_add_agent_health_metrics
Revises: 016_extend_device_fleet_inventory
Create Date: 2026-08-07 12:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '017_add_agent_health_metrics'
down_revision: Union[str, None] = '016_extend_device_fleet_inventory'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('devices', sa.Column('cpu_usage_percent', sa.Float(), nullable=True, server_default='0.0'))
    op.add_column('devices', sa.Column('ram_usage_mb', sa.Float(), nullable=True, server_default='0.0'))
    op.add_column('devices', sa.Column('ram_usage_percent', sa.Float(), nullable=True, server_default='0.0'))
    op.add_column('devices', sa.Column('disk_usage_percent', sa.Float(), nullable=True, server_default='0.0'))
    op.add_column('devices', sa.Column('agent_uptime_seconds', sa.Integer(), nullable=True, server_default='0'))
    op.add_column('devices', sa.Column('service_status', sa.String(50), nullable=True, server_default='RUNNING'))
    op.add_column('devices', sa.Column('last_telemetry_upload', sa.DateTime(timezone=True), nullable=True))
    op.add_column('devices', sa.Column('last_policy_sync', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('devices', 'last_policy_sync')
    op.drop_column('devices', 'last_telemetry_upload')
    op.drop_column('devices', 'service_status')
    op.drop_column('devices', 'agent_uptime_seconds')
    op.drop_column('devices', 'disk_usage_percent')
    op.drop_column('devices', 'ram_usage_percent')
    op.drop_column('devices', 'ram_usage_mb')
    op.drop_column('devices', 'cpu_usage_percent')
