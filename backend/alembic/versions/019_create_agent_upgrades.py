"""019_create_agent_upgrades

Revision ID: 019_create_agent_upgrades
Revises: 018_create_agent_commands
Create Date: 2026-08-07 13:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


revision: str = '019_create_agent_upgrades'
down_revision: Union[str, None] = '018_create_agent_commands'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'agent_upgrades',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('device_id', UUID(as_uuid=True), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False),
        sa.Column('current_version', sa.String(50), nullable=False),
        sa.Column('target_version', sa.String(50), nullable=False, server_default='1.2.0'),
        sa.Column('status', sa.String(50), nullable=False, server_default='AVAILABLE'),
        sa.Column('rollback_status', sa.String(50), nullable=False, server_default='NONE'),
        sa.Column('progress_percent', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('logs', sa.Text(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_agent_upgrades_id', 'agent_upgrades', ['id'])
    op.create_index('ix_agent_upgrades_device_id', 'agent_upgrades', ['device_id'])
    op.create_index('ix_agent_upgrades_status', 'agent_upgrades', ['status'])
    op.create_index('ix_agent_upgrades_rollback_status', 'agent_upgrades', ['rollback_status'])


def downgrade() -> None:
    op.drop_table('agent_upgrades')
