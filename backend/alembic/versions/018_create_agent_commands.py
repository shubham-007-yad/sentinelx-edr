"""018_create_agent_commands

Revision ID: 018_create_agent_commands
Revises: 017_add_agent_health_metrics
Create Date: 2026-08-07 13:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSON


# revision identifiers, used by Alembic.
revision: str = '018_create_agent_commands'
down_revision: Union[str, None] = '017_add_agent_health_metrics'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'agent_commands',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('device_id', UUID(as_uuid=True), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False),
        sa.Column('issuer_id', UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('command_type', sa.String(50), nullable=False),
        sa.Column('status', sa.String(50), nullable=False, server_default='PENDING'),
        sa.Column('payload', JSON(), nullable=True),
        sa.Column('result_output', sa.Text(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('execution_duration_ms', sa.Integer(), nullable=True),
        sa.Column('queued_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('dispatched_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_agent_commands_id', 'agent_commands', ['id'])
    op.create_index('ix_agent_commands_device_id', 'agent_commands', ['device_id'])
    op.create_index('ix_agent_commands_issuer_id', 'agent_commands', ['issuer_id'])
    op.create_index('ix_agent_commands_command_type', 'agent_commands', ['command_type'])
    op.create_index('ix_agent_commands_status', 'agent_commands', ['status'])
    op.create_index('ix_agent_commands_queued_at', 'agent_commands', ['queued_at'])

    op.create_table(
        'agent_command_audit_logs',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('command_id', UUID(as_uuid=True), sa.ForeignKey('agent_commands.id', ondelete='CASCADE'), nullable=False),
        sa.Column('device_id', UUID(as_uuid=True), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False),
        sa.Column('issuer_username', sa.String(100), nullable=False),
        sa.Column('command_type', sa.String(50), nullable=False),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_agent_command_audit_logs_id', 'agent_command_audit_logs', ['id'])
    op.create_index('ix_agent_command_audit_logs_command_id', 'agent_command_audit_logs', ['command_id'])
    op.create_index('ix_agent_command_audit_logs_device_id', 'agent_command_audit_logs', ['device_id'])
    op.create_index('ix_agent_command_audit_logs_created_at', 'agent_command_audit_logs', ['created_at'])


def downgrade() -> None:
    op.drop_table('agent_command_audit_logs')
    op.drop_table('agent_commands')
