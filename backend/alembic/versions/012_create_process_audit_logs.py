"""012_create_process_audit_logs

Revision ID: 012_create_process_audit_logs
Revises: 011_add_process_response_actions
Create Date: 2026-07-30 20:41:15.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '012_create_process_audit_logs'
down_revision: Union[str, None] = '011_add_process_response_actions'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create processeventtype enum
    processeventtype = postgresql.ENUM(
        'PROCESS_STARTED',
        'PROCESS_TERMINATED',
        'RESPONSE_ACTION',
        'DETECTION_FOUND',
        name='processeventtype',
        create_type=False
    )
    processeventtype.create(op.get_bind(), checkfirst=True)

    # Create process_audit_logs table
    op.create_table(
        'process_audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False),
        sa.Column('pid', sa.Integer(), nullable=False),
        sa.Column('ppid', sa.Integer(), nullable=True),
        sa.Column('process_name', sa.String(length=255), nullable=False),
        sa.Column('event_type', sa.Enum('PROCESS_STARTED', 'PROCESS_TERMINATED', 'RESPONSE_ACTION', 'DETECTION_FOUND', name='processeventtype'), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False)
    )
    op.create_index('ix_process_audit_logs_id', 'process_audit_logs', ['id'])
    op.create_index('ix_process_audit_logs_device_id', 'process_audit_logs', ['device_id'])
    op.create_index('ix_process_audit_logs_pid', 'process_audit_logs', ['pid'])
    op.create_index('ix_process_audit_logs_process_name', 'process_audit_logs', ['process_name'])
    op.create_index('ix_process_audit_logs_event_type', 'process_audit_logs', ['event_type'])
    op.create_index('ix_process_audit_logs_timestamp', 'process_audit_logs', ['timestamp'])


def downgrade() -> None:
    op.drop_table('process_audit_logs')
    op.execute("DROP TYPE IF EXISTS processeventtype;")
