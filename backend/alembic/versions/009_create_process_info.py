"""009_create_process_info

Revision ID: 009_create_process_info
Revises: 008_create_response_audit_logs
Create Date: 2026-07-30 20:25:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '009_create_process_info'
down_revision: Union[str, None] = '008_create_response_audit_logs'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'process_info',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('pid', sa.Integer(), nullable=False),
        sa.Column('ppid', sa.Integer(), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('exe_path', sa.String(length=1024), nullable=True),
        sa.Column('username', sa.String(length=255), nullable=True),
        sa.Column('cpu_percent', sa.Float(), nullable=True),
        sa.Column('memory_percent', sa.Float(), nullable=True),
        sa.Column('start_time', sa.String(length=255), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('cmdline', sa.Text(), nullable=True),
        sa.Column('captured_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_index(op.f('ix_process_info_id'), 'process_info', ['id'], unique=False)
    op.create_index(op.f('ix_process_info_device_id'), 'process_info', ['device_id'], unique=False)
    op.create_index(op.f('ix_process_info_pid'), 'process_info', ['pid'], unique=False)
    op.create_index(op.f('ix_process_info_ppid'), 'process_info', ['ppid'], unique=False)
    op.create_index(op.f('ix_process_info_name'), 'process_info', ['name'], unique=False)
    op.create_index(op.f('ix_process_info_captured_at'), 'process_info', ['captured_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_process_info_captured_at'), table_name='process_info')
    op.drop_index(op.f('ix_process_info_name'), table_name='process_info')
    op.drop_index(op.f('ix_process_info_ppid'), table_name='process_info')
    op.drop_index(op.f('ix_process_info_pid'), table_name='process_info')
    op.drop_index(op.f('ix_process_info_device_id'), table_name='process_info')
    op.drop_index(op.f('ix_process_info_id'), table_name='process_info')
    op.drop_table('process_info')
