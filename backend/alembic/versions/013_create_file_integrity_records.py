"""013_create_file_integrity_records

Revision ID: 013_create_file_integrity_records
Revises: 012_create_process_audit_logs
Create Date: 2026-08-01 20:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '013_create_file_integrity_records'
down_revision: Union[str, None] = '012_create_process_audit_logs'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'file_integrity_records',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False),
        sa.Column('file_path', sa.String(length=1024), nullable=False),
        sa.Column('file_name', sa.String(length=255), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('size', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('last_modified', sa.DateTime(timezone=True), nullable=True),
        sa.Column('owner', sa.String(length=100), nullable=True),
        sa.Column('is_executable', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False)
    )
    op.create_index('ix_file_integrity_records_id', 'file_integrity_records', ['id'])
    op.create_index('ix_file_integrity_records_device_id', 'file_integrity_records', ['device_id'])
    op.create_index('ix_file_integrity_records_file_path', 'file_integrity_records', ['file_path'])
    op.create_index('ix_file_integrity_records_file_name', 'file_integrity_records', ['file_name'])
    op.create_index('ix_file_integrity_records_sha256', 'file_integrity_records', ['sha256'])
    op.create_index('ix_file_integrity_records_created_at', 'file_integrity_records', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_file_integrity_records_created_at', table_name='file_integrity_records')
    op.drop_index('ix_file_integrity_records_sha256', table_name='file_integrity_records')
    op.drop_index('ix_file_integrity_records_file_name', table_name='file_integrity_records')
    op.drop_index('ix_file_integrity_records_file_path', table_name='file_integrity_records')
    op.drop_index('ix_file_integrity_records_device_id', table_name='file_integrity_records')
    op.drop_index('ix_file_integrity_records_id', table_name='file_integrity_records')
    op.drop_table('file_integrity_records')
