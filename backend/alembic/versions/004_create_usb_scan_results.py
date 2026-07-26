"""004_create_usb_scan_results

Revision ID: 004_create_usb_scan_results
Revises: 003_create_usb_events
Create Date: 2026-07-26 16:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '004_create_usb_scan_results'
down_revision: Union[str, None] = '003_create_usb_events'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'usb_scan_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('usb_event_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('file_name', sa.String(length=255), nullable=False),
        sa.Column('full_path', sa.Text(), nullable=False),
        sa.Column('extension', sa.String(length=50), nullable=True),
        sa.Column('file_size', sa.BigInteger(), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('is_hidden', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('modified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('scanned_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.ForeignKeyConstraint(['usb_event_id'], ['usb_events.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_index(op.f('ix_usb_scan_results_id'), 'usb_scan_results', ['id'], unique=False)
    op.create_index(op.f('ix_usb_scan_results_usb_event_id'), 'usb_scan_results', ['usb_event_id'], unique=False)
    op.create_index(op.f('ix_usb_scan_results_sha256'), 'usb_scan_results', ['sha256'], unique=False)
    op.create_index(op.f('ix_usb_scan_results_scanned_at'), 'usb_scan_results', ['scanned_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_usb_scan_results_scanned_at'), table_name='usb_scan_results')
    op.drop_index(op.f('ix_usb_scan_results_sha256'), table_name='usb_scan_results')
    op.drop_index(op.f('ix_usb_scan_results_usb_event_id'), table_name='usb_scan_results')
    op.drop_index(op.f('ix_usb_scan_results_id'), table_name='usb_scan_results')
    op.drop_table('usb_scan_results')
