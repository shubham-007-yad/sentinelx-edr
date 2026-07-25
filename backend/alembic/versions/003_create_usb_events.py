"""003_create_usb_events

Revision ID: 003_create_usb_events
Revises: 002_create_devices
Create Date: 2026-07-25 21:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '003_create_usb_events'
down_revision: Union[str, None] = '002_create_devices'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    usbeventtype_enum = sa.Enum('INSERT', 'REMOVE', name='usbeventtype')

    op.create_table(
        'usb_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('event_type', usbeventtype_enum, nullable=False),
        sa.Column('drive_letter', sa.String(length=50), nullable=True),
        sa.Column('volume_label', sa.String(length=255), nullable=True),
        sa.Column('filesystem', sa.String(length=50), nullable=True),
        sa.Column('total_size', sa.BigInteger(), nullable=True),
        sa.Column('free_space', sa.BigInteger(), nullable=True),
        sa.Column('serial_number', sa.String(length=255), nullable=True),
        sa.Column('detected_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_index(op.f('ix_usb_events_id'), 'usb_events', ['id'], unique=False)
    op.create_index(op.f('ix_usb_events_device_id'), 'usb_events', ['device_id'], unique=False)
    op.create_index(op.f('ix_usb_events_detected_at'), 'usb_events', ['detected_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_usb_events_detected_at'), table_name='usb_events')
    op.drop_index(op.f('ix_usb_events_device_id'), table_name='usb_events')
    op.drop_index(op.f('ix_usb_events_id'), table_name='usb_events')
    op.drop_table('usb_events')

    usbeventtype_enum = sa.Enum('INSERT', 'REMOVE', name='usbeventtype')
    usbeventtype_enum.drop(op.get_bind(), checkfirst=True)
