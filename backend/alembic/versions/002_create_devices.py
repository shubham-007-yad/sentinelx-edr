"""002_create_devices

Revision ID: 002_create_devices
Revises: 001_create_users
Create Date: 2026-07-24 07:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '002_create_devices'
down_revision: Union[str, None] = '001_create_users'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    ostype_enum = sa.Enum('WINDOWS', 'LINUX', 'MACOS', 'OTHER', name='ostype')
    devicestatus_enum = sa.Enum('ONLINE', 'OFFLINE', 'ISOLATED', 'UNREGISTERED', name='devicestatus')

    op.create_table(
        'devices',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('mac_address', sa.String(length=17), nullable=True),
        sa.Column('os_type', ostype_enum, server_default='LINUX', nullable=False),
        sa.Column('os_version', sa.String(length=100), nullable=True),
        sa.Column('agent_version', sa.String(length=50), nullable=True),
        sa.Column('status', devicestatus_enum, server_default='OFFLINE', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    
    op.create_index(op.f('ix_devices_id'), 'devices', ['id'], unique=False)
    op.create_index(op.f('ix_devices_hostname'), 'devices', ['hostname'], unique=False)
    op.create_index(op.f('ix_devices_user_id'), 'devices', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_devices_user_id'), table_name='devices')
    op.drop_index(op.f('ix_devices_hostname'), table_name='devices')
    op.drop_index(op.f('ix_devices_id'), table_name='devices')
    op.drop_table('devices')
    
    devicestatus_enum = sa.Enum('ONLINE', 'OFFLINE', 'ISOLATED', 'UNREGISTERED', name='devicestatus')
    devicestatus_enum.drop(op.get_bind(), checkfirst=True)

    ostype_enum = sa.Enum('WINDOWS', 'LINUX', 'MACOS', 'OTHER', name='ostype')
    ostype_enum.drop(op.get_bind(), checkfirst=True)
