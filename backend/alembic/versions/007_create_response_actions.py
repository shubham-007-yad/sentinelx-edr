"""007_create_response_actions

Revision ID: 007_create_response_actions
Revises: 006_create_alerts
Create Date: 2026-07-29 16:18:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '007_create_response_actions'
down_revision: Union[str, None] = '006_create_alerts'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Define PostgreSQL Enum types
    responseactiontype_enum = postgresql.ENUM(
        'QUARANTINE', 'DELETE', 'ISOLATE', 'IGNORE',
        name='responseactiontype', create_type=False
    )
    responseactionstatus_enum = postgresql.ENUM(
        'PENDING', 'RUNNING', 'SUCCESS', 'FAILED',
        name='responseactionstatus', create_type=False
    )

    # Create Enum types in DB if they do not exist
    responseactiontype_enum.create(op.get_bind(), checkfirst=True)
    responseactionstatus_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        'response_actions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('alert_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('action_type', responseactiontype_enum, nullable=False),
        sa.Column('status', responseactionstatus_enum, server_default='PENDING', nullable=False),
        sa.Column('initiated_by', sa.String(length=100), server_default='AUTOMATIC', nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('result', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_index(op.f('ix_response_actions_id'), 'response_actions', ['id'], unique=False)
    op.create_index(op.f('ix_response_actions_alert_id'), 'response_actions', ['alert_id'], unique=False)
    op.create_index(op.f('ix_response_actions_device_id'), 'response_actions', ['device_id'], unique=False)
    op.create_index(op.f('ix_response_actions_action_type'), 'response_actions', ['action_type'], unique=False)
    op.create_index(op.f('ix_response_actions_status'), 'response_actions', ['status'], unique=False)
    op.create_index(op.f('ix_response_actions_started_at'), 'response_actions', ['started_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_response_actions_started_at'), table_name='response_actions')
    op.drop_index(op.f('ix_response_actions_status'), table_name='response_actions')
    op.drop_index(op.f('ix_response_actions_action_type'), table_name='response_actions')
    op.drop_index(op.f('ix_response_actions_device_id'), table_name='response_actions')
    op.drop_index(op.f('ix_response_actions_alert_id'), table_name='response_actions')
    op.drop_index(op.f('ix_response_actions_id'), table_name='response_actions')
    op.drop_table('response_actions')

    postgresql.ENUM(name='responseactionstatus').drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name='responseactiontype').drop(op.get_bind(), checkfirst=True)
