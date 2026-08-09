"""008_create_response_audit_logs

Revision ID: 008_create_response_audit_logs
Revises: 007_create_response_actions
Create Date: 2026-07-29 16:28:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '008_create_response_audit_logs'
down_revision: Union[str, None] = '007_create_response_actions'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'response_audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('action_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.Column('stage', sa.String(length=50), nullable=False),
        sa.Column('actor', sa.String(length=100), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['action_id'], ['response_actions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_index(op.f('ix_response_audit_logs_id'), 'response_audit_logs', ['id'], unique=False)
    op.create_index(op.f('ix_response_audit_logs_action_id'), 'response_audit_logs', ['action_id'], unique=False)
    op.create_index(op.f('ix_response_audit_logs_timestamp'), 'response_audit_logs', ['timestamp'], unique=False)
    op.create_index(op.f('ix_response_audit_logs_stage'), 'response_audit_logs', ['stage'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_response_audit_logs_stage'), table_name='response_audit_logs')
    op.drop_index(op.f('ix_response_audit_logs_timestamp'), table_name='response_audit_logs')
    op.drop_index(op.f('ix_response_audit_logs_action_id'), table_name='response_audit_logs')
    op.drop_index(op.f('ix_response_audit_logs_id'), table_name='response_audit_logs')
    op.drop_table('response_audit_logs')
