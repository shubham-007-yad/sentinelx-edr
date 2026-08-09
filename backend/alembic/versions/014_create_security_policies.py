"""014_create_security_policies

Revision ID: 014_create_security_policies
Revises: 013_create_file_integrity_records
Create Date: 2026-08-05 10:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '014_create_security_policies'
down_revision: Union[str, None] = '013_create_file_integrity_records'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'security_policies',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('policy_name', sa.String(length=255), nullable=False),
        sa.Column('category', sa.Enum('USB', 'PROCESS', 'NETWORK', 'FIM', 'RANSOMWARE', name='policycategory'), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('priority', sa.Integer(), nullable=False, server_default='10'),
        sa.Column('configuration', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('created_by', sa.String(length=255), nullable=False, server_default='Admin'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False)
    )
    op.create_index('ix_security_policies_id', 'security_policies', ['id'])
    op.create_index('ix_security_policies_policy_name', 'security_policies', ['policy_name'])
    op.create_index('ix_security_policies_category', 'security_policies', ['category'])
    op.create_index('ix_security_policies_enabled', 'security_policies', ['enabled'])
    op.create_index('ix_security_policies_created_at', 'security_policies', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_security_policies_created_at', table_name='security_policies')
    op.drop_index('ix_security_policies_enabled', table_name='security_policies')
    op.drop_index('ix_security_policies_category', table_name='security_policies')
    op.drop_index('ix_security_policies_policy_name', table_name='security_policies')
    op.drop_index('ix_security_policies_id', table_name='security_policies')
    op.drop_table('security_policies')
    op.execute('DROP TYPE IF EXISTS policycategory;')
