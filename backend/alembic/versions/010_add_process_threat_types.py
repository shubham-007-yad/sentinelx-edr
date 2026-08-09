"""010_add_process_threat_types

Revision ID: 010_add_process_threat_types
Revises: 009_create_process_info
Create Date: 2026-07-30 20:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '010_add_process_threat_types'
down_revision: Union[str, None] = '009_create_process_info'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add new values to threattype PostgreSQL enum type
    conn = op.get_bind()
    new_values = ['SUSPICIOUS_POWERSHELL', 'SUSPICIOUS_CMD', 'LOLBIN_ABUSE', 'SUSPICIOUS_PROCESS_BEHAVIOR']
    for val in new_values:
        conn.execute(sa.text(f"ALTER TYPE threattype ADD VALUE IF NOT EXISTS '{val}';"))

    # Make scan_result_id nullable for process-level threats
    op.alter_column('threats', 'scan_result_id', nullable=True)


def downgrade() -> None:
    pass
