"""011_add_process_response_actions

Revision ID: 011_add_process_response_actions
Revises: 010_add_process_threat_types
Create Date: 2026-07-30 20:38:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '011_add_process_response_actions'
down_revision: Union[str, None] = '010_add_process_threat_types'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add new values to responseactiontype PostgreSQL enum type
    conn = op.get_bind()
    new_values = ['TERMINATE_PROCESS', 'SUSPEND_PROCESS', 'MARK_TRUSTED', 'ADD_ALLOWLIST']
    for val in new_values:
        conn.execute(sa.text(f"ALTER TYPE responseactiontype ADD VALUE IF NOT EXISTS '{val}';"))


def downgrade() -> None:
    pass
