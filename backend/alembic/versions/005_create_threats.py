"""005_create_threats

Revision ID: 005_create_threats
Revises: 004_create_usb_scan_results
Create Date: 2026-07-27 12:50:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '005_create_threats'
down_revision: Union[str, None] = '004_create_usb_scan_results'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Define PostgreSQL Enum types
    threattype_enum = postgresql.ENUM(
        'KNOWN_MALWARE', 'DOUBLE_EXTENSION', 'HIDDEN_EXECUTABLE',
        'AUTORUN_SCRIPT', 'SUSPICIOUS_EXTENSION', 'ANOMALOUS_FILE',
        name='threattype', create_type=False
    )
    threatseverity_enum = postgresql.ENUM(
        'LOW', 'MEDIUM', 'HIGH', 'CRITICAL',
        name='threatseverity', create_type=False
    )
    threatstatus_enum = postgresql.ENUM(
        'NEW', 'ACKNOWLEDGED', 'RESOLVED',
        name='threatstatus', create_type=False
    )

    # Create Enum types in DB if they do not exist
    threattype_enum.create(op.get_bind(), checkfirst=True)
    threatseverity_enum.create(op.get_bind(), checkfirst=True)
    threatstatus_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        'threats',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_result_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('threat_type', threattype_enum, nullable=False),
        sa.Column('severity', threatseverity_enum, nullable=False),
        sa.Column('rule_name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('status', threatstatus_enum, server_default='NEW', nullable=False),
        sa.Column('detected_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False),
        sa.ForeignKeyConstraint(['scan_result_id'], ['usb_scan_results.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_index(op.f('ix_threats_id'), 'threats', ['id'], unique=False)
    op.create_index(op.f('ix_threats_scan_result_id'), 'threats', ['scan_result_id'], unique=False)
    op.create_index(op.f('ix_threats_threat_type'), 'threats', ['threat_type'], unique=False)
    op.create_index(op.f('ix_threats_severity'), 'threats', ['severity'], unique=False)
    op.create_index(op.f('ix_threats_status'), 'threats', ['status'], unique=False)
    op.create_index(op.f('ix_threats_detected_at'), 'threats', ['detected_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_threats_detected_at'), table_name='threats')
    op.drop_index(op.f('ix_threats_status'), table_name='threats')
    op.drop_index(op.f('ix_threats_severity'), table_name='threats')
    op.drop_index(op.f('ix_threats_threat_type'), table_name='threats')
    op.drop_index(op.f('ix_threats_scan_result_id'), table_name='threats')
    op.drop_index(op.f('ix_threats_id'), table_name='threats')
    op.drop_table('threats')

    postgresql.ENUM(name='threatstatus').drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name='threatseverity').drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name='threattype').drop(op.get_bind(), checkfirst=True)
