import uuid
import enum
from sqlalchemy import Column, String, Text, DateTime, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class CaseSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CaseStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    CLOSED = "CLOSED"


class CaseNote(Base):
    __tablename__ = "case_notes"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        nullable=False
    )
    case_id = Column(
        UUID(as_uuid=True),
        ForeignKey("investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    author = Column(String(255), nullable=False)
    note_text = Column(Text, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    case = relationship("InvestigationCase", back_populates="notes")


class CaseEvidence(Base):
    __tablename__ = "case_evidence"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        nullable=False
    )
    case_id = Column(
        UUID(as_uuid=True),
        ForeignKey("investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    evidence_type = Column(String(100), nullable=False, default="IOC_OR_ARTIFACT")
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    file_path_or_hash = Column(String(500), nullable=True)
    added_by = Column(String(255), nullable=False, default="Analyst")
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    case = relationship("InvestigationCase", back_populates="evidence_items")


class InvestigationCase(Base):
    __tablename__ = "investigation_cases"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        nullable=False
    )
    title = Column(String(255), nullable=False)
    severity = Column(
        Enum(CaseSeverity, native_enum=True, name="caseseverity"),
        default=CaseSeverity.MEDIUM,
        nullable=False,
        index=True
    )
    status = Column(
        Enum(CaseStatus, native_enum=True, name="casestatus"),
        default=CaseStatus.OPEN,
        nullable=False,
        index=True
    )
    assigned_to = Column(String(255), nullable=True, index=True)
    correlation_id = Column(String(255), nullable=True, index=True)
    summary = Column(Text, nullable=True)
    linked_alert_ids = Column(JSONB, default=[], nullable=False)
    linked_telemetry_ids = Column(JSONB, default=[], nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )
    closed_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    notes = relationship("CaseNote", back_populates="case", cascade="all, delete-orphan")
    evidence_items = relationship("CaseEvidence", back_populates="case", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<InvestigationCase id={self.id} title='{self.title}' severity='{self.severity}' status='{self.status}'>"
