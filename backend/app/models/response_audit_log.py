import uuid
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class ResponseAuditLog(Base):
    __tablename__ = "response_audit_logs"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        nullable=False
    )
    action_id = Column(
        UUID(as_uuid=True),
        ForeignKey("response_actions.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )
    stage = Column(
        String(50),
        nullable=False,
        index=True
    )
    actor = Column(
        String(100),
        nullable=False
    )
    message = Column(
        Text,
        nullable=False
    )
    details = Column(
        JSON,
        nullable=True
    )

    action = relationship("ResponseAction", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<ResponseAuditLog id={self.id} stage='{self.stage}' message='{self.message}'>"
