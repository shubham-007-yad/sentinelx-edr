import uuid
import enum
from sqlalchemy import Column, String, Boolean, Integer, DateTime, Enum, JSON
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
from app.db.database import Base


class PolicyCategory(str, enum.Enum):
    USB = "USB"
    PROCESS = "PROCESS"
    NETWORK = "NETWORK"
    FIM = "FIM"
    RANSOMWARE = "RANSOMWARE"


class SecurityPolicy(Base):
    __tablename__ = "security_policies"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        nullable=False
    )
    policy_name = Column(String(255), nullable=False, index=True)
    category = Column(
        Enum(PolicyCategory, native_enum=True, name="policycategory"),
        nullable=False,
        index=True
    )
    version = Column(Integer, default=1, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    priority = Column(Integer, default=10, nullable=False)
    configuration = Column(JSON().with_variant(JSONB, "postgresql"), default={}, nullable=False)
    created_by = Column(String(255), default="Admin", nullable=False)


    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    def __repr__(self) -> str:
        return f"<SecurityPolicy id={self.id} name='{self.policy_name}' category='{self.category}' version={self.version} enabled={self.enabled}>"
