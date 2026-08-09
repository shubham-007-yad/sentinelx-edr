import uuid
import enum
from sqlalchemy import Column, String, Integer, BigInteger, DateTime, ForeignKey, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class NetworkProtocol(str, enum.Enum):
    TCP = "TCP"
    UDP = "UDP"


class NetworkConnectionState(str, enum.Enum):
    ESTABLISHED = "ESTABLISHED"
    LISTEN = "LISTEN"
    SYN_SENT = "SYN_SENT"
    SYN_RECV = "SYN_RECV"
    FIN_WAIT1 = "FIN_WAIT1"
    FIN_WAIT2 = "FIN_WAIT2"
    TIME_WAIT = "TIME_WAIT"
    CLOSE = "CLOSE"
    CLOSE_WAIT = "CLOSE_WAIT"
    LAST_ACK = "LAST_ACK"
    CLOSING = "CLOSING"
    NONE = "NONE"


class NetworkConnection(Base):
    __tablename__ = "network_connections"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        nullable=False
    )
    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    process_id = Column(
        UUID(as_uuid=True),
        ForeignKey("process_info.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    threat_id = Column(
        UUID(as_uuid=True),
        ForeignKey("threats.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    alert_id = Column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    pid = Column(Integer, nullable=True, index=True)
    process_name = Column(String(255), nullable=True, index=True)
    executable_path = Column(String(1024), nullable=True)
    local_ip = Column(String(100), nullable=True, index=True)
    local_port = Column(Integer, nullable=True, index=True)
    remote_ip = Column(String(100), nullable=True, index=True)
    remote_port = Column(Integer, nullable=True, index=True)
    protocol = Column(
        String(50),
        default="TCP",
        nullable=False,
        index=True
    )
    state = Column(
        String(50),
        default="ESTABLISHED",
        nullable=True,
        index=True
    )
    bytes_sent = Column(BigInteger, default=0, nullable=False)
    bytes_received = Column(BigInteger, default=0, nullable=False)

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

    device = relationship("Device", back_populates="network_connections")
    process = relationship("ProcessInfo", foreign_keys=[process_id])
    threat = relationship("Threat", foreign_keys=[threat_id])
    alert = relationship("Alert", foreign_keys=[alert_id])

    def __repr__(self) -> str:
        return (
            f"<NetworkConnection id={self.id} device_id={self.device_id} pid={self.pid} "
            f"process='{self.process_name}' local={self.local_ip}:{self.local_port} "
            f"remote={self.remote_ip}:{self.remote_port} protocol={self.protocol} state={self.state}>"
        )
