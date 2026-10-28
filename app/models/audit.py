from datetime import datetime, timezone
from sqlalchemy import String, DateTime, JSON, Text, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class AuditLog(Base):
    """
    Append-only audit log. Never update or delete rows.
    Application enforces this; a DB trigger can optionally reinforce it.
    """
    __tablename__ = "audit_logs"

    __table_args__ = (
        Index("ix_audit_realm_created", "realm_id", "created_at"),
        Index("ix_audit_actor", "actor_id"),
        Index("ix_audit_target", "target_id"),
        Index("ix_audit_action", "action"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    realm_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Who did it
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # What happened
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    target_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Result
    outcome: Mapped[str] = mapped_column(
        String(16), default="SUCCESS", nullable=False
    )  # SUCCESS | FAILURE | DENIED
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Before/after snapshot for attribute-level audit
    before_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    after_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Correlation
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    agent_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    agent_reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<AuditLog {self.action} by {self.actor_username}>"
