from datetime import datetime, timezone
from sqlalchemy import (
    String, Boolean, DateTime, ForeignKey,
    Index, CheckConstraint, Text, JSON, Integer
)
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class Connector(Base):
    """
    Configured source or target connector.
    connector_type: LDAP | SCIM | CSV | SERVICENOW | REST
    direction:      SOURCE | TARGET | BOTH
    """
    __tablename__ = "connectors"

    __table_args__ = (
        Index("ix_connector_realm", "realm_id"),
        CheckConstraint(
            "connector_type IN ('LDAP','SCIM','CSV','SERVICENOW','REST')",
            name="ck_connector_type",
        ),
        CheckConstraint(
            "direction IN ('SOURCE','TARGET','BOTH')",
            name="ck_connector_direction",
        ),
        CheckConstraint(
            "status IN ('ACTIVE','INACTIVE','ERROR')",
            name="ck_connector_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    realm_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.realm_id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    connector_type: Mapped[str] = mapped_column(String(16), nullable=False)
    direction: Mapped[str] = mapped_column(String(8), default="SOURCE", nullable=False)
    status: Mapped[str] = mapped_column(String(10), default="ACTIVE", nullable=False)

    # Configuration — encrypted at rest in production (env-var backed secrets)
    config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # Sync tracking
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_sync_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<Connector {self.name} [{self.connector_type}]>"


class WebhookSubscription(Base):
    """
    Outbound webhook: when an event fires, POST signed payload to subscriber_url.
    """
    __tablename__ = "webhook_subscriptions"

    __table_args__ = (
        Index("ix_webhook_realm", "realm_id"),
        Index("ix_webhook_active", "realm_id", "is_active"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    realm_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.realm_id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    subscriber_url: Mapped[str] = mapped_column(String(1024), nullable=False)

    # Comma-separated event types e.g. "identity.created,role.assigned"
    # Empty = subscribe to all
    event_types: Mapped[str] = mapped_column(String(1024), default="", nullable=False)

    # HMAC-SHA256 signing secret
    secret: Mapped[str] = mapped_column(String(255), nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<WebhookSubscription {self.name} -> {self.subscriber_url}>"
