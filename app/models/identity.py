from datetime import datetime, timezone
from sqlalchemy import (
    String, Boolean, DateTime, JSON,
    ForeignKey, Index, CheckConstraint
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Identity(Base):
    __tablename__ = "identities"

    __table_args__ = (
        Index("ix_identities_realm_username", "realm_id", "username", unique=True),
        Index("ix_identities_realm_email", "realm_id", "email"),
        Index("ix_identities_realm_status", "realm_id", "status"),
        CheckConstraint(
            "identity_type IN ('HUMAN','SERVICE','BOT','CONTRACTOR')",
            name="ck_identity_type",
        ),
        CheckConstraint(
            "status IN ('ACTIVE','INACTIVE','LOCKED','SUSPENDED','PRE_HIRE',"
            "'ON_LEAVE','TERMINATED','ARCHIVED')",
            name="ck_identity_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    realm_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.realm_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    employee_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    first_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_name: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # HUMAN | SERVICE | BOT | CONTRACTOR
    identity_type: Mapped[str] = mapped_column(
        String(32), default="HUMAN", nullable=False
    )
    # ACTIVE | INACTIVE | LOCKED | SUSPENDED | PRE_HIRE | ON_LEAVE | TERMINATED | ARCHIVED
    status: Mapped[str] = mapped_column(
        String(32), default="ACTIVE", nullable=False
    )

    # Auth
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Flags
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    # Dates
    start_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    termination_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
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

    # Extra attributes (EAV-lite, stored as JSON)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    def __repr__(self) -> str:
        return f"<Identity {self.username}@{self.realm_id}>"
