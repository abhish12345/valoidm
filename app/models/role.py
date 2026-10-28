from datetime import datetime, timezone
from sqlalchemy import (
    String, Boolean, DateTime, ForeignKey,
    Index, CheckConstraint, Text
)
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class Role(Base):
    """Business or technical role definition."""
    __tablename__ = "roles"

    __table_args__ = (
        Index("ix_roles_realm", "realm_id"),
        Index("ix_roles_realm_name", "realm_id", "name", unique=True),
        CheckConstraint(
            "role_type IN ('BUSINESS','TECHNICAL','SYSTEM')",
            name="ck_role_type",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    realm_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.realm_id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    role_type: Mapped[str] = mapped_column(
        String(16), default="BUSINESS", nullable=False
    )  # BUSINESS | TECHNICAL | SYSTEM
    parent_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("roles.id", ondelete="SET NULL"),
        nullable=True,
    )
    owner_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_requestable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
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
        return f"<Role {self.name}@{self.realm_id}>"


class RoleConflict(Base):
    """
    SoD (Segregation of Duties) toxic role pairs.
    If a user holds role_a_id they cannot also hold role_b_id.
    Stored as ordered pair (role_a_id < role_b_id) to avoid duplicates.
    """
    __tablename__ = "role_conflicts"

    __table_args__ = (
        Index("ix_role_conflicts_realm", "realm_id"),
        Index("ix_role_conflicts_pair", "role_a_id", "role_b_id", unique=True),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    realm_id: Mapped[str] = mapped_column(String(64), nullable=False)
    role_a_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )
    role_b_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<RoleConflict {self.role_a_id} x {self.role_b_id}>"


class RoleAssignment(Base):
    """
    Assigned role on an identity — with optional validity window.
    status: ACTIVE | EXPIRED | REVOKED
    """
    __tablename__ = "role_assignments"

    __table_args__ = (
        Index("ix_ra_identity", "identity_id"),
        Index("ix_ra_role", "role_id"),
        Index("ix_ra_realm_status", "realm_id", "status"),
        Index("ix_ra_identity_role", "identity_id", "role_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    realm_id: Mapped[str] = mapped_column(String(64), nullable=False)
    identity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identities.id", ondelete="CASCADE"), nullable=False
    )
    role_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(16), default="ACTIVE", nullable=False
    )  # ACTIVE | EXPIRED | REVOKED
    assigned_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)

    def __repr__(self) -> str:
        return f"<RoleAssignment identity={self.identity_id} role={self.role_id}>"
