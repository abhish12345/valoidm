from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey, Index, Text, JSON, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class AccessRequest(Base):
    """
    Access request: a user asks for a role.
    Flows through: PENDING → APPROVED | REJECTED | CANCELLED
    On APPROVED → provisioning fulfills it → RoleAssignment created.
    """
    __tablename__ = "access_requests"

    __table_args__ = (
        Index("ix_ar_realm_status", "realm_id", "status"),
        Index("ix_ar_requester", "requester_id"),
        Index("ix_ar_approver", "approver_id"),
        Index("ix_ar_role", "role_id"),
        CheckConstraint(
            "status IN ('PENDING','APPROVED','REJECTED','CANCELLED','EXPIRED')",
            name="ck_ar_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    realm_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Who is requesting and what
    requester_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identities.id", ondelete="CASCADE"), nullable=False
    )
    target_identity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identities.id", ondelete="CASCADE"), nullable=False
    )  # usually same as requester, or a manager requesting on behalf
    role_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )

    # Why
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    business_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Access duration (None = permanent)
    access_duration_days: Mapped[int | None] = mapped_column(nullable=True)

    # Workflow state
    status: Mapped[str] = mapped_column(String(16), default="PENDING", nullable=False)
    approver_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approver_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Risk scoring (set by Approval Risk Agent)
    risk_score: Mapped[float | None] = mapped_column(nullable=True)
    risk_factors: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    agent_recommendation: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # APPROVE | ESCALATE | DENY

    # SoD check result
    sod_conflict: Mapped[bool] = mapped_column(default=False, nullable=False)
    sod_detail: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Resulting assignment (set after approval + provisioning)
    assignment_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    def __repr__(self) -> str:
        return f"<AccessRequest {self.requester_id} -> {self.role_id} [{self.status}]>"
