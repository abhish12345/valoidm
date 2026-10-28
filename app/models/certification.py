from datetime import datetime, timezone
from sqlalchemy import (
    String, Boolean, DateTime, ForeignKey,
    Index, CheckConstraint, Text, Integer
)
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class CertificationCampaign(Base):
    """
    A periodic access certification campaign.
    Admins create campaigns; reviewers get a list of line items to attest.
    status: DRAFT → ACTIVE → COMPLETED | CANCELLED
    """
    __tablename__ = "certification_campaigns"

    __table_args__ = (
        Index("ix_cert_campaign_realm", "realm_id"),
        Index("ix_cert_campaign_status", "realm_id", "status"),
        CheckConstraint(
            "status IN ('DRAFT','ACTIVE','COMPLETED','CANCELLED')",
            name="ck_campaign_status",
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
    status: Mapped[str] = mapped_column(String(16), default="DRAFT", nullable=False)

    # Who created it
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)

    # Deadline for reviewers
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Counts (updated as items are decided)
    total_items: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    certified_items: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    revoked_items: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<CertificationCampaign {self.name} [{self.status}]>"


class CertificationItem(Base):
    """
    One line item in a campaign: reviewer must CERTIFY or REVOKE this assignment.
    status: PENDING → CERTIFIED | REVOKED | SKIPPED
    """
    __tablename__ = "certification_items"

    __table_args__ = (
        Index("ix_cert_item_campaign", "campaign_id"),
        Index("ix_cert_item_reviewer", "reviewer_id"),
        Index("ix_cert_item_identity", "identity_id"),
        Index("ix_cert_item_status", "campaign_id", "status"),
        CheckConstraint(
            "status IN ('PENDING','CERTIFIED','REVOKED','SKIPPED')",
            name="ck_item_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("certification_campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    realm_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # What is being certified
    identity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identities.id", ondelete="CASCADE"), nullable=False
    )
    role_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )
    assignment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("role_assignments.id", ondelete="CASCADE"), nullable=False
    )

    # Who reviews it
    reviewer_id: Mapped[str] = mapped_column(String(36), nullable=False)

    # Decision
    status: Mapped[str] = mapped_column(String(16), default="PENDING", nullable=False)
    decision_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(36), nullable=True)

    # Agent pre-screening result
    agent_recommendation: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # CERTIFY | REVOKE | REVIEW
    agent_risk_score: Mapped[float | None] = mapped_column(nullable=True)
    agent_reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<CertificationItem {self.identity_id}/{self.role_id} [{self.status}]>"
