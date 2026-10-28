from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class OrgUnit(Base):
    __tablename__ = "org_units"

    __table_args__ = (
        Index("ix_org_units_realm", "realm_id"),
        Index("ix_org_units_parent", "parent_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    realm_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.realm_id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)
    parent_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("org_units.id", ondelete="SET NULL"),
        nullable=True,
    )
    manager_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
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
        return f"<OrgUnit {self.name}>"
