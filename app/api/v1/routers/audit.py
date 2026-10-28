import math
from datetime import datetime
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_

from app.core.database import get_db
from app.core.security import get_current_user, get_current_admin
from app.models.audit import AuditLog
from app.schemas.audit import AuditLogResponse, AuditLogListResponse

router = APIRouter(prefix="/audit", tags=["audit"])


# ── GET /api/v1/audit/events ──────────────────────────────────────────────────

@router.get("/events", response_model=AuditLogListResponse)
async def query_events(
    action: str | None = Query(None, description="Filter by action e.g. ROLE_ASSIGNED"),
    actor_id: str | None = Query(None),
    target_id: str | None = Query(None),
    resource_type: str | None = Query(None),
    outcome: str | None = Query(None, description="SUCCESS | FAILURE | DENIED"),
    search: str | None = Query(None, description="Free text in action or detail"),
    from_date: datetime | None = Query(None),
    to_date: datetime | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AuditLogListResponse:
    realm_id = current_user["realm_id"]
    q = select(AuditLog).where(AuditLog.realm_id == realm_id)

    if action:
        q = q.where(AuditLog.action.ilike(f"%{action}%"))
    if actor_id:
        q = q.where(AuditLog.actor_id == actor_id)
    if target_id:
        q = q.where(AuditLog.target_id == target_id)
    if resource_type:
        q = q.where(AuditLog.resource_type == resource_type)
    if outcome:
        q = q.where(AuditLog.outcome == outcome.upper())
    if search:
        term = f"%{search}%"
        q = q.where(
            or_(
                AuditLog.action.ilike(term),
                AuditLog.detail.ilike(term),
                AuditLog.actor_username.ilike(term),
                AuditLog.target_name.ilike(term),
            )
        )
    if from_date:
        q = q.where(AuditLog.created_at >= from_date)
    if to_date:
        q = q.where(AuditLog.created_at <= to_date)

    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()

    rows = (await db.execute(
        q.order_by(AuditLog.created_at.desc())
        .offset((page - 1) * page_size).limit(page_size)
    )).scalars().all()

    return AuditLogListResponse(
        items=[AuditLogResponse.model_validate(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


# ── GET /api/v1/audit/events/{id} ────────────────────────────────────────────

@router.get("/events/{log_id}", response_model=AuditLogResponse)
async def get_event(
    log_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AuditLogResponse:
    from fastapi import HTTPException
    log = await db.get(AuditLog, log_id)
    if not log or log.realm_id != current_user["realm_id"]:
        raise HTTPException(status_code=404, detail="Audit log entry not found")
    return AuditLogResponse.model_validate(log)


# ── GET /api/v1/audit/summary ─────────────────────────────────────────────────

@router.get("/summary")
async def audit_summary(
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """High-level counts: total events, by action category, by outcome."""
    realm_id = current_user["realm_id"]

    total = (await db.execute(
        select(func.count(AuditLog.id)).where(AuditLog.realm_id == realm_id)
    )).scalar_one()

    # Counts per outcome
    outcomes = (await db.execute(
        select(AuditLog.outcome, func.count(AuditLog.id))
        .where(AuditLog.realm_id == realm_id)
        .group_by(AuditLog.outcome)
    )).all()

    # Top 10 actions
    top_actions = (await db.execute(
        select(AuditLog.action, func.count(AuditLog.id).label("cnt"))
        .where(AuditLog.realm_id == realm_id)
        .group_by(AuditLog.action)
        .order_by(func.count(AuditLog.id).desc())
        .limit(10)
    )).all()

    # Recent failures
    recent_failures = (await db.execute(
        select(AuditLog).where(
            AuditLog.realm_id == realm_id,
            AuditLog.outcome == "FAILURE",
        ).order_by(AuditLog.created_at.desc()).limit(5)
    )).scalars().all()

    return {
        "total_events": total,
        "by_outcome": {row[0]: row[1] for row in outcomes},
        "top_actions": [{"action": row[0], "count": row[1]} for row in top_actions],
        "recent_failures": [
            {
                "id": e.id,
                "action": e.action,
                "actor": e.actor_username,
                "target": e.target_name,
                "created_at": e.created_at.isoformat(),
            }
            for e in recent_failures
        ],
    }


# ── GET /api/v1/audit/identity/{id} ──────────────────────────────────────────

@router.get("/identity/{identity_id}", response_model=AuditLogListResponse)
async def identity_audit_trail(
    identity_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AuditLogListResponse:
    """All audit events where this identity was the actor or the target."""
    realm_id = current_user["realm_id"]
    q = select(AuditLog).where(
        AuditLog.realm_id == realm_id,
        or_(
            AuditLog.actor_id == identity_id,
            AuditLog.target_id == identity_id,
        ),
    )
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows = (await db.execute(
        q.order_by(AuditLog.created_at.desc())
        .offset((page - 1) * page_size).limit(page_size)
    )).scalars().all()
    return AuditLogListResponse(
        items=[AuditLogResponse.model_validate(r) for r in rows],
        total=total, page=page, page_size=page_size,
    )
