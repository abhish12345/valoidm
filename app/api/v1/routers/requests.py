import uuid
import math
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.security import get_current_user, get_current_admin
from app.core.audit import write_audit
from app.models.role import Role, RoleConflict, RoleAssignment
from app.models.workflow import AccessRequest
from app.schemas.workflow import (
    AccessRequestCreate, AccessRequestDecision,
    AccessRequestResponse, AccessRequestListResponse,
)
from app.api.v1.routers.roles import _sod_check

router = APIRouter(prefix="/requests", tags=["access-requests"])


def _ip(r: Request) -> str:
    fwd = r.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (r.client.host if r.client else "unknown")


# ── POST /api/v1/requests ─────────────────────────────────────────────────────

@router.post("", response_model=AccessRequestResponse, status_code=201)
async def submit_request(
    body: AccessRequestCreate,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AccessRequestResponse:
    realm_id = current_user["realm_id"]
    requester_id = current_user["sub"]
    target_id = body.target_identity_id or requester_id

    # Validate role exists and is requestable
    role = await db.get(Role, body.role_id)
    if not role or role.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Role not found")
    if not role.is_requestable:
        raise HTTPException(status_code=403, detail="This role is not requestable")

    # Check for existing pending or active
    existing_pending = (await db.execute(
        select(AccessRequest).where(
            AccessRequest.realm_id == realm_id,
            AccessRequest.target_identity_id == target_id,
            AccessRequest.role_id == body.role_id,
            AccessRequest.status == "PENDING",
        )
    )).scalar_one_or_none()
    if existing_pending:
        raise HTTPException(status_code=409, detail="A pending request for this role already exists")

    existing_active = (await db.execute(
        select(RoleAssignment).where(
            RoleAssignment.realm_id == realm_id,
            RoleAssignment.identity_id == target_id,
            RoleAssignment.role_id == body.role_id,
            RoleAssignment.status == "ACTIVE",
        )
    )).scalar_one_or_none()
    if existing_active:
        raise HTTPException(status_code=409, detail="Identity already has this role assigned")

    # SoD pre-check (advisory — stored on request, not blocking at submit time)
    sod = await _sod_check(db, realm_id, target_id, body.role_id)

    # Expiry for the request itself (7 days to approve/reject)
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    req = AccessRequest(
        id=str(uuid.uuid4()),
        realm_id=realm_id,
        requester_id=requester_id,
        target_identity_id=target_id,
        role_id=body.role_id,
        justification=body.justification,
        business_reason=body.business_reason,
        access_duration_days=body.access_duration_days,
        status="PENDING",
        sod_conflict=sod.has_conflict,
        sod_detail=sod.detail if sod.has_conflict else None,
        expires_at=expires_at,
    )
    db.add(req)

    await write_audit(
        db, realm_id=realm_id, action="ACCESS_REQUEST_SUBMITTED",
        actor_id=requester_id, actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="access_request",
        target_id=req.id,
        after_state={
            "role_id": body.role_id, "role_name": role.name,
            "sod_conflict": sod.has_conflict,
        },
    )
    await db.commit()
    await db.refresh(req)
    return AccessRequestResponse.model_validate(req)


# ── GET /api/v1/requests ──────────────────────────────────────────────────────

@router.get("", response_model=AccessRequestListResponse)
async def list_requests(
    status_filter: str | None = Query(None, alias="status"),
    mine_only: bool = Query(False),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AccessRequestListResponse:
    realm_id = current_user["realm_id"]
    q = select(AccessRequest).where(AccessRequest.realm_id == realm_id)

    if status_filter:
        q = q.where(AccessRequest.status == status_filter.upper())
    if mine_only:
        q = q.where(AccessRequest.requester_id == current_user["sub"])

    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    pending_count = (await db.execute(
        select(func.count(AccessRequest.id)).where(
            AccessRequest.realm_id == realm_id,
            AccessRequest.status == "PENDING",
        )
    )).scalar_one()

    rows = (await db.execute(
        q.order_by(AccessRequest.created_at.desc())
        .offset((page - 1) * page_size).limit(page_size)
    )).scalars().all()

    return AccessRequestListResponse(
        items=[AccessRequestResponse.model_validate(r) for r in rows],
        total=total,
        pending_count=pending_count,
    )


# ── GET /api/v1/requests/{id} ─────────────────────────────────────────────────

@router.get("/{request_id}", response_model=AccessRequestResponse)
async def get_request(
    request_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AccessRequestResponse:
    req = await db.get(AccessRequest, request_id)
    if not req or req.realm_id != current_user["realm_id"]:
        raise HTTPException(status_code=404, detail="Request not found")
    return AccessRequestResponse.model_validate(req)


# ── POST /api/v1/requests/{id}/decide ────────────────────────────────────────

@router.post("/{request_id}/decide", response_model=AccessRequestResponse)
async def decide_request(
    request_id: str,
    body: AccessRequestDecision,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> AccessRequestResponse:
    """Approve or reject an access request. On approval, creates the role assignment."""
    realm_id = current_user["realm_id"]
    req = await db.get(AccessRequest, request_id)
    if not req or req.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Request not found")
    if req.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"Request is already {req.status}")

    req.status = body.decision
    req.approver_id = current_user["sub"]
    req.approver_comment = body.comment
    req.decided_at = datetime.now(timezone.utc)

    assignment_id = None
    if body.decision == "APPROVED":
        # Re-run SoD check at decision time
        sod = await _sod_check(db, realm_id, req.target_identity_id, req.role_id)
        if sod.has_conflict:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot approve — SoD conflict detected: {sod.detail}",
            )

        # Calculate validity window
        valid_until = None
        if req.access_duration_days:
            valid_until = datetime.now(timezone.utc) + timedelta(days=req.access_duration_days)

        assignment = RoleAssignment(
            id=str(uuid.uuid4()),
            realm_id=realm_id,
            identity_id=req.target_identity_id,
            role_id=req.role_id,
            status="ACTIVE",
            assigned_by=current_user["sub"],
            valid_until=valid_until,
        )
        db.add(assignment)
        await db.flush()
        req.assignment_id = assignment.id
        assignment_id = assignment.id

    await write_audit(
        db, realm_id=realm_id,
        action=f"ACCESS_REQUEST_{body.decision}",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="access_request",
        target_id=request_id,
        after_state={
            "decision": body.decision,
            "comment": body.comment,
            "assignment_id": assignment_id,
        },
    )
    await db.commit()
    await db.refresh(req)
    return AccessRequestResponse.model_validate(req)


# ── POST /api/v1/requests/{id}/cancel ────────────────────────────────────────

@router.post("/{request_id}/cancel", response_model=AccessRequestResponse)
async def cancel_request(
    request_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AccessRequestResponse:
    realm_id = current_user["realm_id"]
    req = await db.get(AccessRequest, request_id)
    if not req or req.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Request not found")
    if req.status != "PENDING":
        raise HTTPException(status_code=400, detail="Only PENDING requests can be cancelled")
    # Only requester or admin can cancel
    if req.requester_id != current_user["sub"] and not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="You can only cancel your own requests")

    req.status = "CANCELLED"
    req.decided_at = datetime.now(timezone.utc)
    await write_audit(
        db, realm_id=realm_id, action="ACCESS_REQUEST_CANCELLED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="access_request", target_id=request_id,
    )
    await db.commit()
    await db.refresh(req)
    return AccessRequestResponse.model_validate(req)
