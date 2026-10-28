import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import hash_password, get_current_admin
from app.core.audit import write_audit
from app.models.identity import Identity
from app.schemas.identity import (
    JoinRequest, MoveRequest, LeaveRequest, TerminateRequest,
    IdentityResponse,
)

router = APIRouter(prefix="/lifecycle", tags=["lifecycle"])


def _ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")


# ── POST /api/v1/lifecycle/join ───────────────────────────────────────────────

@router.post("/join", response_model=IdentityResponse, status_code=201)
async def joiner(
    body: JoinRequest,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> IdentityResponse:
    """Onboard a new joiner. Sets status PRE_HIRE if start_date is future, else ACTIVE."""
    realm_id = current_user["realm_id"]

    existing = await db.execute(
        select(Identity).where(
            Identity.realm_id == realm_id,
            Identity.username == body.username.strip().lower(),
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Username '{body.username}' already exists")

    now = datetime.now(timezone.utc)
    start = body.start_date or now
    initial_status = "PRE_HIRE" if start > now else "ACTIVE"

    identity = Identity(
        id=str(uuid.uuid4()),
        realm_id=realm_id,
        username=body.username.strip().lower(),
        email=body.email,
        display_name=f"{body.first_name or ''} {body.last_name or ''}".strip() or body.username,
        first_name=body.first_name,
        last_name=body.last_name,
        employee_id=body.employee_id,
        identity_type="HUMAN",
        status=initial_status,
        start_date=start,
        attributes=body.attributes,
    )
    db.add(identity)

    await write_audit(
        db,
        realm_id=realm_id,
        action="LIFECYCLE_JOIN",
        actor_id=current_user["sub"],
        actor_username=current_user["username"],
        actor_ip=_ip(request),
        resource_type="identity",
        target_id=identity.id,
        target_name=identity.username,
        after_state={
            "status": initial_status,
            "start_date": str(start),
            "employee_id": body.employee_id,
        },
    )
    await db.commit()
    await db.refresh(identity)
    return IdentityResponse.model_validate(identity)


# ── POST /api/v1/lifecycle/{id}/activate ─────────────────────────────────────

@router.post("/{identity_id}/activate", response_model=IdentityResponse)
async def activate(
    identity_id: str,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> IdentityResponse:
    """Activate a PRE_HIRE identity (first day of work)."""
    realm_id = current_user["realm_id"]
    identity = await db.get(Identity, identity_id)
    if not identity or identity.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Identity not found")
    if identity.status not in ("PRE_HIRE", "INACTIVE"):
        raise HTTPException(status_code=400, detail=f"Cannot activate identity with status {identity.status}")

    before_status = identity.status
    identity.status = "ACTIVE"
    identity.updated_at = datetime.now(timezone.utc)

    await write_audit(
        db,
        realm_id=realm_id,
        action="LIFECYCLE_ACTIVATE",
        actor_id=current_user["sub"],
        actor_username=current_user["username"],
        actor_ip=_ip(request),
        resource_type="identity",
        target_id=identity.id,
        target_name=identity.username,
        before_state={"status": before_status},
        after_state={"status": "ACTIVE"},
    )
    await db.commit()
    await db.refresh(identity)
    return IdentityResponse.model_validate(identity)


# ── POST /api/v1/lifecycle/{id}/move ─────────────────────────────────────────

@router.post("/{identity_id}/move", response_model=IdentityResponse)
async def mover(
    identity_id: str,
    body: MoveRequest,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> IdentityResponse:
    """Transfer identity — department change, new manager, new employee ID."""
    realm_id = current_user["realm_id"]
    identity = await db.get(Identity, identity_id)
    if not identity or identity.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Identity not found")
    if identity.status != "ACTIVE":
        raise HTTPException(status_code=400, detail="Can only move ACTIVE identities")

    before = {
        "employee_id": identity.employee_id,
        "attributes": dict(identity.attributes),
    }

    if body.new_employee_id:
        identity.employee_id = body.new_employee_id
    if body.new_org_unit_id:
        attrs = dict(identity.attributes)
        attrs["org_unit_id"] = body.new_org_unit_id
        identity.attributes = attrs
    if body.new_manager_id:
        attrs = dict(identity.attributes)
        attrs["manager_id"] = body.new_manager_id
        identity.attributes = attrs

    identity.updated_at = datetime.now(timezone.utc)

    await write_audit(
        db,
        realm_id=realm_id,
        action="LIFECYCLE_MOVE",
        actor_id=current_user["sub"],
        actor_username=current_user["username"],
        actor_ip=_ip(request),
        resource_type="identity",
        target_id=identity.id,
        target_name=identity.username,
        before_state=before,
        after_state={
            "new_org_unit_id": body.new_org_unit_id,
            "new_manager_id": body.new_manager_id,
            "new_employee_id": body.new_employee_id,
            "reason": body.reason,
        },
    )
    await db.commit()
    await db.refresh(identity)
    return IdentityResponse.model_validate(identity)


# ── POST /api/v1/lifecycle/{id}/leave ────────────────────────────────────────

@router.post("/{identity_id}/leave", response_model=IdentityResponse)
async def leave_of_absence(
    identity_id: str,
    body: LeaveRequest,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> IdentityResponse:
    """Put identity on leave — status ON_LEAVE, preserves access."""
    realm_id = current_user["realm_id"]
    identity = await db.get(Identity, identity_id)
    if not identity or identity.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Identity not found")
    if identity.status != "ACTIVE":
        raise HTTPException(status_code=400, detail="Can only put ACTIVE identities on leave")

    identity.status = "ON_LEAVE"
    if body.expected_return_date:
        attrs = dict(identity.attributes)
        attrs["expected_return_date"] = str(body.expected_return_date)
        identity.attributes = attrs
    identity.updated_at = datetime.now(timezone.utc)

    await write_audit(
        db,
        realm_id=realm_id,
        action="LIFECYCLE_LEAVE",
        actor_id=current_user["sub"],
        actor_username=current_user["username"],
        actor_ip=_ip(request),
        resource_type="identity",
        target_id=identity.id,
        target_name=identity.username,
        before_state={"status": "ACTIVE"},
        after_state={"status": "ON_LEAVE", "reason": body.reason},
    )
    await db.commit()
    await db.refresh(identity)
    return IdentityResponse.model_validate(identity)


# ── POST /api/v1/lifecycle/{id}/return-from-leave ────────────────────────────

@router.post("/{identity_id}/return-from-leave", response_model=IdentityResponse)
async def return_from_leave(
    identity_id: str,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> IdentityResponse:
    realm_id = current_user["realm_id"]
    identity = await db.get(Identity, identity_id)
    if not identity or identity.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Identity not found")
    if identity.status != "ON_LEAVE":
        raise HTTPException(status_code=400, detail="Identity is not ON_LEAVE")

    identity.status = "ACTIVE"
    identity.updated_at = datetime.now(timezone.utc)

    await write_audit(
        db, realm_id=realm_id, action="LIFECYCLE_RETURN_FROM_LEAVE",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="identity",
        target_id=identity.id, target_name=identity.username,
        before_state={"status": "ON_LEAVE"}, after_state={"status": "ACTIVE"},
    )
    await db.commit()
    await db.refresh(identity)
    return IdentityResponse.model_validate(identity)


# ── POST /api/v1/lifecycle/{id}/lock ─────────────────────────────────────────

@router.post("/{identity_id}/lock", response_model=IdentityResponse)
async def lock_identity(
    identity_id: str,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> IdentityResponse:
    realm_id = current_user["realm_id"]
    identity = await db.get(Identity, identity_id)
    if not identity or identity.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Identity not found")

    before_status = identity.status
    identity.status = "LOCKED"
    identity.updated_at = datetime.now(timezone.utc)

    await write_audit(
        db, realm_id=realm_id, action="LIFECYCLE_LOCK",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="identity",
        target_id=identity.id, target_name=identity.username,
        before_state={"status": before_status}, after_state={"status": "LOCKED"},
    )
    await db.commit()
    await db.refresh(identity)
    return IdentityResponse.model_validate(identity)


# ── POST /api/v1/lifecycle/{id}/unlock ───────────────────────────────────────

@router.post("/{identity_id}/unlock", response_model=IdentityResponse)
async def unlock_identity(
    identity_id: str,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> IdentityResponse:
    realm_id = current_user["realm_id"]
    identity = await db.get(Identity, identity_id)
    if not identity or identity.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Identity not found")
    if identity.status != "LOCKED":
        raise HTTPException(status_code=400, detail="Identity is not LOCKED")

    identity.status = "ACTIVE"
    identity.failed_login_attempts = 0
    identity.locked_until = None
    identity.updated_at = datetime.now(timezone.utc)

    await write_audit(
        db, realm_id=realm_id, action="LIFECYCLE_UNLOCK",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="identity",
        target_id=identity.id, target_name=identity.username,
        before_state={"status": "LOCKED"}, after_state={"status": "ACTIVE"},
    )
    await db.commit()
    await db.refresh(identity)
    return IdentityResponse.model_validate(identity)


# ── POST /api/v1/lifecycle/{id}/terminate ────────────────────────────────────

@router.post("/{identity_id}/terminate", response_model=IdentityResponse)
async def terminate(
    identity_id: str,
    body: TerminateRequest,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> IdentityResponse:
    """Immediate termination — disables account, sets termination_date."""
    realm_id = current_user["realm_id"]
    identity = await db.get(Identity, identity_id)
    if not identity or identity.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Identity not found")
    if identity.status == "TERMINATED":
        raise HTTPException(status_code=400, detail="Identity is already TERMINATED")

    before_status = identity.status
    identity.status = "TERMINATED"
    identity.termination_date = datetime.now(timezone.utc)
    identity.updated_at = datetime.now(timezone.utc)

    await write_audit(
        db,
        realm_id=realm_id,
        action="LIFECYCLE_TERMINATE",
        actor_id=current_user["sub"],
        actor_username=current_user["username"],
        actor_ip=_ip(request),
        resource_type="identity",
        target_id=identity.id,
        target_name=identity.username,
        before_state={"status": before_status},
        after_state={
            "status": "TERMINATED",
            "termination_date": str(identity.termination_date),
            "reason": body.reason,
            "revoke_access": body.revoke_access,
        },
    )
    await db.commit()
    await db.refresh(identity)
    return IdentityResponse.model_validate(identity)
