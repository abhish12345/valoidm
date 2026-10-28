import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_

from app.core.database import get_db
from app.core.security import get_current_user, get_current_admin
from app.core.audit import write_audit
from app.models.role import Role, RoleConflict, RoleAssignment
from app.schemas.role import (
    RoleCreate, RoleUpdate, RoleResponse,
    RoleConflictCreate, RoleConflictResponse,
    AssignRoleRequest, RevokeRoleRequest,
    RoleAssignmentResponse, SoDCheckResult,
)

router = APIRouter(prefix="/roles", tags=["roles"])


def _ip(r: Request) -> str:
    fwd = r.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (r.client.host if r.client else "unknown")


# ── Role CRUD ─────────────────────────────────────────────────────────────────

@router.get("/catalog", response_model=list[RoleResponse])
async def role_catalog(
    role_type: str | None = Query(None),
    requestable_only: bool = Query(False),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[RoleResponse]:
    """Public role catalog — what roles exist and are requestable."""
    realm_id = current_user["realm_id"]
    q = select(Role).where(Role.realm_id == realm_id, Role.is_active == True)
    if role_type:
        q = q.where(Role.role_type == role_type.upper())
    if requestable_only:
        q = q.where(Role.is_requestable == True)
    rows = (await db.execute(q.order_by(Role.name))).scalars().all()
    return [RoleResponse.model_validate(r) for r in rows]


@router.get("/{role_id}", response_model=RoleResponse)
async def get_role(
    role_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> RoleResponse:
    role = await db.get(Role, role_id)
    if not role or role.realm_id != current_user["realm_id"]:
        raise HTTPException(status_code=404, detail="Role not found")
    return RoleResponse.model_validate(role)


@router.post("", response_model=RoleResponse, status_code=201)
async def create_role(
    body: RoleCreate,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> RoleResponse:
    realm_id = current_user["realm_id"]

    # Check unique name in realm
    existing = (await db.execute(
        select(Role).where(Role.realm_id == realm_id, Role.name == body.name)
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail=f"Role '{body.name}' already exists")

    # Validate parent
    if body.parent_id:
        parent = await db.get(Role, body.parent_id)
        if not parent or parent.realm_id != realm_id:
            raise HTTPException(status_code=404, detail="Parent role not found")

    role = Role(
        id=str(uuid.uuid4()),
        realm_id=realm_id,
        name=body.name,
        description=body.description,
        role_type=body.role_type,
        parent_id=body.parent_id,
        owner_id=body.owner_id,
        is_requestable=body.is_requestable,
        requires_approval=body.requires_approval,
    )
    db.add(role)
    await write_audit(
        db, realm_id=realm_id, action="ROLE_CREATED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="role",
        target_id=role.id, target_name=role.name,
        after_state={"name": role.name, "type": role.role_type},
    )
    await db.commit()
    await db.refresh(role)
    return RoleResponse.model_validate(role)


@router.put("/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: str,
    body: RoleUpdate,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> RoleResponse:
    role = await db.get(Role, role_id)
    if not role or role.realm_id != current_user["realm_id"]:
        raise HTTPException(status_code=404, detail="Role not found")

    before = {"name": role.name, "is_active": role.is_active}
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(role, field, value)
    role.updated_at = datetime.now(timezone.utc)

    await write_audit(
        db, realm_id=current_user["realm_id"], action="ROLE_UPDATED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="role",
        target_id=role.id, target_name=role.name,
        before_state=before,
    )
    await db.commit()
    await db.refresh(role)
    return RoleResponse.model_validate(role)


@router.delete("/{role_id}", status_code=204)
async def delete_role(
    role_id: str,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    role = await db.get(Role, role_id)
    if not role or role.realm_id != current_user["realm_id"]:
        raise HTTPException(status_code=404, detail="Role not found")

    # Check active assignments
    active_assign = (await db.execute(
        select(RoleAssignment).where(
            RoleAssignment.role_id == role_id,
            RoleAssignment.status == "ACTIVE",
        )
    )).scalar_one_or_none()
    if active_assign:
        raise HTTPException(
            status_code=409,
            detail="Cannot delete role with active assignments — revoke all assignments first",
        )

    await write_audit(
        db, realm_id=current_user["realm_id"], action="ROLE_DELETED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="role",
        target_id=role.id, target_name=role.name,
    )
    await db.delete(role)
    await db.commit()


# ── SoD Conflicts ─────────────────────────────────────────────────────────────

@router.get("/conflicts/all", response_model=list[RoleConflictResponse])
async def list_conflicts(
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> list[RoleConflictResponse]:
    rows = (await db.execute(
        select(RoleConflict).where(RoleConflict.realm_id == current_user["realm_id"])
    )).scalars().all()
    return [RoleConflictResponse.model_validate(r) for r in rows]


@router.post("/conflicts", response_model=RoleConflictResponse, status_code=201)
async def create_conflict(
    body: RoleConflictCreate,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> RoleConflictResponse:
    realm_id = current_user["realm_id"]

    # Validate both roles exist
    for rid in (body.role_a_id, body.role_b_id):
        role = await db.get(Role, rid)
        if not role or role.realm_id != realm_id:
            raise HTTPException(status_code=404, detail=f"Role {rid} not found")

    # Enforce ordered pair to prevent duplicates
    a, b = sorted([body.role_a_id, body.role_b_id])

    existing = (await db.execute(
        select(RoleConflict).where(
            RoleConflict.role_a_id == a, RoleConflict.role_b_id == b
        )
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="SoD conflict already defined for this pair")

    conflict = RoleConflict(
        id=str(uuid.uuid4()), realm_id=realm_id,
        role_a_id=a, role_b_id=b, description=body.description,
    )
    db.add(conflict)
    await write_audit(
        db, realm_id=realm_id, action="SOD_CONFLICT_CREATED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="role_conflict",
        target_id=conflict.id,
        after_state={"role_a": a, "role_b": b},
    )
    await db.commit()
    await db.refresh(conflict)
    return RoleConflictResponse.model_validate(conflict)


@router.delete("/conflicts/{conflict_id}", status_code=204)
async def delete_conflict(
    conflict_id: str,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    conflict = await db.get(RoleConflict, conflict_id)
    if not conflict or conflict.realm_id != current_user["realm_id"]:
        raise HTTPException(status_code=404, detail="Conflict not found")
    await write_audit(
        db, realm_id=current_user["realm_id"], action="SOD_CONFLICT_DELETED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="role_conflict", target_id=conflict_id,
    )
    await db.delete(conflict)
    await db.commit()


# ── Role Assignments ──────────────────────────────────────────────────────────

@router.get("/assignments/identity/{identity_id}", response_model=list[RoleAssignmentResponse])
async def get_assignments(
    identity_id: str,
    active_only: bool = Query(True),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[RoleAssignmentResponse]:
    q = select(RoleAssignment).where(
        RoleAssignment.realm_id == current_user["realm_id"],
        RoleAssignment.identity_id == identity_id,
    )
    if active_only:
        q = q.where(RoleAssignment.status == "ACTIVE")
    rows = (await db.execute(q)).scalars().all()
    return [RoleAssignmentResponse.model_validate(r) for r in rows]


async def _sod_check(
    db: AsyncSession, realm_id: str, identity_id: str, new_role_id: str
) -> SoDCheckResult:
    """Check if assigning new_role_id would create an SoD violation."""
    active_roles = (await db.execute(
        select(RoleAssignment.role_id).where(
            RoleAssignment.realm_id == realm_id,
            RoleAssignment.identity_id == identity_id,
            RoleAssignment.status == "ACTIVE",
        )
    )).scalars().all()

    if not active_roles:
        return SoDCheckResult(has_conflict=False)

    conflicts = (await db.execute(
        select(RoleConflict).where(
            RoleConflict.realm_id == realm_id,
            or_(
                and_(
                    RoleConflict.role_a_id == new_role_id,
                    RoleConflict.role_b_id.in_(active_roles),
                ),
                and_(
                    RoleConflict.role_b_id == new_role_id,
                    RoleConflict.role_a_id.in_(active_roles),
                ),
            ),
        )
    )).scalars().all()

    if conflicts:
        conflicting = list({c.role_a_id for c in conflicts} | {c.role_b_id for c in conflicts})
        conflicting = [r for r in conflicting if r != new_role_id]
        return SoDCheckResult(
            has_conflict=True,
            conflicting_role_ids=conflicting,
            detail=f"Assigning this role conflicts with {len(conflicts)} SoD rule(s)",
        )
    return SoDCheckResult(has_conflict=False)


@router.post("/assignments/identity/{identity_id}", response_model=RoleAssignmentResponse, status_code=201)
async def assign_role(
    identity_id: str,
    body: AssignRoleRequest,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> RoleAssignmentResponse:
    realm_id = current_user["realm_id"]

    # Validate role
    role = await db.get(Role, body.role_id)
    if not role or role.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Role not found")

    # Check duplicate active assignment
    existing = (await db.execute(
        select(RoleAssignment).where(
            RoleAssignment.identity_id == identity_id,
            RoleAssignment.role_id == body.role_id,
            RoleAssignment.status == "ACTIVE",
        )
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Role already actively assigned to this identity")

    # SoD check
    sod = await _sod_check(db, realm_id, identity_id, body.role_id)
    if sod.has_conflict:
        raise HTTPException(
            status_code=409,
            detail=f"SoD violation: {sod.detail}. Conflicting roles: {sod.conflicting_role_ids}",
        )

    assignment = RoleAssignment(
        id=str(uuid.uuid4()),
        realm_id=realm_id,
        identity_id=identity_id,
        role_id=body.role_id,
        status="ACTIVE",
        assigned_by=current_user["sub"],
        valid_from=body.valid_from,
        valid_until=body.valid_until,
    )
    db.add(assignment)
    await write_audit(
        db, realm_id=realm_id, action="ROLE_ASSIGNED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="role_assignment",
        target_id=identity_id,
        after_state={"role_id": body.role_id, "role_name": role.name},
    )
    await db.commit()
    await db.refresh(assignment)
    return RoleAssignmentResponse.model_validate(assignment)


@router.delete("/assignments/{assignment_id}", status_code=200)
async def revoke_role(
    assignment_id: str,
    body: RevokeRoleRequest,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    assignment = await db.get(RoleAssignment, assignment_id)
    if not assignment or assignment.realm_id != current_user["realm_id"]:
        raise HTTPException(status_code=404, detail="Assignment not found")
    if assignment.status != "ACTIVE":
        raise HTTPException(status_code=400, detail=f"Assignment is already {assignment.status}")

    assignment.status = "REVOKED"
    assignment.revoked_at = datetime.now(timezone.utc)
    assignment.revoked_by = current_user["sub"]
    assignment.revoke_reason = body.reason

    await write_audit(
        db, realm_id=current_user["realm_id"], action="ROLE_REVOKED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="role_assignment",
        target_id=assignment.identity_id,
        before_state={"status": "ACTIVE", "role_id": assignment.role_id},
        after_state={"status": "REVOKED", "reason": body.reason},
    )
    await db.commit()
    return {"message": "Role revoked", "assignment_id": assignment_id}
