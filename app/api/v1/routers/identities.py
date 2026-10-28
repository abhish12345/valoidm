import uuid
import math
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.security import hash_password, get_current_user, get_current_admin
from app.core.audit import write_audit
from app.models.identity import Identity
from app.schemas.identity import (
    IdentityCreate, IdentityUpdate,
    IdentityResponse, IdentityListResponse,
)

router = APIRouter(prefix="/identities", tags=["identities"])


def _ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")


# ── GET /api/v1/identities ────────────────────────────────────────────────────

@router.get("", response_model=IdentityListResponse)
async def list_identities(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: str | None = Query(None),
    identity_type: str | None = Query(None),
    search: str | None = Query(None, description="Search username or email"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> IdentityListResponse:
    realm_id = current_user["realm_id"]

    q = select(Identity).where(Identity.realm_id == realm_id)

    if status:
        q = q.where(Identity.status == status.upper())
    if identity_type:
        q = q.where(Identity.identity_type == identity_type.upper())
    if search:
        term = f"%{search.lower()}%"
        from sqlalchemy import or_
        q = q.where(
            or_(
                Identity.username.ilike(term),
                Identity.email.ilike(term),
                Identity.display_name.ilike(term),
            )
        )

    # Total count
    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar_one()

    # Paginate
    q = q.order_by(Identity.created_at.desc())
    q = q.offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(q)).scalars().all()

    return IdentityListResponse(
        items=[IdentityResponse.model_validate(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


# ── GET /api/v1/identities/{id} ───────────────────────────────────────────────

@router.get("/{identity_id}", response_model=IdentityResponse)
async def get_identity(
    identity_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> IdentityResponse:
    realm_id = current_user["realm_id"]
    row = await db.get(Identity, identity_id)
    if not row or row.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Identity not found")
    return IdentityResponse.model_validate(row)


# ── POST /api/v1/identities ───────────────────────────────────────────────────

@router.post("", response_model=IdentityResponse, status_code=201)
async def create_identity(
    body: IdentityCreate,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> IdentityResponse:
    realm_id = current_user["realm_id"]

    existing = await db.execute(
        select(Identity).where(
            Identity.realm_id == realm_id,
            Identity.username == body.username,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Username '{body.username}' already exists")

    identity = Identity(
        id=str(uuid.uuid4()),
        realm_id=realm_id,
        username=body.username,
        email=body.email,
        display_name=f"{body.first_name or ''} {body.last_name or ''}".strip() or body.username,
        first_name=body.first_name,
        last_name=body.last_name,
        identity_type=body.identity_type,
        employee_id=body.employee_id,
        status="ACTIVE",
        password_hash=hash_password(body.password) if body.password else None,
        attributes=body.attributes,
    )
    db.add(identity)

    await write_audit(
        db,
        realm_id=realm_id,
        action="IDENTITY_CREATED",
        actor_id=current_user["sub"],
        actor_username=current_user["username"],
        actor_ip=_ip(request),
        resource_type="identity",
        target_id=identity.id,
        target_name=identity.username,
        after_state={"username": identity.username, "email": identity.email, "type": identity.identity_type},
    )
    await db.commit()
    await db.refresh(identity)
    return IdentityResponse.model_validate(identity)


# ── PUT /api/v1/identities/{id} ───────────────────────────────────────────────

@router.put("/{identity_id}", response_model=IdentityResponse)
async def update_identity(
    identity_id: str,
    body: IdentityUpdate,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> IdentityResponse:
    realm_id = current_user["realm_id"]
    identity = await db.get(Identity, identity_id)
    if not identity or identity.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Identity not found")

    before = {"email": identity.email, "display_name": identity.display_name}
    updates = body.model_dump(exclude_none=True)
    for field, value in updates.items():
        setattr(identity, field, value)

    # Rebuild display_name if names changed
    if body.first_name or body.last_name:
        fn = body.first_name or identity.first_name or ""
        ln = body.last_name or identity.last_name or ""
        if not body.display_name:
            identity.display_name = f"{fn} {ln}".strip() or identity.username

    identity.updated_at = datetime.now(timezone.utc)

    await write_audit(
        db,
        realm_id=realm_id,
        action="IDENTITY_UPDATED",
        actor_id=current_user["sub"],
        actor_username=current_user["username"],
        actor_ip=_ip(request),
        resource_type="identity",
        target_id=identity.id,
        target_name=identity.username,
        before_state=before,
        after_state=updates,
    )
    await db.commit()
    await db.refresh(identity)
    return IdentityResponse.model_validate(identity)


# ── DELETE /api/v1/identities/{id} ───────────────────────────────────────────

@router.delete("/{identity_id}", status_code=204)
async def delete_identity(
    identity_id: str,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    realm_id = current_user["realm_id"]
    identity = await db.get(Identity, identity_id)
    if not identity or identity.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Identity not found")

    if identity.legal_hold:
        raise HTTPException(
            status_code=409,
            detail="Identity has a legal hold — cannot be deleted",
        )

    await write_audit(
        db,
        realm_id=realm_id,
        action="IDENTITY_DELETED",
        actor_id=current_user["sub"],
        actor_username=current_user["username"],
        actor_ip=_ip(request),
        resource_type="identity",
        target_id=identity.id,
        target_name=identity.username,
        before_state={"username": identity.username, "status": identity.status},
    )
    await db.delete(identity)
    await db.commit()
