"""
SCIM 2.0 inbound server — allows external systems to manage identities in ValoIDM.
Implements: GET /Users, POST /Users, GET /Users/{id}, PUT /Users/{id}, DELETE /Users/{id}
RFC 7644 compliant.
"""
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.core.audit import write_audit
from app.models.identity import Identity

router = APIRouter(prefix="/scim/v2", tags=["scim"])

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


def _to_scim_user(identity: Identity, base_url: str) -> dict:
    return {
        "schemas":    [SCIM_USER_SCHEMA],
        "id":         identity.id,
        "externalId": identity.employee_id or "",
        "userName":   identity.username,
        "name": {
            "formatted":  identity.display_name,
            "givenName":  identity.first_name or "",
            "familyName": identity.last_name or "",
        },
        "emails": [{"value": identity.email, "primary": True}],
        "active": identity.status == "ACTIVE",
        "meta": {
            "resourceType": "User",
            "created":      identity.created_at.isoformat(),
            "lastModified": identity.updated_at.isoformat(),
            "location":     f"{base_url}/scim/v2/Users/{identity.id}",
        },
    }


def _base_url(request: Request) -> str:
    return str(request.base_url).rstrip("/")


# ── GET /scim/v2/Users ────────────────────────────────────────────────────────

@router.get("/Users")
async def scim_list_users(
    request: Request,
    startIndex: int = Query(1, ge=1),
    count: int = Query(100, ge=1, le=200),
    filter: str | None = Query(None),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    realm_id = current_user["realm_id"]
    q = select(Identity).where(Identity.realm_id == realm_id)

    # Basic SCIM filter support: userName eq "xxx"  |  emails.value eq "xxx"
    if filter:
        import re
        m = re.match(r'userName eq "([^"]+)"', filter, re.I)
        if m:
            q = q.where(Identity.username == m.group(1).lower())
        m2 = re.match(r'emails\.value eq "([^"]+)"', filter, re.I)
        if m2:
            q = q.where(Identity.email == m2.group(1).lower())

    from sqlalchemy import func
    total = (await db.execute(
        select(func.count()).select_from(q.subquery())
    )).scalar_one()

    rows = (await db.execute(
        q.offset(startIndex - 1).limit(count)
    )).scalars().all()

    base = _base_url(request)
    return JSONResponse(content={
        "schemas":      [SCIM_LIST_SCHEMA],
        "totalResults": total,
        "startIndex":   startIndex,
        "itemsPerPage": len(rows),
        "Resources":    [_to_scim_user(r, base) for r in rows],
    })


# ── POST /scim/v2/Users ───────────────────────────────────────────────────────

@router.post("/Users", status_code=201)
async def scim_create_user(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    realm_id = current_user["realm_id"]
    body = await request.json()

    username   = body.get("userName", "").strip().lower()
    email_list = body.get("emails", [])
    email      = next((e["value"] for e in email_list if e.get("primary")), "")
    if not email and email_list:
        email = email_list[0].get("value", "")

    name      = body.get("name", {})
    first     = name.get("givenName", "")
    last      = name.get("familyName", "")
    ext_id    = body.get("externalId", "")
    active    = body.get("active", True)

    if not username:
        return JSONResponse(status_code=400, content={
            "schemas": [SCIM_ERROR_SCHEMA], "status": 400,
            "detail": "userName is required",
        })

    existing = (await db.execute(
        select(Identity).where(
            Identity.realm_id == realm_id, Identity.username == username
        )
    )).scalar_one_or_none()
    if existing:
        return JSONResponse(status_code=409, content={
            "schemas": [SCIM_ERROR_SCHEMA], "status": 409,
            "detail": f"User '{username}' already exists",
        })

    identity = Identity(
        id=str(uuid.uuid4()),
        realm_id=realm_id,
        username=username,
        email=email,
        display_name=f"{first} {last}".strip() or username,
        first_name=first, last_name=last,
        employee_id=ext_id,
        identity_type="HUMAN",
        status="ACTIVE" if active else "INACTIVE",
        attributes={},
    )
    db.add(identity)
    await write_audit(
        db, realm_id=realm_id, action="SCIM_USER_CREATED",
        actor_username="scim-client", resource_type="identity",
        target_id=identity.id, target_name=username,
    )
    await db.commit()
    await db.refresh(identity)

    base = _base_url(request)
    return JSONResponse(status_code=201, content=_to_scim_user(identity, base))


# ── GET /scim/v2/Users/{id} ───────────────────────────────────────────────────

@router.get("/Users/{user_id}")
async def scim_get_user(
    user_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    identity = await db.get(Identity, user_id)
    if not identity or identity.realm_id != current_user["realm_id"]:
        return JSONResponse(status_code=404, content={
            "schemas": [SCIM_ERROR_SCHEMA], "status": 404, "detail": "User not found",
        })
    return JSONResponse(content=_to_scim_user(identity, _base_url(request)))


# ── PUT /scim/v2/Users/{id} ───────────────────────────────────────────────────

@router.put("/Users/{user_id}")
async def scim_replace_user(
    user_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    realm_id = current_user["realm_id"]
    identity = await db.get(Identity, user_id)
    if not identity or identity.realm_id != realm_id:
        return JSONResponse(status_code=404, content={
            "schemas": [SCIM_ERROR_SCHEMA], "status": 404, "detail": "User not found",
        })

    body   = await request.json()
    name   = body.get("name", {})
    emails = body.get("emails", [])
    email  = next((e["value"] for e in emails if e.get("primary")), "")
    active = body.get("active", True)

    before = {"email": identity.email, "status": identity.status}

    if name.get("givenName"):
        identity.first_name = name["givenName"]
    if name.get("familyName"):
        identity.last_name = name["familyName"]
    if email:
        identity.email = email
    identity.status = "ACTIVE" if active else "INACTIVE"
    identity.updated_at = datetime.now(timezone.utc)

    await write_audit(
        db, realm_id=realm_id, action="SCIM_USER_UPDATED",
        actor_username="scim-client", resource_type="identity",
        target_id=identity.id, target_name=identity.username,
        before_state=before,
    )
    await db.commit()
    await db.refresh(identity)
    return JSONResponse(content=_to_scim_user(identity, _base_url(request)))


# ── PATCH /scim/v2/Users/{id} — partial update (active flag etc.) ─────────────

@router.patch("/Users/{user_id}")
async def scim_patch_user(
    user_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    realm_id = current_user["realm_id"]
    identity = await db.get(Identity, user_id)
    if not identity or identity.realm_id != realm_id:
        return JSONResponse(status_code=404, content={
            "schemas": [SCIM_ERROR_SCHEMA], "status": 404, "detail": "User not found",
        })

    body = await request.json()
    ops  = body.get("Operations", [])
    for op in ops:
        path  = op.get("path", "")
        value = op.get("value")
        if path == "active" and value is not None:
            identity.status = "ACTIVE" if value else "INACTIVE"

    identity.updated_at = datetime.now(timezone.utc)
    await write_audit(
        db, realm_id=realm_id, action="SCIM_USER_PATCHED",
        actor_username="scim-client", resource_type="identity",
        target_id=identity.id, target_name=identity.username,
    )
    await db.commit()
    await db.refresh(identity)
    return JSONResponse(content=_to_scim_user(identity, _base_url(request)))


# ── DELETE /scim/v2/Users/{id} ────────────────────────────────────────────────

@router.delete("/Users/{user_id}", status_code=204)
async def scim_delete_user(
    user_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    realm_id = current_user["realm_id"]
    identity = await db.get(Identity, user_id)
    if not identity or identity.realm_id != realm_id:
        return JSONResponse(status_code=404, content={
            "schemas": [SCIM_ERROR_SCHEMA], "status": 404, "detail": "User not found",
        })
    if identity.legal_hold:
        return JSONResponse(status_code=409, content={
            "schemas": [SCIM_ERROR_SCHEMA], "status": 409,
            "detail": "Identity has a legal hold",
        })
    await write_audit(
        db, realm_id=realm_id, action="SCIM_USER_DELETED",
        actor_username="scim-client", resource_type="identity",
        target_id=identity.id, target_name=identity.username,
    )
    await db.delete(identity)
    await db.commit()


# ── GET /scim/v2/ServiceProviderConfig ────────────────────────────────────────

@router.get("/ServiceProviderConfig")
async def service_provider_config() -> JSONResponse:
    return JSONResponse(content={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "",
        "patch":    {"supported": True},
        "bulk":     {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter":   {"supported": True,  "maxResults": 200},
        "changePassword": {"supported": False},
        "sort":     {"supported": False},
        "etag":     {"supported": False},
        "authenticationSchemes": [
            {"type": "oauthbearertoken", "name": "OAuth Bearer Token",
             "description": "Bearer JWT", "specUri": "https://tools.ietf.org/html/rfc6750"}
        ],
    })
