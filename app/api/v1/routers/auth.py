import uuid
import pyotp
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import (
    hash_password, verify_password,
    create_access_token, create_refresh_token,
    decode_token, get_current_user,
)
from app.core.audit import write_audit
from app.core.config import settings
from app.models.tenant import Tenant
from app.models.identity import Identity
from app.schemas.auth import (
    RegisterRequest, LoginRequest, TokenResponse,
    MFASetupResponse, MFAVerifyRequest, RefreshRequest,
    MeResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


# ── helpers ───────────────────────────────────────────────────────────────────

def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")


async def _ensure_tenant(db: AsyncSession, realm_id: str) -> Tenant:
    result = await db.execute(select(Tenant).where(Tenant.realm_id == realm_id))
    tenant = result.scalar_one_or_none()
    if not tenant:
        # Auto-create realm on first use (development convenience)
        tenant = Tenant(
            id=str(uuid.uuid4()),
            realm_id=realm_id,
            display_name=realm_id.capitalize(),
            is_active=True,
            config={},
        )
        db.add(tenant)
        await db.flush()
    return tenant


def _build_token_payload(identity: Identity) -> dict:
    return {
        "sub":      identity.id,
        "realm_id": identity.realm_id,
        "username": identity.username,
        "email":    identity.email,
        "is_admin": identity.is_admin,
    }


# ── POST /api/v1/auth/register ────────────────────────────────────────────────

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _ensure_tenant(db, body.realm_id)

    # Check username not taken in this realm
    existing = await db.execute(
        select(Identity).where(
            Identity.realm_id == body.realm_id,
            Identity.username == body.username,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{body.username}' already exists in realm '{body.realm_id}'",
        )

    identity = Identity(
        id=str(uuid.uuid4()),
        realm_id=body.realm_id,
        username=body.username,
        email=str(body.email),
        display_name=f"{body.first_name or ''} {body.last_name or ''}".strip() or body.username,
        first_name=body.first_name,
        last_name=body.last_name,
        identity_type="HUMAN",
        status="ACTIVE",
        password_hash=hash_password(body.password),
        is_admin=body.is_admin,
        attributes={},
    )
    db.add(identity)

    await write_audit(
        db,
        realm_id=body.realm_id,
        action="IDENTITY_REGISTERED",
        actor_username=body.username,
        actor_ip=_client_ip(request),
        resource_type="identity",
        target_id=identity.id,
        target_name=body.username,
        outcome="SUCCESS",
    )

    await db.commit()
    return {
        "id": identity.id,
        "username": identity.username,
        "realm_id": identity.realm_id,
        "message": "Registration successful",
    }


# ── POST /api/v1/auth/login ───────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    result = await db.execute(
        select(Identity).where(
            Identity.realm_id == body.realm_id,
            Identity.username == body.username,
        )
    )
    identity = result.scalar_one_or_none()

    # Constant-time failure (don't reveal whether user exists)
    if not identity or not identity.password_hash:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Check lockout
    if identity.locked_until and identity.locked_until > datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account temporarily locked — too many failed attempts",
        )

    if not verify_password(body.password, identity.password_hash):
        identity.failed_login_attempts += 1
        if identity.failed_login_attempts >= 5:
            from datetime import timedelta
            identity.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        await write_audit(
            db,
            realm_id=body.realm_id,
            action="LOGIN_FAILED",
            actor_username=body.username,
            actor_ip=_client_ip(request),
            target_id=identity.id,
            outcome="FAILURE",
            detail="Wrong password",
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if identity.status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account is {identity.status.lower()}",
        )

    # MFA check
    if identity.mfa_enabled:
        if not body.totp_code:
            return TokenResponse(
                access_token="",
                refresh_token="",
                expires_in=0,
                realm_id=identity.realm_id,
                username=identity.username,
                is_admin=identity.is_admin,
                mfa_required=True,
            )
        totp = pyotp.TOTP(identity.totp_secret)
        if not totp.verify(body.totp_code, valid_window=1):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code",
            )

    # Success — reset failed attempts, update last_login
    identity.failed_login_attempts = 0
    identity.locked_until = None
    identity.last_login_at = datetime.now(timezone.utc)

    payload = _build_token_payload(identity)
    access_token  = create_access_token(payload)
    refresh_token = create_refresh_token({"sub": identity.id, "realm_id": identity.realm_id})

    await write_audit(
        db,
        realm_id=identity.realm_id,
        action="LOGIN_SUCCESS",
        actor_id=identity.id,
        actor_username=identity.username,
        actor_ip=_client_ip(request),
        target_id=identity.id,
        outcome="SUCCESS",
    )
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.JWT_EXPIRE_MINUTES * 60,
        realm_id=identity.realm_id,
        username=identity.username,
        is_admin=identity.is_admin,
    )


# ── GET /api/v1/auth/me ───────────────────────────────────────────────────────

@router.get("/me", response_model=MeResponse)
async def me(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MeResponse:
    result = await db.execute(
        select(Identity).where(Identity.id == current_user["sub"])
    )
    identity = result.scalar_one_or_none()
    if not identity:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return MeResponse(
        id=identity.id,
        realm_id=identity.realm_id,
        username=identity.username,
        email=identity.email,
        display_name=identity.display_name,
        identity_type=identity.identity_type,
        status=identity.status,
        is_admin=identity.is_admin,
        mfa_enabled=identity.mfa_enabled,
        created_at=identity.created_at,
    )


# ── POST /api/v1/auth/mfa/setup ──────────────────────────────────────────────

@router.post("/mfa/setup", response_model=MFASetupResponse)
async def mfa_setup(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MFASetupResponse:
    result = await db.execute(
        select(Identity).where(Identity.id == current_user["sub"])
    )
    identity = result.scalar_one_or_none()
    if not identity:
        raise HTTPException(status_code=404, detail="User not found")
    if identity.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA already enabled")

    secret = pyotp.random_base32()
    identity.totp_secret = secret
    # Not yet enabled — user must verify first
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=identity.email, issuer_name="ValoIDM")
    await db.commit()
    return MFASetupResponse(totp_uri=uri, secret=secret)


# ── POST /api/v1/auth/mfa/verify ─────────────────────────────────────────────

@router.post("/mfa/verify")
async def mfa_verify(
    body: MFAVerifyRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(
        select(Identity).where(Identity.id == current_user["sub"])
    )
    identity = result.scalar_one_or_none()
    if not identity or not identity.totp_secret:
        raise HTTPException(status_code=400, detail="MFA not set up")

    totp = pyotp.TOTP(identity.totp_secret)
    if not totp.verify(body.totp_code, valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    identity.mfa_enabled = True
    await db.commit()
    return {"message": "MFA enabled successfully"}


# ── POST /api/v1/auth/refresh ─────────────────────────────────────────────────

@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    try:
        payload = decode_token(body.refresh_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")

    result = await db.execute(
        select(Identity).where(Identity.id == payload["sub"])
    )
    identity = result.scalar_one_or_none()
    if not identity or identity.status != "ACTIVE":
        raise HTTPException(status_code=401, detail="User not found or inactive")

    token_payload = _build_token_payload(identity)
    return TokenResponse(
        access_token=create_access_token(token_payload),
        refresh_token=create_refresh_token({"sub": identity.id, "realm_id": identity.realm_id}),
        expires_in=settings.JWT_EXPIRE_MINUTES * 60,
        realm_id=identity.realm_id,
        username=identity.username,
        is_admin=identity.is_admin,
    )
