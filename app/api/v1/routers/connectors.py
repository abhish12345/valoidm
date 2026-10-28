"""
Connector management API:
  - CRUD for configured connectors
  - Test connection
  - Trigger sync (CSV or LDAP -> identity import)
  - Webhook subscription CRUD
  - CSV bulk import endpoint
"""
import hmac
import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_admin
from app.core.audit import write_audit
from app.models.connector import Connector, WebhookSubscription
from app.models.identity import Identity
from app.connectors.registry import get_connector
from app.connectors.csv_connector import CSVConnector

router = APIRouter(prefix="/connectors", tags=["connectors"])


def _ip(r: Request) -> str:
    fwd = r.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (r.client.host if r.client else "unknown")


# ── Pydantic models ───────────────────────────────────────────────────────────

class ConnectorCreate(BaseModel):
    name: str
    connector_type: str  # LDAP | CSV | SCIM | SERVICENOW | REST
    direction: str = "SOURCE"
    config: dict = {}


class ConnectorResponse(BaseModel):
    id: str
    realm_id: str
    name: str
    connector_type: str
    direction: str
    status: str
    last_sync_at: datetime | None
    last_sync_status: str | None
    last_sync_count: int
    last_error: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class WebhookCreate(BaseModel):
    name: str
    subscriber_url: str
    event_types: str = ""   # comma-separated e.g. "identity.created,role.assigned"


class WebhookResponse(BaseModel):
    id: str
    realm_id: str
    name: str
    subscriber_url: str
    event_types: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class SyncResponse(BaseModel):
    connector_name: str
    records_read: int
    records_created: int
    records_updated: int
    records_skipped: int
    records_failed: int
    errors: list[str]


# ── Connector CRUD ────────────────────────────────────────────────────────────

@router.get("", response_model=list[ConnectorResponse])
async def list_connectors(
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> list[ConnectorResponse]:
    rows = (await db.execute(
        select(Connector).where(Connector.realm_id == current_user["realm_id"])
    )).scalars().all()
    return [ConnectorResponse.model_validate(r) for r in rows]


@router.post("", response_model=ConnectorResponse, status_code=201)
async def create_connector(
    body: ConnectorCreate,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> ConnectorResponse:
    realm_id = current_user["realm_id"]
    valid_types = {"LDAP", "CSV", "SCIM", "SERVICENOW", "REST"}
    if body.connector_type.upper() not in valid_types:
        raise HTTPException(status_code=400, detail=f"connector_type must be one of {valid_types}")

    connector = Connector(
        id=str(uuid.uuid4()),
        realm_id=realm_id,
        name=body.name,
        connector_type=body.connector_type.upper(),
        direction=body.direction.upper(),
        status="ACTIVE",
        config=body.config,
    )
    db.add(connector)
    await write_audit(
        db, realm_id=realm_id, action="CONNECTOR_CREATED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="connector",
        target_id=connector.id, target_name=connector.name,
    )
    await db.commit()
    await db.refresh(connector)
    return ConnectorResponse.model_validate(connector)


@router.get("/{connector_id}", response_model=ConnectorResponse)
async def get_connector_detail(
    connector_id: str,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> ConnectorResponse:
    c = await db.get(Connector, connector_id)
    if not c or c.realm_id != current_user["realm_id"]:
        raise HTTPException(status_code=404, detail="Connector not found")
    return ConnectorResponse.model_validate(c)


@router.delete("/{connector_id}", status_code=204)
async def delete_connector(
    connector_id: str,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    c = await db.get(Connector, connector_id)
    if not c or c.realm_id != current_user["realm_id"]:
        raise HTTPException(status_code=404, detail="Connector not found")
    await write_audit(
        db, realm_id=current_user["realm_id"], action="CONNECTOR_DELETED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="connector",
        target_id=c.id, target_name=c.name,
    )
    await db.delete(c)
    await db.commit()


# ── Test connection ───────────────────────────────────────────────────────────

@router.post("/{connector_id}/test")
async def test_connection(
    connector_id: str,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    c = await db.get(Connector, connector_id)
    if not c or c.realm_id != current_user["realm_id"]:
        raise HTTPException(status_code=404, detail="Connector not found")
    try:
        conn = get_connector(c.connector_type, c.config)
        ok = conn.test_connection()
        return {"status": "ok" if ok else "failed", "connector": c.name}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


# ── Trigger sync ──────────────────────────────────────────────────────────────

@router.post("/{connector_id}/sync", response_model=SyncResponse)
async def trigger_sync(
    connector_id: str,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> SyncResponse:
    """
    Pull identities from the connector and upsert into the identity store.
    Works for LDAP connectors. For CSV, use /connectors/import/csv instead.
    """
    realm_id = current_user["realm_id"]
    c = await db.get(Connector, connector_id)
    if not c or c.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Connector not found")
    if c.connector_type == "CSV":
        raise HTTPException(status_code=400, detail="Use POST /connectors/import/csv for CSV sync")

    from app.connectors.base import SyncResult
    result = SyncResult(connector_name=c.name)

    try:
        conn = get_connector(c.connector_type, c.config)
        records = conn.sync_identities()
        result.records_read = len(records)

        for rec in records:
            existing = (await db.execute(
                select(Identity).where(
                    Identity.realm_id == realm_id,
                    Identity.username == rec.username,
                )
            )).scalar_one_or_none()

            if existing:
                existing.email      = rec.email or existing.email
                existing.first_name = rec.first_name or existing.first_name
                existing.last_name  = rec.last_name or existing.last_name
                existing.employee_id = rec.employee_id or existing.employee_id
                existing.updated_at = datetime.now(timezone.utc)
                result.records_updated += 1
            else:
                identity = Identity(
                    id=str(uuid.uuid4()),
                    realm_id=realm_id,
                    username=rec.username,
                    email=rec.email,
                    display_name=(
                        rec.display_name or
                        f"{rec.first_name} {rec.last_name}".strip() or
                        rec.username
                    ),
                    first_name=rec.first_name,
                    last_name=rec.last_name,
                    employee_id=rec.employee_id,
                    identity_type="HUMAN",
                    status=rec.status,
                    attributes={"source_connector": c.id, "external_id": rec.external_id},
                )
                db.add(identity)
                result.records_created += 1

        c.last_sync_at     = datetime.now(timezone.utc)
        c.last_sync_status = "SUCCESS"
        c.last_sync_count  = result.records_read
        c.last_error       = None

    except Exception as exc:
        result.errors.append(str(exc))
        c.last_sync_status = "ERROR"
        c.last_error       = str(exc)

    await write_audit(
        db, realm_id=realm_id, action="CONNECTOR_SYNC",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="connector",
        target_id=c.id, target_name=c.name,
        after_state={
            "read": result.records_read,
            "created": result.records_created,
            "updated": result.records_updated,
        },
    )
    await db.commit()

    return SyncResponse(
        connector_name=result.connector_name,
        records_read=result.records_read,
        records_created=result.records_created,
        records_updated=result.records_updated,
        records_skipped=result.records_skipped,
        records_failed=result.records_failed,
        errors=result.errors,
    )


# ── CSV bulk import ───────────────────────────────────────────────────────────

@router.post("/import/csv", response_model=SyncResponse)
async def import_csv(
    request: Request,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> SyncResponse:
    """Upload a CSV file and bulk-import identities."""
    realm_id = current_user["realm_id"]

    if not file.filename or not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="File must be a .csv")

    content = await file.read()
    if len(content) > 10 * 1024 * 1024:  # 10 MB limit
        raise HTTPException(status_code=413, detail="CSV file too large (max 10 MB)")

    connector = CSVConnector({})
    records, errors = connector.parse_csv(content)

    created = updated = failed = 0

    for rec in records:
        try:
            existing = (await db.execute(
                select(Identity).where(
                    Identity.realm_id == realm_id,
                    Identity.username == rec.username,
                )
            )).scalar_one_or_none()

            if existing:
                existing.email       = rec.email or existing.email
                existing.first_name  = rec.first_name or existing.first_name
                existing.last_name   = rec.last_name or existing.last_name
                existing.employee_id = rec.employee_id or existing.employee_id
                existing.updated_at  = datetime.now(timezone.utc)
                updated += 1
            else:
                identity = Identity(
                    id=str(uuid.uuid4()),
                    realm_id=realm_id,
                    username=rec.username,
                    email=rec.email,
                    display_name=(
                        f"{rec.first_name} {rec.last_name}".strip() or rec.username
                    ),
                    first_name=rec.first_name,
                    last_name=rec.last_name,
                    employee_id=rec.employee_id,
                    identity_type="HUMAN",
                    status=rec.status,
                    attributes={"source": "csv_import"},
                )
                db.add(identity)
                created += 1
        except Exception as exc:
            errors.append(f"Error processing {rec.username}: {exc}")
            failed += 1

    await write_audit(
        db, realm_id=realm_id, action="CSV_IMPORT",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="identity",
        after_state={
            "filename": file.filename,
            "created": created, "updated": updated, "failed": failed,
        },
    )
    await db.commit()

    return SyncResponse(
        connector_name="csv_import",
        records_read=len(records),
        records_created=created,
        records_updated=updated,
        records_skipped=0,
        records_failed=failed,
        errors=errors,
    )


# ── Webhook Subscriptions ─────────────────────────────────────────────────────

@router.get("/webhooks/all", response_model=list[WebhookResponse])
async def list_webhooks(
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> list[WebhookResponse]:
    rows = (await db.execute(
        select(WebhookSubscription).where(
            WebhookSubscription.realm_id == current_user["realm_id"]
        )
    )).scalars().all()
    return [WebhookResponse.model_validate(r) for r in rows]


@router.post("/webhooks", status_code=201)
async def create_webhook(
    body: WebhookCreate,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> WebhookResponse:
    realm_id = current_user["realm_id"]
    # Auto-generate signing secret
    signing_secret = secrets.token_hex(32)

    webhook = WebhookSubscription(
        id=str(uuid.uuid4()),
        realm_id=realm_id,
        name=body.name,
        subscriber_url=body.subscriber_url,
        event_types=body.event_types,
        secret=signing_secret,
        is_active=True,
    )
    db.add(webhook)
    await write_audit(
        db, realm_id=realm_id, action="WEBHOOK_CREATED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="webhook",
        target_id=webhook.id, target_name=webhook.name,
        after_state={"url": body.subscriber_url, "events": body.event_types},
    )
    await db.commit()
    await db.refresh(webhook)

    return JSONResponse(
        status_code=201,
        content={
            "id":             webhook.id,
            "realm_id":       webhook.realm_id,
            "name":           webhook.name,
            "subscriber_url": webhook.subscriber_url,
            "event_types":    webhook.event_types,
            "is_active":      webhook.is_active,
            "created_at":     webhook.created_at.isoformat(),
            "secret":         signing_secret,
            "note":           "Store this secret - it will not be shown again",
        }
    )


@router.delete("/webhooks/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: str,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    wh = await db.get(WebhookSubscription, webhook_id)
    if not wh or wh.realm_id != current_user["realm_id"]:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await write_audit(
        db, realm_id=current_user["realm_id"], action="WEBHOOK_DELETED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="webhook", target_id=webhook_id,
    )
    await db.delete(wh)
    await db.commit()


# ── Webhook test-fire ─────────────────────────────────────────────────────────

@router.post("/webhooks/{webhook_id}/test")
async def test_webhook(
    webhook_id: str,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Fire a test ping event to the webhook URL."""
    wh = await db.get(WebhookSubscription, webhook_id)
    if not wh or wh.realm_id != current_user["realm_id"]:
        raise HTTPException(status_code=404, detail="Webhook not found")

    from app.connectors.webhook_publisher import publish_event
    # Temporarily override event_types so test always fires
    original = wh.event_types
    wh.event_types = ""
    result = await publish_event(
        db,
        realm_id=wh.realm_id,
        event_type="webhook.test",
        payload={"message": "This is a test ping from ValoIDM", "webhook_id": webhook_id},
    )
    wh.event_types = original
    return result


# end of file
