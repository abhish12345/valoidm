import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.security import get_current_user, get_current_admin
from app.core.audit import write_audit
from app.models.role import RoleAssignment
from app.models.certification import CertificationCampaign, CertificationItem
from app.schemas.certification import (
    CampaignCreate, CampaignResponse,
    CertificationItemResponse, ItemDecision,
)

router = APIRouter(prefix="/certifications", tags=["certifications"])


def _ip(r: Request) -> str:
    fwd = r.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (r.client.host if r.client else "unknown")


# ── POST /api/v1/certifications ───────────────────────────────────────────────

@router.post("", response_model=CampaignResponse, status_code=201)
async def create_campaign(
    body: CampaignCreate,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> CampaignResponse:
    """Create a certification campaign in DRAFT state."""
    realm_id = current_user["realm_id"]

    campaign = CertificationCampaign(
        id=str(uuid.uuid4()),
        realm_id=realm_id,
        name=body.name,
        description=body.description,
        status="DRAFT",
        created_by=current_user["sub"],
        due_date=body.due_date,
    )
    db.add(campaign)
    await write_audit(
        db, realm_id=realm_id, action="CERT_CAMPAIGN_CREATED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="certification_campaign",
        target_id=campaign.id, target_name=campaign.name,
    )
    await db.commit()
    await db.refresh(campaign)
    return CampaignResponse.model_validate(campaign)


# ── POST /api/v1/certifications/{id}/launch ───────────────────────────────────

@router.post("/{campaign_id}/launch", response_model=CampaignResponse)
async def launch_campaign(
    campaign_id: str,
    request: Request,
    reviewer_id: str = Query(..., description="Identity ID of the reviewer for all items"),
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> CampaignResponse:
    """
    Launch a DRAFT campaign → ACTIVE.
    Snapshots all current ACTIVE role assignments and creates CertificationItems.
    In production this would assign reviewers per role-owner / manager.
    For now, all items go to the specified reviewer.
    """
    realm_id = current_user["realm_id"]
    campaign = await db.get(CertificationCampaign, campaign_id)
    if not campaign or campaign.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.status != "DRAFT":
        raise HTTPException(status_code=400, detail=f"Campaign is already {campaign.status}")

    # Snapshot all active assignments
    assignments = (await db.execute(
        select(RoleAssignment).where(
            RoleAssignment.realm_id == realm_id,
            RoleAssignment.status == "ACTIVE",
        )
    )).scalars().all()

    if not assignments:
        raise HTTPException(status_code=400, detail="No active role assignments to certify")

    items = []
    for a in assignments:
        item = CertificationItem(
            id=str(uuid.uuid4()),
            campaign_id=campaign.id,
            realm_id=realm_id,
            identity_id=a.identity_id,
            role_id=a.role_id,
            assignment_id=a.id,
            reviewer_id=reviewer_id,
            status="PENDING",
        )
        db.add(item)
        items.append(item)

    campaign.status = "ACTIVE"
    campaign.total_items = len(items)

    await write_audit(
        db, realm_id=realm_id, action="CERT_CAMPAIGN_LAUNCHED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="certification_campaign",
        target_id=campaign.id, target_name=campaign.name,
        after_state={"total_items": len(items), "reviewer_id": reviewer_id},
    )
    await db.commit()
    await db.refresh(campaign)
    return CampaignResponse.model_validate(campaign)


# ── GET /api/v1/certifications ────────────────────────────────────────────────

@router.get("", response_model=list[CampaignResponse])
async def list_campaigns(
    status_filter: str | None = Query(None, alias="status"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[CampaignResponse]:
    q = select(CertificationCampaign).where(
        CertificationCampaign.realm_id == current_user["realm_id"]
    )
    if status_filter:
        q = q.where(CertificationCampaign.status == status_filter.upper())
    rows = (await db.execute(q.order_by(CertificationCampaign.created_at.desc()))).scalars().all()
    return [CampaignResponse.model_validate(r) for r in rows]


# ── GET /api/v1/certifications/{id} ──────────────────────────────────────────

@router.get("/{campaign_id}", response_model=CampaignResponse)
async def get_campaign(
    campaign_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CampaignResponse:
    campaign = await db.get(CertificationCampaign, campaign_id)
    if not campaign or campaign.realm_id != current_user["realm_id"]:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return CampaignResponse.model_validate(campaign)


# ── GET /api/v1/certifications/{id}/items ────────────────────────────────────

@router.get("/{campaign_id}/items", response_model=list[CertificationItemResponse])
async def list_items(
    campaign_id: str,
    status_filter: str | None = Query(None, alias="status"),
    reviewer_only: bool = Query(False, description="Only show items assigned to me"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[CertificationItemResponse]:
    campaign = await db.get(CertificationCampaign, campaign_id)
    if not campaign or campaign.realm_id != current_user["realm_id"]:
        raise HTTPException(status_code=404, detail="Campaign not found")

    q = select(CertificationItem).where(CertificationItem.campaign_id == campaign_id)
    if status_filter:
        q = q.where(CertificationItem.status == status_filter.upper())
    if reviewer_only:
        q = q.where(CertificationItem.reviewer_id == current_user["sub"])
    rows = (await db.execute(q)).scalars().all()
    return [CertificationItemResponse.model_validate(r) for r in rows]


# ── POST /api/v1/certifications/items/{id}/decide ────────────────────────────

@router.post("/items/{item_id}/decide", response_model=CertificationItemResponse)
async def decide_item(
    item_id: str,
    body: ItemDecision,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CertificationItemResponse:
    """
    Reviewer certifies or revokes a line item.
    On REVOKE: the underlying RoleAssignment is immediately revoked.
    """
    realm_id = current_user["realm_id"]
    item = await db.get(CertificationItem, item_id)
    if not item or item.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Item not found")
    if item.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"Item is already {item.status}")

    # Reviewers can only decide their own items (admins can decide any)
    if item.reviewer_id != current_user["sub"] and not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="You are not the reviewer for this item")

    item.status = body.decision
    item.decision_comment = body.comment
    item.decided_at = datetime.now(timezone.utc)
    item.decided_by = current_user["sub"]

    # If REVOKED → immediately revoke the underlying assignment
    if body.decision == "REVOKED":
        assignment = await db.get(RoleAssignment, item.assignment_id)
        if assignment and assignment.status == "ACTIVE":
            assignment.status = "REVOKED"
            assignment.revoked_at = datetime.now(timezone.utc)
            assignment.revoked_by = current_user["sub"]
            assignment.revoke_reason = f"Revoked in certification campaign {item.campaign_id}"

    # Update campaign counters
    campaign = await db.get(CertificationCampaign, item.campaign_id)
    if campaign:
        if body.decision == "CERTIFIED":
            campaign.certified_items += 1
        elif body.decision == "REVOKED":
            campaign.revoked_items += 1

        # Auto-complete campaign if all items decided
        decided = campaign.certified_items + campaign.revoked_items
        if decided >= campaign.total_items:
            campaign.status = "COMPLETED"
            campaign.completed_at = datetime.now(timezone.utc)

    await write_audit(
        db, realm_id=realm_id,
        action=f"CERT_ITEM_{body.decision}",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="certification_item",
        target_id=item.identity_id,
        after_state={
            "campaign_id": item.campaign_id,
            "role_id": item.role_id,
            "decision": body.decision,
            "comment": body.comment,
        },
    )
    await db.commit()
    await db.refresh(item)
    return CertificationItemResponse.model_validate(item)


# ── POST /api/v1/certifications/{id}/cancel ──────────────────────────────────

@router.post("/{campaign_id}/cancel", response_model=CampaignResponse)
async def cancel_campaign(
    campaign_id: str,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> CampaignResponse:
    realm_id = current_user["realm_id"]
    campaign = await db.get(CertificationCampaign, campaign_id)
    if not campaign or campaign.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.status in ("COMPLETED", "CANCELLED"):
        raise HTTPException(status_code=400, detail=f"Campaign is already {campaign.status}")

    campaign.status = "CANCELLED"
    await write_audit(
        db, realm_id=realm_id, action="CERT_CAMPAIGN_CANCELLED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="certification_campaign",
        target_id=campaign.id, target_name=campaign.name,
    )
    await db.commit()
    await db.refresh(campaign)
    return CampaignResponse.model_validate(campaign)
