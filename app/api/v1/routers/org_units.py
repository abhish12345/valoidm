import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user, get_current_admin
from app.core.audit import write_audit
from app.models.org_unit import OrgUnit
from app.schemas.identity import OrgUnitCreate, OrgUnitResponse, OrgUnitTreeNode

router = APIRouter(prefix="/org-units", tags=["org-units"])


def _ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")


@router.get("", response_model=list[OrgUnitResponse])
async def list_org_units(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[OrgUnitResponse]:
    realm_id = current_user["realm_id"]
    rows = (await db.execute(
        select(OrgUnit).where(OrgUnit.realm_id == realm_id).order_by(OrgUnit.name)
    )).scalars().all()
    return [OrgUnitResponse.model_validate(r) for r in rows]


@router.get("/tree", response_model=list[OrgUnitTreeNode])
async def org_tree(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[OrgUnitTreeNode]:
    """Return the full org hierarchy as a nested tree."""
    realm_id = current_user["realm_id"]
    all_units = (await db.execute(
        select(OrgUnit).where(OrgUnit.realm_id == realm_id)
    )).scalars().all()

    # Build lookup and tree
    by_id: dict[str, OrgUnitTreeNode] = {}
    for u in all_units:
        by_id[u.id] = OrgUnitTreeNode(
            id=u.id, name=u.name, code=u.code, parent_id=u.parent_id
        )

    roots: list[OrgUnitTreeNode] = []
    for node in by_id.values():
        if node.parent_id and node.parent_id in by_id:
            by_id[node.parent_id].children.append(node)
        else:
            roots.append(node)

    return roots


@router.post("", response_model=OrgUnitResponse, status_code=201)
async def create_org_unit(
    body: OrgUnitCreate,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> OrgUnitResponse:
    realm_id = current_user["realm_id"]

    if body.parent_id:
        parent = await db.get(OrgUnit, body.parent_id)
        if not parent or parent.realm_id != realm_id:
            raise HTTPException(status_code=404, detail="Parent org unit not found")

    unit = OrgUnit(
        id=str(uuid.uuid4()),
        realm_id=realm_id,
        name=body.name,
        code=body.code,
        description=body.description,
        parent_id=body.parent_id,
        manager_id=body.manager_id,
    )
    db.add(unit)

    await write_audit(
        db, realm_id=realm_id, action="ORG_UNIT_CREATED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="org_unit",
        target_id=unit.id, target_name=unit.name,
        after_state={"name": unit.name, "parent_id": unit.parent_id},
    )
    await db.commit()
    await db.refresh(unit)
    return OrgUnitResponse.model_validate(unit)


@router.delete("/{unit_id}", status_code=204)
async def delete_org_unit(
    unit_id: str,
    request: Request,
    current_user: dict = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    realm_id = current_user["realm_id"]
    unit = await db.get(OrgUnit, unit_id)
    if not unit or unit.realm_id != realm_id:
        raise HTTPException(status_code=404, detail="Org unit not found")

    # Check for children
    children = (await db.execute(
        select(OrgUnit).where(OrgUnit.parent_id == unit_id)
    )).scalars().first()
    if children:
        raise HTTPException(status_code=409, detail="Cannot delete org unit with children")

    await write_audit(
        db, realm_id=realm_id, action="ORG_UNIT_DELETED",
        actor_id=current_user["sub"], actor_username=current_user["username"],
        actor_ip=_ip(request), resource_type="org_unit",
        target_id=unit.id, target_name=unit.name,
    )
    await db.delete(unit)
    await db.commit()
