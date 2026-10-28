from pydantic import BaseModel, field_validator
from datetime import datetime
from typing import Any


VALID_TYPES   = {"HUMAN", "SERVICE", "BOT", "CONTRACTOR"}
VALID_STATUSES = {
    "ACTIVE", "INACTIVE", "LOCKED", "SUSPENDED",
    "PRE_HIRE", "ON_LEAVE", "TERMINATED", "ARCHIVED",
}


class IdentityCreate(BaseModel):
    username: str
    email: str
    password: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    identity_type: str = "HUMAN"
    employee_id: str | None = None
    attributes: dict = {}

    @field_validator("username")
    @classmethod
    def clean_username(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) < 2:
            raise ValueError("username must be at least 2 characters")
        return v

    @field_validator("identity_type")
    @classmethod
    def valid_type(cls, v: str) -> str:
        if v not in VALID_TYPES:
            raise ValueError(f"identity_type must be one of {VALID_TYPES}")
        return v


class IdentityUpdate(BaseModel):
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    display_name: str | None = None
    employee_id: str | None = None
    identity_type: str | None = None
    attributes: dict | None = None

    @field_validator("identity_type")
    @classmethod
    def valid_type(cls, v: str | None) -> str | None:
        if v and v not in VALID_TYPES:
            raise ValueError(f"identity_type must be one of {VALID_TYPES}")
        return v


class IdentityResponse(BaseModel):
    id: str
    realm_id: str
    username: str
    email: str
    display_name: str
    first_name: str | None
    last_name: str | None
    identity_type: str
    status: str
    employee_id: str | None
    is_admin: bool
    mfa_enabled: bool
    legal_hold: bool
    last_login_at: datetime | None
    created_at: datetime
    updated_at: datetime
    attributes: dict

    model_config = {"from_attributes": True}


class IdentityListResponse(BaseModel):
    items: list[IdentityResponse]
    total: int
    page: int
    page_size: int
    pages: int


# ── Lifecycle schemas ─────────────────────────────────────────────────────────

class JoinRequest(BaseModel):
    """Onboard a new joiner."""
    username: str
    email: str
    first_name: str | None = None
    last_name: str | None = None
    employee_id: str | None = None
    start_date: datetime | None = None
    org_unit_id: str | None = None
    attributes: dict = {}


class MoveRequest(BaseModel):
    """Transfer identity to a new department/role."""
    new_org_unit_id: str | None = None
    new_manager_id: str | None = None
    new_employee_id: str | None = None
    reason: str | None = None


class LeaveRequest(BaseModel):
    """Put identity on leave of absence."""
    expected_return_date: datetime | None = None
    reason: str | None = None


class TerminateRequest(BaseModel):
    """Terminate identity immediately."""
    reason: str | None = None
    revoke_access: bool = True     # revoke all roles + downstream accounts


# ── OrgUnit schemas ───────────────────────────────────────────────────────────

class OrgUnitCreate(BaseModel):
    name: str
    code: str | None = None
    description: str | None = None
    parent_id: str | None = None
    manager_id: str | None = None


class OrgUnitResponse(BaseModel):
    id: str
    realm_id: str
    name: str
    code: str | None
    description: str | None
    parent_id: str | None
    manager_id: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class OrgUnitTreeNode(BaseModel):
    id: str
    name: str
    code: str | None
    parent_id: str | None
    children: list["OrgUnitTreeNode"] = []

    model_config = {"from_attributes": True}


OrgUnitTreeNode.model_rebuild()
