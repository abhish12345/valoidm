from pydantic import BaseModel, field_validator
from datetime import datetime
from typing import Any


ROLE_TYPES = {"BUSINESS", "TECHNICAL", "SYSTEM"}


class RoleCreate(BaseModel):
    name: str
    description: str | None = None
    role_type: str = "BUSINESS"
    parent_id: str | None = None
    owner_id: str | None = None
    is_requestable: bool = True
    requires_approval: bool = True

    @field_validator("role_type")
    @classmethod
    def valid_type(cls, v: str) -> str:
        if v not in ROLE_TYPES:
            raise ValueError(f"role_type must be one of {ROLE_TYPES}")
        return v

    @field_validator("name")
    @classmethod
    def clean_name(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2:
            raise ValueError("name must be at least 2 characters")
        return v


class RoleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    owner_id: str | None = None
    is_active: bool | None = None
    is_requestable: bool | None = None
    requires_approval: bool | None = None


class RoleResponse(BaseModel):
    id: str
    realm_id: str
    name: str
    description: str | None
    role_type: str
    parent_id: str | None
    owner_id: str | None
    is_active: bool
    is_requestable: bool
    requires_approval: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class RoleConflictCreate(BaseModel):
    role_a_id: str
    role_b_id: str
    description: str | None = None


class RoleConflictResponse(BaseModel):
    id: str
    realm_id: str
    role_a_id: str
    role_b_id: str
    description: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AssignRoleRequest(BaseModel):
    role_id: str
    valid_from: datetime | None = None
    valid_until: datetime | None = None


class RevokeRoleRequest(BaseModel):
    reason: str | None = None


class RoleAssignmentResponse(BaseModel):
    id: str
    realm_id: str
    identity_id: str
    role_id: str
    status: str
    assigned_by: str | None
    assigned_at: datetime
    valid_from: datetime | None
    valid_until: datetime | None
    revoked_at: datetime | None
    revoke_reason: str | None

    model_config = {"from_attributes": True}


class SoDCheckResult(BaseModel):
    has_conflict: bool
    conflicting_role_ids: list[str] = []
    detail: str | None = None
