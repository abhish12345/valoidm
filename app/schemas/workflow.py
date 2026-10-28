from pydantic import BaseModel, field_validator
from datetime import datetime


class AccessRequestCreate(BaseModel):
    role_id: str
    target_identity_id: str | None = None  # None = self-request
    justification: str | None = None
    business_reason: str | None = None
    access_duration_days: int | None = None

    @field_validator("access_duration_days")
    @classmethod
    def positive_days(cls, v: int | None) -> int | None:
        if v is not None and v < 1:
            raise ValueError("access_duration_days must be positive")
        return v


class AccessRequestDecision(BaseModel):
    decision: str          # APPROVED | REJECTED
    comment: str | None = None

    @field_validator("decision")
    @classmethod
    def valid_decision(cls, v: str) -> str:
        if v not in ("APPROVED", "REJECTED"):
            raise ValueError("decision must be APPROVED or REJECTED")
        return v


class AccessRequestResponse(BaseModel):
    id: str
    realm_id: str
    requester_id: str
    target_identity_id: str
    role_id: str
    justification: str | None
    business_reason: str | None
    access_duration_days: int | None
    status: str
    approver_id: str | None
    approver_comment: str | None
    decided_at: datetime | None
    risk_score: float | None
    risk_factors: dict | None
    agent_recommendation: str | None
    sod_conflict: bool
    sod_detail: str | None
    created_at: datetime
    expires_at: datetime | None
    assignment_id: str | None

    model_config = {"from_attributes": True}


class AccessRequestListResponse(BaseModel):
    items: list[AccessRequestResponse]
    total: int
    pending_count: int
