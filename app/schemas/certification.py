from pydantic import BaseModel, field_validator
from datetime import datetime


class CampaignCreate(BaseModel):
    name: str
    description: str | None = None
    due_date: datetime | None = None

    @field_validator("name")
    @classmethod
    def clean(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3:
            raise ValueError("name must be at least 3 characters")
        return v


class CampaignResponse(BaseModel):
    id: str
    realm_id: str
    name: str
    description: str | None
    status: str
    created_by: str
    due_date: datetime | None
    total_items: int
    certified_items: int
    revoked_items: int
    created_at: datetime
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class CertificationItemResponse(BaseModel):
    id: str
    campaign_id: str
    realm_id: str
    identity_id: str
    role_id: str
    assignment_id: str
    reviewer_id: str
    status: str
    decision_comment: str | None
    decided_at: datetime | None
    decided_by: str | None
    agent_recommendation: str | None
    agent_risk_score: float | None
    agent_reasoning: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ItemDecision(BaseModel):
    decision: str        # CERTIFIED | REVOKED
    comment: str | None = None

    @field_validator("decision")
    @classmethod
    def valid(cls, v: str) -> str:
        if v not in ("CERTIFIED", "REVOKED"):
            raise ValueError("decision must be CERTIFIED or REVOKED")
        return v
