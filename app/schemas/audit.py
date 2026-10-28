from pydantic import BaseModel
from datetime import datetime


class AuditLogResponse(BaseModel):
    id: str
    realm_id: str
    action: str
    actor_id: str | None
    actor_username: str | None
    actor_ip: str | None
    resource_type: str | None
    target_id: str | None
    target_name: str | None
    outcome: str
    detail: str | None
    before_state: dict | None
    after_state: dict | None
    request_id: str | None
    agent_name: str | None
    agent_reasoning: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditLogListResponse(BaseModel):
    items: list[AuditLogResponse]
    total: int
    page: int
    page_size: int
