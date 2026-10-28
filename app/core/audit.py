"""
Append-only audit log writer.
Call write_audit() from any router or service — never update/delete audit rows.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.audit import AuditLog


async def write_audit(
    db: AsyncSession,
    *,
    realm_id: str,
    action: str,
    actor_id: str | None = None,
    actor_username: str | None = None,
    actor_ip: str | None = None,
    resource_type: str | None = None,
    target_id: str | None = None,
    target_name: str | None = None,
    outcome: str = "SUCCESS",
    detail: str | None = None,
    before_state: dict | None = None,
    after_state: dict | None = None,
    request_id: str | None = None,
    agent_name: str | None = None,
    agent_reasoning: str | None = None,
) -> AuditLog:
    log = AuditLog(
        id=str(uuid.uuid4()),
        realm_id=realm_id,
        action=action,
        actor_id=actor_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        resource_type=resource_type,
        target_id=target_id,
        target_name=target_name,
        outcome=outcome,
        detail=detail,
        before_state=before_state,
        after_state=after_state,
        request_id=request_id,
        agent_name=agent_name,
        agent_reasoning=agent_reasoning,
        created_at=datetime.now(timezone.utc),
    )
    db.add(log)
    # flush immediately so the log is written even if the outer tx rolls back later
    await db.flush()
    return log
