"""
Agent API endpoints — exposes all LangGraph agents via REST.
Agents run asynchronously; every decision is audit-logged.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user

router = APIRouter(prefix="/agents", tags=["agents"])


# ── Schemas ────────────────────────────────────────────────────────────────────

class AuditQueryRequest(BaseModel):
    query: str   # natural-language question


class CorrelationRequest(BaseModel):
    incoming_record: dict   # {username, email, first_name, last_name, employee_id}
    phase_c_enabled: bool = False


class ApprovalRiskRequest(BaseModel):
    access_request_id:   str
    role_id:             str
    requester_id:        str
    target_identity_id:  str
    sod_conflict:        bool = False


# ── Audit Query Agent ─────────────────────────────────────────────────────────

@router.post("/audit-query")
async def audit_query(
    body: AuditQueryRequest,
    current_user: dict = Depends(get_current_user),
) -> dict:
    """
    Ask a natural-language question about the audit log.
    Phase A — read-only. No state changes.

    Example queries:
      - "Show me all failed logins in the last 7 days"
      - "Which users had roles assigned and revoked on the same day?"
      - "What did admin do yesterday?"
    """
    from app.agents.audit_query import run_audit_query
    result = await run_audit_query(
        query=body.query,
        realm_id=current_user["realm_id"],
        actor_id=current_user["sub"],
        actor_username=current_user["username"],
    )
    return result


# ── Correlation Agent ─────────────────────────────────────────────────────────

@router.post("/correlation")
async def correlation_score(
    body: CorrelationRequest,
    current_user: dict = Depends(get_current_user),
) -> dict:
    """
    Score an incoming identity record against existing identities.
    Phase A: returns recommendation only.
    Phase C (phase_c_enabled=true): auto-resolves high-confidence matches.

    Example:
      { "incoming_record": {"username": "j.doe", "email": "john.doe@corp.com",
                            "first_name": "John", "last_name": "Doe"} }
    """
    from app.agents.correlation import run_correlation
    result = await run_correlation(
        incoming_record=body.incoming_record,
        realm_id=current_user["realm_id"],
        actor_id=current_user["sub"],
        actor_username=current_user["username"],
        phase_c_enabled=body.phase_c_enabled,
    )
    return result


# ── Approval Risk Agent ───────────────────────────────────────────────────────

@router.post("/approval-risk")
async def approval_risk(
    body: ApprovalRiskRequest,
    current_user: dict = Depends(get_current_user),
) -> dict:
    """
    Risk-score an access request.
    Returns risk_score (0.0-1.0) and recommendation (APPROVE/ESCALATE/DENY).
    Phase B — approver still decides; this agent surfaces context only.
    """
    from app.agents.approval_risk import run_approval_risk
    result = await run_approval_risk(
        access_request_id=body.access_request_id,
        role_id=body.role_id,
        requester_id=body.requester_id,
        target_identity_id=body.target_identity_id,
        realm_id=current_user["realm_id"],
        actor_id=current_user["sub"],
        actor_username=current_user["username"],
        sod_conflict=body.sod_conflict,
    )
    return result


# ── Agent health check ────────────────────────────────────────────────────────

@router.get("/health")
async def agents_health(current_user: dict = Depends(get_current_user)) -> dict:
    """Check Ollama connectivity and list available agents."""
    from app.agents.llm import get_llm
    from app.core.config import settings
    import httpx

    ollama_ok = False
    models    = []
    try:
        r = httpx.get(f"{settings.OLLAMA_BASE_URL}/api/tags", timeout=3)
        if r.status_code < 300:
            ollama_ok = True
            models    = [m["name"] for m in r.json().get("models", [])]
    except Exception:
        pass

    return {
        "ollama_reachable":  ollama_ok,
        "ollama_url":        settings.OLLAMA_BASE_URL,
        "configured_model":  settings.OLLAMA_MODEL,
        "model_available":   settings.OLLAMA_MODEL in models if ollama_ok else False,
        "available_models":  models,
        "agents": [
            {"name": "audit_query",    "phase": "A", "mode": "read-only"},
            {"name": "correlation",    "phase": "A/C", "mode": "advisory/auto-resolve"},
            {"name": "approval_risk",  "phase": "B", "mode": "risk-scoring only"},
        ],
    }
