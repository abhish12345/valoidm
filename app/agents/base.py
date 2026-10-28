"""
Base agent infrastructure shared by all ValoIDM agents.
- BaseAgentState: common TypedDict all agents extend
- AgentResult: structured output every agent returns
- write_agent_audit: writes agent decisions to the audit log
- Guardrail: checks that run BEFORE any agent acts
"""
import uuid
from datetime import datetime, timezone
from typing import TypedDict, Any
from sqlalchemy.ext.asyncio import AsyncSession


# ── Shared state schema ───────────────────────────────────────────────────────

class BaseAgentState(TypedDict):
    """Fields every agent carries through its graph."""
    realm_id:       str
    actor_id:       str          # identity ID of the user who triggered the agent
    actor_username: str
    request_id:     str          # correlation ID for this agent run
    input:          str          # natural-language input or JSON trigger
    messages:       list         # LangChain message history
    reasoning:      str          # LLM reasoning trace (written to audit)
    decision:       str | None   # final decision text
    confidence:     float        # 0.0 – 1.0
    requires_human: bool         # True = escalate to human before acting
    error:          str | None   # set if the agent hit an unrecoverable error
    audit_written:  bool         # True once audit log entry created


# ── Structured result every agent returns ─────────────────────────────────────

class AgentResult:
    def __init__(
        self,
        decision: str,
        reasoning: str,
        confidence: float = 1.0,
        requires_human: bool = False,
        data: dict | None = None,
        error: str | None = None,
    ):
        self.decision       = decision
        self.reasoning      = reasoning
        self.confidence     = confidence
        self.requires_human = requires_human
        self.data           = data or {}
        self.error          = error
        self.request_id     = str(uuid.uuid4())
        self.created_at     = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "decision":       self.decision,
            "reasoning":      self.reasoning,
            "confidence":     self.confidence,
            "requires_human": self.requires_human,
            "data":           self.data,
            "error":          self.error,
            "request_id":     self.request_id,
            "created_at":     self.created_at.isoformat(),
        }


# ── Audit writer for agent decisions ─────────────────────────────────────────

async def write_agent_audit(
    db: AsyncSession,
    realm_id: str,
    actor_id: str,
    actor_username: str,
    agent_name: str,
    action: str,
    target_id: str | None,
    result: AgentResult,
    request_id: str | None = None,
) -> None:
    """Write every agent decision + reasoning to the append-only audit log."""
    from app.core.audit import write_audit
    await write_audit(
        db,
        realm_id=realm_id,
        action=action,
        actor_id=actor_id,
        actor_username=actor_username,
        resource_type="agent_decision",
        target_id=target_id,
        outcome="SUCCESS" if not result.error else "FAILURE",
        detail=result.decision[:500] if result.decision else None,
        after_state=result.data,
        request_id=request_id or result.request_id,
        agent_name=agent_name,
        agent_reasoning=result.reasoning[:2000] if result.reasoning else None,
    )


# ── Guardrails ────────────────────────────────────────────────────────────────

class GuardrailViolation(Exception):
    """Raised when a guardrail check blocks the agent."""
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


async def check_realm_isolation(
    db: AsyncSession,
    realm_id: str,
    resource_realm_id: str,
) -> None:
    """Ensure the agent is not crossing tenant boundaries."""
    if realm_id != resource_realm_id:
        raise GuardrailViolation(
            f"Tenant isolation violation: agent realm '{realm_id}' "
            f"cannot access resource in realm '{resource_realm_id}'"
        )


async def check_not_auth_path(action: str) -> None:
    """The agent must never touch the ValoAuth authentication path."""
    blocked_actions = {"login", "mfa", "token", "jwt", "password_reset", "session"}
    action_lower = action.lower()
    for blocked in blocked_actions:
        if blocked in action_lower:
            raise GuardrailViolation(
                f"Auth path guardrail: agents cannot perform '{action}'. "
                "Authentication is handled by ValoAuth exclusively."
            )


def low_confidence_requires_human(confidence: float, threshold: float = 0.75) -> bool:
    """Returns True if confidence is below threshold — must escalate to human."""
    return confidence < threshold
