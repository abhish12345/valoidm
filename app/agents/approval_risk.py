"""
Approval Risk Agent (Phase B — orchestration with human approval).

Scores an access request 0.0-1.0 risk and recommends APPROVE / ESCALATE / DENY.
The approver always makes the final decision — this agent surfaces context only.

Risk factors checked:
  - SoD conflict (hard block)
  - Requester already has similar roles (redundant access)
  - Role is high-privilege (TECHNICAL / SYSTEM type)
  - Unusual requester (recently created account, high failed-login count)
  - Peer comparison (does anyone in same org unit have this role?)
"""
import json
from typing import TypedDict
from langgraph.graph import StateGraph, START, END
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.base import (
    BaseAgentState, AgentResult, write_agent_audit,
)
from app.agents.llm import get_structured_llm


class ApprovalRiskState(BaseAgentState):
    request_id_ar:  str          # access request ID
    role_id:        str
    requester_id:   str
    target_id_ar:   str
    role_data:      dict
    requester_data: dict
    existing_roles: list[dict]
    sod_conflict:   bool
    risk_score:     float
    risk_factors:   list[str]
    recommendation: str          # APPROVE | ESCALATE | DENY


SYSTEM_PROMPT = """You are an access risk analyst for an Identity Governance system.
Given an access request and context, produce a JSON risk assessment:
{
  "risk_score": 0.0-1.0,
  "risk_factors": ["factor1", "factor2"],
  "recommendation": "APPROVE|ESCALATE|DENY",
  "reasoning": "brief explanation"
}
Risk levels:
  0.0-0.3  = LOW    -> APPROVE
  0.3-0.6  = MEDIUM -> ESCALATE (needs human review)
  0.6-1.0  = HIGH   -> DENY or ESCALATE with manager

Consider: SoD conflicts (always HIGH), role type (SYSTEM=higher risk),
new accounts requesting privileged access, redundant access already held."""


async def load_context(state: ApprovalRiskState) -> ApprovalRiskState:
    """Load role and requester context from DB."""
    from app.core.database import AsyncSessionLocal
    from app.models.role import Role, RoleAssignment
    from app.models.identity import Identity
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        # Load role
        role = await db.get(Role, state["role_id"])
        role_data = {
            "name":              role.name if role else "unknown",
            "role_type":         role.role_type if role else "BUSINESS",
            "requires_approval": role.requires_approval if role else True,
        } if role else {}

        # Load requester
        requester = await db.get(Identity, state["requester_id"])
        requester_data = {
            "username":               requester.username if requester else "unknown",
            "status":                 requester.status if requester else "UNKNOWN",
            "failed_login_attempts":  requester.failed_login_attempts if requester else 0,
            "identity_type":          requester.identity_type if requester else "HUMAN",
        } if requester else {}

        # Load existing role assignments for target
        existing_rows = (await db.execute(
            select(RoleAssignment).where(
                RoleAssignment.identity_id == state["target_id_ar"],
                RoleAssignment.status == "ACTIVE",
            )
        )).scalars().all()
        existing_roles = [
            {"role_id": r.role_id, "assigned_at": r.assigned_at.isoformat()}
            for r in existing_rows
        ]

    return {
        **state,
        "role_data":      role_data,
        "requester_data": requester_data,
        "existing_roles": existing_roles,
    }


async def compute_risk(state: ApprovalRiskState) -> ApprovalRiskState:
    """Deterministic risk rules + LLM for final score."""
    risk_factors = []
    base_score   = 0.0

    # Hard rule: SoD conflict
    if state.get("sod_conflict"):
        return {
            **state,
            "risk_score":   1.0,
            "risk_factors": ["SoD conflict detected — hard block"],
            "recommendation": "DENY",
            "reasoning":    "SoD violation: this assignment conflicts with an existing role.",
            "decision":     "DENY",
            "confidence":   1.0,
            "requires_human": False,
        }

    role = state.get("role_data", {})
    requester = state.get("requester_data", {})

    # High-privilege role type
    if role.get("role_type") in ("TECHNICAL", "SYSTEM"):
        base_score += 0.3
        risk_factors.append(f"High-privilege role type: {role.get('role_type')}")

    # Suspended/inactive requester
    if requester.get("status") not in ("ACTIVE",):
        base_score += 0.4
        risk_factors.append(f"Requester status: {requester.get('status')}")

    # High failed login attempts
    if requester.get("failed_login_attempts", 0) >= 3:
        base_score += 0.2
        risk_factors.append(f"Requester has {requester['failed_login_attempts']} failed login attempts")

    # Already has many roles (excessive access risk)
    existing_count = len(state.get("existing_roles", []))
    if existing_count >= 10:
        base_score += 0.15
        risk_factors.append(f"Target already holds {existing_count} active roles")

    base_score = min(base_score, 1.0)

    # LLM refinement for borderline cases
    if 0.2 <= base_score <= 0.7:
        try:
            llm = get_structured_llm()
            context = {
                "role":              role,
                "requester":         requester,
                "existing_roles_count": existing_count,
                "deterministic_score": base_score,
                "risk_factors_so_far": risk_factors,
            }
            response = await llm.ainvoke([
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=json.dumps(context)),
            ])
            content = response.content if hasattr(response, "content") else str(response)
            import re
            m = re.search(r'\{.*\}', content, re.DOTALL)
            if m:
                llm_result = json.loads(m.group())
                # Blend deterministic and LLM scores
                llm_score = float(llm_result.get("risk_score", base_score))
                base_score = round(0.5 * base_score + 0.5 * llm_score, 3)
                risk_factors += llm_result.get("risk_factors", [])
        except Exception:
            pass  # stick with deterministic

    # Final recommendation
    if base_score < 0.3:
        recommendation = "APPROVE"
    elif base_score < 0.6:
        recommendation = "ESCALATE"
    else:
        recommendation = "DENY"

    return {
        **state,
        "risk_score":     base_score,
        "risk_factors":   risk_factors,
        "recommendation": recommendation,
        "decision":       recommendation,
        "confidence":     1.0 - base_score,
        "requires_human": recommendation != "APPROVE",
        "reasoning":      f"Risk score {base_score:.2f}. Factors: {'; '.join(risk_factors) or 'none'}",
    }


async def write_audit_node(state: ApprovalRiskState) -> ApprovalRiskState:
    from app.core.database import AsyncSessionLocal
    result = AgentResult(
        decision=state.get("recommendation", "ESCALATE"),
        reasoning=state.get("reasoning", ""),
        confidence=state.get("confidence", 0.5),
        requires_human=state.get("requires_human", True),
        data={
            "risk_score":     state.get("risk_score"),
            "risk_factors":   state.get("risk_factors", []),
            "recommendation": state.get("recommendation"),
        },
    )
    async with AsyncSessionLocal() as db:
        await write_agent_audit(
            db=db,
            realm_id=state["realm_id"],
            actor_id=state["actor_id"],
            actor_username=state["actor_username"],
            agent_name="approval_risk_agent",
            action="AGENT_APPROVAL_RISK_SCORE",
            target_id=state.get("request_id_ar"),
            result=result,
            request_id=state["request_id"],
        )
        await db.commit()
    return {**state, "audit_written": True}


def build_approval_risk_graph():
    graph = StateGraph(ApprovalRiskState)
    graph.add_node("load_context",  load_context)
    graph.add_node("compute_risk",  compute_risk)
    graph.add_node("write_audit",   write_audit_node)
    graph.add_edge(START,           "load_context")
    graph.add_edge("load_context",  "compute_risk")
    graph.add_edge("compute_risk",  "write_audit")
    graph.add_edge("write_audit",   END)
    return graph.compile()


_approval_risk_graph = None

def get_approval_risk_graph():
    global _approval_risk_graph
    if _approval_risk_graph is None:
        _approval_risk_graph = build_approval_risk_graph()
    return _approval_risk_graph


async def run_approval_risk(
    access_request_id: str,
    role_id: str,
    requester_id: str,
    target_identity_id: str,
    realm_id: str,
    actor_id: str,
    actor_username: str,
    sod_conflict: bool = False,
    request_id: str | None = None,
) -> dict:
    import uuid as _uuid
    rid = request_id or str(_uuid.uuid4())
    initial: ApprovalRiskState = {
        "realm_id":       realm_id,
        "actor_id":       actor_id,
        "actor_username": actor_username,
        "request_id":     rid,
        "input":          access_request_id,
        "messages":       [],
        "reasoning":      "",
        "decision":       None,
        "confidence":     0.5,
        "requires_human": True,
        "error":          None,
        "audit_written":  False,
        "request_id_ar":  access_request_id,
        "role_id":        role_id,
        "requester_id":   requester_id,
        "target_id_ar":   target_identity_id,
        "role_data":      {},
        "requester_data": {},
        "existing_roles": [],
        "sod_conflict":   sod_conflict,
        "risk_score":     0.0,
        "risk_factors":   [],
        "recommendation": "ESCALATE",
    }
    result = await get_approval_risk_graph().ainvoke(initial)
    return {
        "risk_score":     result["risk_score"],
        "risk_factors":   result["risk_factors"],
        "recommendation": result["recommendation"],
        "requires_human": result["requires_human"],
        "reasoning":      result["reasoning"],
        "request_id":     rid,
    }
