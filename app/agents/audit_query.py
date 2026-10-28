"""
Audit Query Agent (Phase A — read-only).

Takes a natural-language question about the audit log and returns:
  - relevant audit events
  - a natural-language answer
  - anomaly flags if suspicious patterns detected

This agent NEVER writes or changes any state.
"""
import json
from typing import TypedDict
from langgraph.graph import StateGraph, START, END
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

from app.agents.base import BaseAgentState, AgentResult, write_agent_audit
from app.agents.llm import get_llm


# ── State ──────────────────────────────────────────────────────────────────────

class AuditQueryState(BaseAgentState):
    query:          str          # NL question
    raw_events:     list[dict]   # fetched from DB
    anomalies:      list[str]    # detected anomaly descriptions
    answer:         str          # NL answer


SYSTEM_PROMPT = """You are an Identity Governance audit analyst for ValoIDM.
You have been given a set of audit log events. Your job is to:
1. Answer the user's question about the audit events clearly and concisely.
2. Identify any anomalies, suspicious patterns, or policy violations.
3. Be specific: name users, actions, timestamps from the data.
4. If no events match the query, say so clearly.
5. Never make up events — only use the provided data.
6. Format your response as plain text with sections: ANSWER and ANOMALIES."""


# ── Graph nodes ───────────────────────────────────────────────────────────────

async def fetch_events(state: AuditQueryState) -> AuditQueryState:
    """Fetch relevant audit events from DB based on the query."""
    from app.core.database import AsyncSessionLocal
    from app.models.audit import AuditLog
    from sqlalchemy import select, or_
    import re

    query_lower = state["query"].lower()

    async with AsyncSessionLocal() as db:
        q = select(AuditLog).where(AuditLog.realm_id == state["realm_id"])

        # Simple keyword extraction from NL query
        # User mentioned
        user_match = re.search(r"\buser\s+(\w[\w.]+)", query_lower)
        if user_match:
            name = user_match.group(1)
            q = q.where(
                or_(
                    AuditLog.actor_username.ilike(f"%{name}%"),
                    AuditLog.target_name.ilike(f"%{name}%"),
                )
            )

        # Action type keywords
        action_keywords = {
            "login": "LOGIN", "role": "ROLE", "certif": "CERT",
            "assign": "ASSIGN", "revoke": "REVOKE", "fail": "FAIL",
            "terminat": "TERMINAT", "creat": "CREAT", "delet": "DELET",
            "request": "REQUEST", "approv": "APPROV", "scim": "SCIM",
        }
        for keyword, action_frag in action_keywords.items():
            if keyword in query_lower:
                q = q.where(AuditLog.action.ilike(f"%{action_frag}%"))
                break

        # Failure filter
        if "fail" in query_lower or "denied" in query_lower or "error" in query_lower:
            q = q.where(AuditLog.outcome == "FAILURE")

        events = (
            await db.execute(q.order_by(AuditLog.created_at.desc()).limit(50))
        ).scalars().all()

        raw = [
            {
                "id":             e.id,
                "action":         e.action,
                "actor":          e.actor_username or "system",
                "target":         e.target_name or e.target_id or "",
                "outcome":        e.outcome,
                "resource_type":  e.resource_type or "",
                "detail":         e.detail or "",
                "created_at":     e.created_at.isoformat(),
            }
            for e in events
        ]

    return {**state, "raw_events": raw}


async def analyse_with_llm(state: AuditQueryState) -> AuditQueryState:
    """Use the LLM to answer the NL question based on the fetched events."""
    llm = get_llm(temperature=0.1)

    events_text = json.dumps(state["raw_events"][:30], indent=2)
    if not state["raw_events"]:
        events_text = "No audit events matched your query."

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=(
            f"QUESTION: {state['query']}\n\n"
            f"AUDIT EVENTS ({len(state['raw_events'])} total, showing up to 30):\n"
            f"{events_text}"
        )),
    ]

    try:
        response = await llm.ainvoke(messages)
        content = response.content if hasattr(response, "content") else str(response)
    except Exception as exc:
        content = f"LLM unavailable: {exc}. Raw events returned above."

    return {
        **state,
        "answer": content,
        "reasoning": f"Fetched {len(state['raw_events'])} events, analysed with LLM.",
        "messages": [*state.get("messages", []), AIMessage(content=content)],
    }


async def detect_anomalies(state: AuditQueryState) -> AuditQueryState:
    """Detect simple anomaly patterns without LLM (deterministic rules)."""
    anomalies = []
    events = state["raw_events"]

    # Rule 1: >5 failed logins for same user
    fail_counts: dict[str, int] = {}
    for e in events:
        if "LOGIN_FAILED" in e["action"]:
            actor = e["actor"]
            fail_counts[actor] = fail_counts.get(actor, 0) + 1
    for user, count in fail_counts.items():
        if count >= 5:
            anomalies.append(
                f"SUSPICIOUS: {count} failed login attempts for '{user}'"
            )

    # Rule 2: Role assigned AND revoked same day for same user
    assigns: dict[str, set] = {}
    revokes: dict[str, set] = {}
    for e in events:
        day = e["created_at"][:10]
        if "ROLE_ASSIGNED" in e["action"]:
            assigns.setdefault(e["actor"], set()).add(day)
        if "ROLE_REVOKED" in e["action"]:
            revokes.setdefault(e["actor"], set()).add(day)
    for user in set(assigns) & set(revokes):
        overlap = assigns[user] & revokes[user]
        if overlap:
            anomalies.append(
                f"SUSPICIOUS: '{user}' had roles assigned AND revoked on {list(overlap)}"
            )

    # Rule 3: Admin account used outside business hours (00:00–06:00 UTC)
    for e in events:
        if e.get("actor", "").startswith("admin"):
            hour = int(e["created_at"][11:13])
            if 0 <= hour < 6:
                anomalies.append(
                    f"UNUSUAL: Admin action '{e['action']}' at {e['created_at'][:19]} UTC (off-hours)"
                )
                break  # only flag once

    return {**state, "anomalies": anomalies}


async def write_audit_node(state: AuditQueryState) -> AuditQueryState:
    """Write agent decision to audit log."""
    from app.core.database import AsyncSessionLocal
    result = AgentResult(
        decision=state.get("answer", "")[:200],
        reasoning=state.get("reasoning", ""),
        confidence=1.0,
        requires_human=False,
        data={
            "events_fetched": len(state.get("raw_events", [])),
            "anomalies":      state.get("anomalies", []),
        },
    )
    async with AsyncSessionLocal() as db:
        await write_agent_audit(
            db=db,
            realm_id=state["realm_id"],
            actor_id=state["actor_id"],
            actor_username=state["actor_username"],
            agent_name="audit_query_agent",
            action="AGENT_AUDIT_QUERY",
            target_id=None,
            result=result,
            request_id=state["request_id"],
        )
        await db.commit()

    return {**state, "audit_written": True, "decision": result.decision}


# ── Build graph ───────────────────────────────────────────────────────────────

def build_audit_query_graph() -> StateGraph:
    graph = StateGraph(AuditQueryState)

    graph.add_node("fetch_events",     fetch_events)
    graph.add_node("detect_anomalies", detect_anomalies)
    graph.add_node("analyse_with_llm", analyse_with_llm)
    graph.add_node("write_audit",      write_audit_node)

    graph.add_edge(START,             "fetch_events")
    graph.add_edge("fetch_events",    "detect_anomalies")
    graph.add_edge("detect_anomalies","analyse_with_llm")
    graph.add_edge("analyse_with_llm","write_audit")
    graph.add_edge("write_audit",     END)

    return graph.compile()


# Singleton compiled graph
_audit_query_graph = None


def get_audit_query_graph():
    global _audit_query_graph
    if _audit_query_graph is None:
        _audit_query_graph = build_audit_query_graph()
    return _audit_query_graph


# ── Public entry point ────────────────────────────────────────────────────────

async def run_audit_query(
    query: str,
    realm_id: str,
    actor_id: str,
    actor_username: str,
    request_id: str | None = None,
) -> dict:
    """
    Run the Audit Query Agent.
    Returns: { answer, anomalies, events_fetched, request_id }
    """
    import uuid as _uuid
    rid = request_id or str(_uuid.uuid4())

    initial_state: AuditQueryState = {
        "realm_id":       realm_id,
        "actor_id":       actor_id,
        "actor_username": actor_username,
        "request_id":     rid,
        "input":          query,
        "query":          query,
        "messages":       [],
        "reasoning":      "",
        "decision":       None,
        "confidence":     1.0,
        "requires_human": False,
        "error":          None,
        "audit_written":  False,
        "raw_events":     [],
        "anomalies":      [],
        "answer":         "",
    }

    graph  = get_audit_query_graph()
    result = await graph.ainvoke(initial_state)

    return {
        "answer":         result.get("answer", ""),
        "anomalies":      result.get("anomalies", []),
        "events_fetched": len(result.get("raw_events", [])),
        "request_id":     rid,
    }
