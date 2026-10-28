"""
Correlation Agent (Phase A advisory / Phase C selective autonomy).

Takes an incoming identity record (from sync) and:
1. Searches the identity store for candidate matches
2. Scores each candidate (0.0-1.0 confidence)
3. HIGH confidence (>=0.85) -> auto-resolve (Phase C)
4. LOW confidence (<0.85)   -> escalate to human review queue

Never creates, updates, or deletes identities without human confirmation
unless confidence >= 0.85 and Phase C mode is explicitly enabled.
"""
import json
import difflib
from typing import TypedDict
from langgraph.graph import StateGraph, START, END
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.base import (
    BaseAgentState, AgentResult,
    write_agent_audit, low_confidence_requires_human,
)
from app.agents.llm import get_structured_llm


AUTO_RESOLVE_THRESHOLD = 0.85   # confidence needed for Phase C auto-resolve
ESCALATE_THRESHOLD     = 0.50   # below this -> definitely needs human


class CorrelationState(BaseAgentState):
    incoming_record:    dict         # {username, email, first_name, last_name, employee_id, ...}
    candidates:         list[dict]   # existing identities that might match
    scores:             list[dict]   # [{identity_id, score, reasons}]
    best_match:         dict | None  # highest-scored candidate
    phase_c_enabled:    bool         # True enables auto-resolution


SYSTEM_PROMPT = """You are a correlation engine for an Identity Governance system.
You will be given an incoming identity record and a list of candidate existing identities.
Score each candidate 0.0-1.0:
  1.0  = definite match (same email OR same employee_id)
  0.9  = very likely (same username, similar name)
  0.7  = probable (similar email domain, similar name)
  0.5  = possible (partial name match)
  0.0  = no match

Respond ONLY with valid JSON:
{
  "scores": [{"identity_id": "...", "score": 0.95, "reason": "exact email match"}],
  "recommendation": "AUTO_RESOLVE|ESCALATE|NO_MATCH",
  "reasoning": "brief explanation"
}"""


# ── Nodes ──────────────────────────────────────────────────────────────────────

async def find_candidates(state: CorrelationState) -> CorrelationState:
    """Find candidate identities in the DB for the incoming record."""
    from app.core.database import AsyncSessionLocal
    from app.models.identity import Identity
    from sqlalchemy import select, or_

    rec = state["incoming_record"]
    candidates = []

    async with AsyncSessionLocal() as db:
        q = select(Identity).where(
            Identity.realm_id == state["realm_id"],
            or_(
                Identity.email == rec.get("email", "").lower(),
                Identity.username == rec.get("username", "").lower(),
                Identity.employee_id == rec.get("employee_id", "") if rec.get("employee_id") else False,
            )
        ).limit(10)

        rows = (await db.execute(q)).scalars().all()
        candidates = [
            {
                "identity_id":  r.id,
                "username":     r.username,
                "email":        r.email,
                "first_name":   r.first_name or "",
                "last_name":    r.last_name or "",
                "employee_id":  r.employee_id or "",
                "status":       r.status,
            }
            for r in rows
        ]

    return {**state, "candidates": candidates}


def _simple_score(incoming: dict, candidate: dict) -> tuple[float, str]:
    """Deterministic scoring before sending to LLM."""
    # Exact email match
    if incoming.get("email") and incoming["email"].lower() == candidate["email"].lower():
        return 0.98, "exact email match"
    # Exact employee ID
    if (incoming.get("employee_id") and candidate.get("employee_id") and
            incoming["employee_id"] == candidate["employee_id"]):
        return 0.95, "exact employee_id match"
    # Exact username
    if incoming.get("username") and incoming["username"].lower() == candidate["username"].lower():
        return 0.90, "exact username match"
    # Name similarity
    inc_name = f"{incoming.get('first_name','')} {incoming.get('last_name','')}".lower().strip()
    cnd_name = f"{candidate.get('first_name','')} {candidate.get('last_name','')}".lower().strip()
    if inc_name and cnd_name:
        ratio = difflib.SequenceMatcher(None, inc_name, cnd_name).ratio()
        if ratio >= 0.85:
            return round(ratio * 0.85, 2), f"name similarity {ratio:.0%}"
    return 0.0, "no match"


async def score_candidates(state: CorrelationState) -> CorrelationState:
    """Score candidates — deterministic first, then LLM for ambiguous cases."""
    incoming  = state["incoming_record"]
    candidates = state["candidates"]

    if not candidates:
        return {
            **state,
            "scores":    [],
            "best_match": None,
            "decision":  "NO_MATCH",
            "confidence": 1.0,
            "reasoning": "No candidates found in identity store.",
            "requires_human": False,
        }

    # Step 1: deterministic scores
    scores = []
    for c in candidates:
        score, reason = _simple_score(incoming, c)
        scores.append({"identity_id": c["identity_id"], "score": score, "reason": reason})

    # Step 2: if best score is ambiguous (0.5-0.84), use LLM to re-evaluate
    best = max(scores, key=lambda x: x["score"])
    if 0.50 <= best["score"] < AUTO_RESOLVE_THRESHOLD:
        try:
            llm = get_structured_llm()
            messages = [
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=(
                    f"Incoming: {json.dumps(incoming)}\n"
                    f"Candidates: {json.dumps(candidates)}"
                )),
            ]
            response = await llm.ainvoke(messages)
            content  = response.content if hasattr(response, "content") else str(response)
            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                llm_result = json.loads(json_match.group())
                for llm_score in llm_result.get("scores", []):
                    for s in scores:
                        if s["identity_id"] == llm_score.get("identity_id"):
                            # Blend: weight deterministic more
                            s["score"] = round(
                                0.6 * s["score"] + 0.4 * llm_score.get("score", s["score"]), 3
                            )
                            s["reason"] += f" + LLM: {llm_score.get('reason','')}"
                best = max(scores, key=lambda x: x["score"])
        except Exception:
            pass  # fall back to deterministic scores

    requires_human = low_confidence_requires_human(best["score"], AUTO_RESOLVE_THRESHOLD)
    best_candidate = next(
        (c for c in candidates if c["identity_id"] == best["identity_id"]), None
    )

    if best["score"] == 0.0:
        decision = "NO_MATCH"
        requires_human = False
    elif requires_human:
        decision = "ESCALATE_TO_HUMAN"
    else:
        decision = "AUTO_RESOLVE" if state.get("phase_c_enabled") else "RECOMMEND_MATCH"

    return {
        **state,
        "scores":     scores,
        "best_match": {**best, "candidate": best_candidate},
        "confidence": best["score"],
        "decision":   decision,
        "reasoning":  f"Best match score {best['score']}: {best['reason']}",
        "requires_human": requires_human,
    }


async def write_audit_node(state: CorrelationState) -> CorrelationState:
    from app.core.database import AsyncSessionLocal
    result = AgentResult(
        decision=state.get("decision", ""),
        reasoning=state.get("reasoning", ""),
        confidence=state.get("confidence", 0.0),
        requires_human=state.get("requires_human", True),
        data={
            "best_match":   state.get("best_match"),
            "scores":       state.get("scores", []),
            "candidate_count": len(state.get("candidates", [])),
        },
    )
    async with AsyncSessionLocal() as db:
        await write_agent_audit(
            db=db,
            realm_id=state["realm_id"],
            actor_id=state["actor_id"],
            actor_username=state["actor_username"],
            agent_name="correlation_agent",
            action="AGENT_CORRELATION_SCORE",
            target_id=(state.get("best_match") or {}).get("identity_id"),
            result=result,
            request_id=state["request_id"],
        )
        await db.commit()
    return {**state, "audit_written": True}


def build_correlation_graph() -> StateGraph:
    graph = StateGraph(CorrelationState)
    graph.add_node("find_candidates", find_candidates)
    graph.add_node("score_candidates", score_candidates)
    graph.add_node("write_audit",      write_audit_node)
    graph.add_edge(START,              "find_candidates")
    graph.add_edge("find_candidates",  "score_candidates")
    graph.add_edge("score_candidates", "write_audit")
    graph.add_edge("write_audit",      END)
    return graph.compile()


_correlation_graph = None

def get_correlation_graph():
    global _correlation_graph
    if _correlation_graph is None:
        _correlation_graph = build_correlation_graph()
    return _correlation_graph


async def run_correlation(
    incoming_record: dict,
    realm_id: str,
    actor_id: str,
    actor_username: str,
    phase_c_enabled: bool = False,
    request_id: str | None = None,
) -> dict:
    import uuid as _uuid
    rid = request_id or str(_uuid.uuid4())
    initial: CorrelationState = {
        "realm_id":        realm_id,
        "actor_id":        actor_id,
        "actor_username":  actor_username,
        "request_id":      rid,
        "input":           str(incoming_record),
        "messages":        [],
        "reasoning":       "",
        "decision":        None,
        "confidence":      0.0,
        "requires_human":  True,
        "error":           None,
        "audit_written":   False,
        "incoming_record": incoming_record,
        "candidates":      [],
        "scores":          [],
        "best_match":      None,
        "phase_c_enabled": phase_c_enabled,
    }
    result = await get_correlation_graph().ainvoke(initial)
    return {
        "decision":       result["decision"],
        "confidence":     result["confidence"],
        "requires_human": result["requires_human"],
        "best_match":     result.get("best_match"),
        "scores":         result.get("scores", []),
        "reasoning":      result.get("reasoning", ""),
        "request_id":     rid,
    }
