"""Day 7 test - agent layer (Audit Query, Correlation, Approval Risk)."""
import httpx, sys, uuid, json

BASE = "http://localhost:8000"
C    = httpx.Client(timeout=120.0)   # agents can take longer (LLM call)
PASS = []
FAIL = []
RUN  = uuid.uuid4().hex[:6]


def chk(label, r, expect=None):
    ok = (r.status_code == expect) if expect else (r.status_code < 400)
    (PASS if ok else FAIL).append(label)
    d = r.json() if r.content else {}
    mark = "  OK  " if ok else " FAIL "
    print(f"[{mark}] {label} -> HTTP {r.status_code}")
    for k in ["decision","recommendation","risk_score","confidence",
              "requires_human","events_fetched","request_id","detail",
              "ollama_reachable","configured_model","model_available"]:
        if k in d:
            print(f"       {k}: {d[k]}")
    return d


# Login
d = chk("Login admin", C.post(f"{BASE}/api/v1/auth/login",
    json={"username":"admin","password":"Admin1234!","realm_id":"master"}))
H = {"Authorization": f"Bearer {d['access_token']}"}
admin_id = C.get(f"{BASE}/api/v1/auth/me", headers=H).json()["id"]

# ── Agent Health ──────────────────────────────────────────────────────────────
print("\n=== Agent Health ===")
d = chk("GET /agents/health", C.get(f"{BASE}/api/v1/agents/health", headers=H))
ollama_up = d.get("ollama_reachable", False)
model_ok  = d.get("model_available",  False)
print(f"       Ollama reachable: {ollama_up}")
print(f"       Model available:  {model_ok}")
print(f"       Available models: {d.get('available_models', [])}")

# ── Audit Query Agent ─────────────────────────────────────────────────────────
print("\n=== Audit Query Agent (Phase A - read-only) ===")
d = chk("Query: all logins", C.post(f"{BASE}/api/v1/agents/audit-query",
    json={"query": "Show me all login events"}, headers=H))
print(f"       events_fetched: {d.get('events_fetched', 0)}")
print(f"       anomalies: {d.get('anomalies', [])}")
if d.get("answer"):
    print(f"       answer (first 200): {d['answer'][:200]}")

d = chk("Query: failed logins", C.post(f"{BASE}/api/v1/agents/audit-query",
    json={"query": "Show me all failed login attempts"}, headers=H))

d = chk("Query: role events", C.post(f"{BASE}/api/v1/agents/audit-query",
    json={"query": "What role assignments happened recently?"}, headers=H))

d = chk("Query: admin actions", C.post(f"{BASE}/api/v1/agents/audit-query",
    json={"query": "What did the admin user do?"}, headers=H))
print(f"       events_fetched: {d.get('events_fetched', 0)}")

# Verify audit trail was written for agent actions
audit_d = C.get(f"{BASE}/api/v1/audit/events?action=AGENT_AUDIT_QUERY", headers=H).json()
agent_logged = audit_d.get("total", 0) > 0
(PASS if agent_logged else FAIL).append("Audit Query Agent writes to audit log")
print(f"\n[{'  OK  ' if agent_logged else ' FAIL '}] Agent decisions written to audit log: {audit_d.get('total',0)} entries")

# ── Correlation Agent ─────────────────────────────────────────────────────────
print("\n=== Correlation Agent (Phase A/C) ===")

# Case 1: exact email match -> high confidence
d = chk("Correlation: exact email (HIGH confidence)", C.post(
    f"{BASE}/api/v1/agents/correlation",
    json={"incoming_record": {
        "username":   "admin",
        "email":      "admin@valoidm.local",
        "first_name": "Admin",
        "last_name":  "User",
    }}, headers=H))
print(f"       confidence: {d.get('confidence')}, requires_human: {d.get('requires_human')}")
assert d.get("confidence", 0) >= 0.85, f"Expected high confidence for exact email match, got {d.get('confidence')}"
PASS.append("Correlation: exact email -> confidence >= 0.85")
print(f"[  OK  ] Exact email -> confidence >= 0.85")

# Case 2: no match
d = chk("Correlation: no match", C.post(
    f"{BASE}/api/v1/agents/correlation",
    json={"incoming_record": {
        "username":   "completely.unknown.zzz",
        "email":      "nobody@nowhere.xyz",
        "first_name": "Nobody",
        "last_name":  "Here",
    }}, headers=H))
print(f"       decision: {d.get('decision')}")

# Case 3: phase_c_enabled
d = chk("Correlation: phase_c_enabled", C.post(
    f"{BASE}/api/v1/agents/correlation",
    json={
        "incoming_record": {
            "username":   "abhishek",
            "email":      "abhishek@valoidm.local",
        },
        "phase_c_enabled": True,
    }, headers=H))
print(f"       decision: {d.get('decision')}, confidence: {d.get('confidence')}")

# ── Approval Risk Agent ───────────────────────────────────────────────────────
print("\n=== Approval Risk Agent (Phase B) ===")

# Create test data for risk scoring
d_r = C.post(f"{BASE}/api/v1/roles",
    json={"name": f"Agent Test Role {RUN}", "role_type": "BUSINESS"}, headers=H)
role_id = d_r.json().get("id","") if d_r.status_code == 201 else ""

# Case 1: SoD conflict -> always DENY
d = chk("Risk: SoD conflict -> DENY", C.post(
    f"{BASE}/api/v1/agents/approval-risk",
    json={
        "access_request_id":  "req-sod-test",
        "role_id":            role_id or "00000000-0000-0000-0000-000000000001",
        "requester_id":       admin_id,
        "target_identity_id": admin_id,
        "sod_conflict":       True,
    }, headers=H))
assert d.get("recommendation") == "DENY", f"SoD conflict should DENY, got {d.get('recommendation')}"
PASS.append("Approval Risk: SoD conflict -> DENY")
print(f"[  OK  ] SoD conflict -> recommendation: {d.get('recommendation')}")

# Case 2: Normal low-risk request
d = chk("Risk: normal BUSINESS role (low risk)", C.post(
    f"{BASE}/api/v1/agents/approval-risk",
    json={
        "access_request_id":  f"req-normal-{RUN}",
        "role_id":            role_id or "00000000-0000-0000-0000-000000000002",
        "requester_id":       admin_id,
        "target_identity_id": admin_id,
        "sod_conflict":       False,
    }, headers=H))
print(f"       risk_score: {d.get('risk_score')}, recommendation: {d.get('recommendation')}")
print(f"       risk_factors: {d.get('risk_factors', [])}")

# Verify approval risk agent writes to audit log
audit_d2 = C.get(
    f"{BASE}/api/v1/audit/events?action=AGENT_APPROVAL_RISK_SCORE", headers=H).json()
agent_risk_logged = audit_d2.get("total", 0) > 0
(PASS if agent_risk_logged else FAIL).append("Approval Risk Agent writes to audit log")
print(f"\n[{'  OK  ' if agent_risk_logged else ' FAIL '}] Risk agent decisions in audit: {audit_d2.get('total',0)} entries")

# ── Summary ────────────────────────────────────────────────────────────────────
print()
print("=" * 60)
print(f"  Day 7 - Passed: {len(PASS)}   Failed: {len(FAIL)}")
if not ollama_up:
    print("  NOTE: Ollama not reachable - LLM calls degraded gracefully,")
    print("        deterministic rules still ran correctly.")
if FAIL:
    for f in FAIL:
        print(f"    FAIL: {f}")
else:
    print("  All tests passed.")
print("=" * 60)
C.close()
if FAIL:
    sys.exit(1)
