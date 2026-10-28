"""Day 4 test — roles, SoD, assignments, access requests."""
import httpx, sys, uuid

BASE = "http://localhost:8000"
C    = httpx.Client(timeout=30.0)
PASS = []
FAIL = []
RUN  = uuid.uuid4().hex[:6]


def chk(label, r, expect=None):
    ok = (r.status_code == expect) if expect else (r.status_code < 400)
    (PASS if ok else FAIL).append(label)
    d = r.json() if r.content else {}
    mark = "  OK  " if ok else " FAIL "
    print(f"[{mark}] {label} -> HTTP {r.status_code}")
    for k in ["id", "name", "status", "message", "detail", "total", "has_conflict"]:
        if k in d:
            print(f"       {k}: {d[k]}")
    return d


# login
d = chk("Login admin", C.post(f"{BASE}/api/v1/auth/login",
    json={"username": "admin", "password": "Admin1234!", "realm_id": "master"}))
H = {"Authorization": f"Bearer {d['access_token']}"}

# create two test identities for this run
d1 = chk("Create identity alice", C.post(f"{BASE}/api/v1/identities",
    json={"username": f"alice.{RUN}", "email": f"alice.{RUN}@x.local",
          "password": "Alice1234!"}, headers=H), expect=201)
alice_id = d1.get("id", "")

d2 = chk("Create identity bob", C.post(f"{BASE}/api/v1/identities",
    json={"username": f"bob.{RUN}", "email": f"bob.{RUN}@x.local",
          "password": "Bob1234!"}, headers=H), expect=201)
bob_id = d2.get("id", "")

# ── Roles ──────────────────────────────────────────────────────────────────────
print("\n=== Roles ===")
d = chk("Create BUSINESS role: Finance Approver", C.post(f"{BASE}/api/v1/roles",
    json={"name": f"Finance Approver {RUN}", "role_type": "BUSINESS",
          "description": "Can approve finance transactions"}, headers=H), expect=201)
role_fin_id = d.get("id", "")

d = chk("Create BUSINESS role: Finance Auditor", C.post(f"{BASE}/api/v1/roles",
    json={"name": f"Finance Auditor {RUN}", "role_type": "BUSINESS",
          "description": "Read-only audit access to finance"}, headers=H), expect=201)
role_aud_id = d.get("id", "")

d = chk("Create TECHNICAL role: DB Admin", C.post(f"{BASE}/api/v1/roles",
    json={"name": f"DB Admin {RUN}", "role_type": "TECHNICAL",
          "requires_approval": True}, headers=H), expect=201)
role_dba_id = d.get("id", "")

chk("GET /roles/catalog", C.get(f"{BASE}/api/v1/roles/catalog", headers=H))
chk("GET /roles/catalog?role_type=BUSINESS", C.get(
    f"{BASE}/api/v1/roles/catalog?role_type=BUSINESS", headers=H))
chk("GET /roles/{id}", C.get(f"{BASE}/api/v1/roles/{role_fin_id}", headers=H))
chk("PUT /roles/{id} update", C.put(f"{BASE}/api/v1/roles/{role_dba_id}",
    json={"description": "Database administrator - high privilege"}, headers=H))
chk("Duplicate role name -> 409", C.post(f"{BASE}/api/v1/roles",
    json={"name": f"Finance Approver {RUN}", "role_type": "BUSINESS"}, headers=H), expect=409)

# ── SoD Conflicts ─────────────────────────────────────────────────────────────
print("\n=== SoD Conflicts ===")
d = chk("Create SoD conflict (Approver x Auditor)", C.post(f"{BASE}/api/v1/roles/conflicts",
    json={"role_a_id": role_fin_id, "role_b_id": role_aud_id,
          "description": "Cannot approve and audit same transactions"}, headers=H), expect=201)
conflict_id = d.get("id", "")

chk("GET /roles/conflicts/all", C.get(f"{BASE}/api/v1/roles/conflicts/all", headers=H))
chk("Duplicate SoD pair -> 409", C.post(f"{BASE}/api/v1/roles/conflicts",
    json={"role_a_id": role_fin_id, "role_b_id": role_aud_id}, headers=H), expect=409)

# ── Role Assignments ───────────────────────────────────────────────────────────
print("\n=== Role Assignments ===")
d = chk("Assign Finance Approver to alice", C.post(
    f"{BASE}/api/v1/roles/assignments/identity/{alice_id}",
    json={"role_id": role_fin_id}, headers=H), expect=201)
assign_id = d.get("id", "")

chk("Duplicate assign -> 409", C.post(
    f"{BASE}/api/v1/roles/assignments/identity/{alice_id}",
    json={"role_id": role_fin_id}, headers=H), expect=409)

# alice has Finance Approver — assigning Finance Auditor should fail (SoD)
chk("SoD violation -> 409", C.post(
    f"{BASE}/api/v1/roles/assignments/identity/{alice_id}",
    json={"role_id": role_aud_id}, headers=H), expect=409)

chk("Assign DB Admin to alice (no conflict)", C.post(
    f"{BASE}/api/v1/roles/assignments/identity/{alice_id}",
    json={"role_id": role_dba_id}, headers=H), expect=201)

chk("GET assignments for alice", C.get(
    f"{BASE}/api/v1/roles/assignments/identity/{alice_id}", headers=H))

if assign_id:
    chk("Revoke Finance Approver from alice", C.request("DELETE",
        f"{BASE}/api/v1/roles/assignments/{assign_id}",
        json={"reason": "Role no longer needed"}, headers=H), expect=200)
    chk("Revoke already-revoked -> 400", C.request("DELETE",
        f"{BASE}/api/v1/roles/assignments/{assign_id}",
        json={}, headers=H), expect=400)

# ── Access Requests ────────────────────────────────────────────────────────────
print("\n=== Access Requests ===")
d = chk("Submit access request (bob -> Finance Auditor)", C.post(
    f"{BASE}/api/v1/requests",
    json={"role_id": role_aud_id, "target_identity_id": bob_id,
          "justification": "Need read access for Q4 audit",
          "access_duration_days": 30}, headers=H), expect=201)
req_id = d.get("id", "")
print(f"       sod_conflict: {d.get('sod_conflict')}")

chk("Duplicate pending -> 409", C.post(f"{BASE}/api/v1/requests",
    json={"role_id": role_aud_id, "target_identity_id": bob_id,
          "justification": "Again"}, headers=H), expect=409)

chk("GET /requests (all)", C.get(f"{BASE}/api/v1/requests", headers=H))
chk("GET /requests?status=PENDING", C.get(
    f"{BASE}/api/v1/requests?status=PENDING", headers=H))
chk("GET /requests/{id}", C.get(f"{BASE}/api/v1/requests/{req_id}", headers=H))

if req_id:
    chk("Approve request", C.post(f"{BASE}/api/v1/requests/{req_id}/decide",
        json={"decision": "APPROVED", "comment": "Approved for audit period"}, headers=H))
    chk("Decide already-decided -> 400", C.post(f"{BASE}/api/v1/requests/{req_id}/decide",
        json={"decision": "APPROVED"}, headers=H), expect=400)

# Submit and cancel
d2 = chk("Submit request to cancel", C.post(f"{BASE}/api/v1/requests",
    json={"role_id": role_fin_id, "target_identity_id": bob_id,
          "justification": "Will cancel this"}, headers=H), expect=201)
req2_id = d2.get("id", "")
if req2_id:
    chk("Cancel request", C.post(f"{BASE}/api/v1/requests/{req2_id}/cancel", headers=H))

# Verify bob now has Finance Auditor assignment from approved request
chk("Bob's assignments after approval", C.get(
    f"{BASE}/api/v1/roles/assignments/identity/{bob_id}", headers=H))

# ── Role delete blocked by active assignment ───────────────────────────────────
print("\n=== Role delete blocked by assignment ===")
chk("Delete role with active assignment -> 409", C.delete(
    f"{BASE}/api/v1/roles/{role_dba_id}", headers=H), expect=409)

# Summary
print()
print("=" * 55)
print(f"  Day 4 — Passed: {len(PASS)}   Failed: {len(FAIL)}")
if FAIL:
    for f in FAIL:
        print(f"    FAIL: {f}")
else:
    print("  All tests passed.")
print("=" * 55)
C.close()
if FAIL:
    sys.exit(1)
