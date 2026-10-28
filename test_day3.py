"""
Day 3 end-to-end test: identities CRUD + lifecycle + org units.
Run with: python test_day3.py
"""
import httpx, sys, uuid

BASE = "http://localhost:8000"
C = httpx.Client(timeout=30.0)
PASS = []
FAIL = []
RUN = uuid.uuid4().hex[:6]   # unique suffix per run


def chk(label, r, expect=None):
    if expect is None:
        ok = r.status_code < 400
    else:
        ok = r.status_code == expect
    (PASS if ok else FAIL).append(label)
    mark = "  OK  " if ok else " FAIL "
    d = r.json() if r.content else {}
    print(f"[{mark}] {label} -> HTTP {r.status_code}")
    for k in ["id", "username", "status", "identity_type", "message",
              "total", "name", "detail"]:
        if k in d:
            print(f"       {k}: {d[k]}")
    return d


# ── Login as admin ─────────────────────────────────────────────────────────────
print("\n=== Auth ===")
d = chk("POST /auth/login (admin)", C.post(f"{BASE}/api/v1/auth/login", json={
    "username": "admin", "password": "Admin1234!", "realm_id": "master"
}))
token = d.get("access_token", "")
H = {"Authorization": f"Bearer {token}"}

# ── Identity CRUD ──────────────────────────────────────────────────────────────
print("\n=== Identities CRUD ===")
d = chk("POST /identities (create)", C.post(f"{BASE}/api/v1/identities", json={
    "username": f"john.doe.{RUN}", "email": f"john.{RUN}@company.local",
    "password": "John1234!", "first_name": "John", "last_name": "Doe",
    "identity_type": "HUMAN",
}, headers=H), expect=201)
john_id = d.get("id", "")

d = chk("POST /identities (service account)", C.post(f"{BASE}/api/v1/identities", json={
    "username": f"svc.billing.{RUN}", "email": f"svc.{RUN}@company.local",
    "identity_type": "SERVICE",
}, headers=H), expect=201)
svc_id = d.get("id", "")

chk("GET  /identities (list)", C.get(f"{BASE}/api/v1/identities", headers=H))
chk("GET  /identities?search=john", C.get(f"{BASE}/api/v1/identities?search=john", headers=H))
chk("GET  /identities?identity_type=SERVICE", C.get(f"{BASE}/api/v1/identities?identity_type=SERVICE", headers=H))

if john_id:
    chk("GET  /identities/{id}", C.get(f"{BASE}/api/v1/identities/{john_id}", headers=H))
    chk("PUT  /identities/{id}", C.put(f"{BASE}/api/v1/identities/{john_id}",
        json={"first_name": "Johnny", "attributes": {"department": "Finance"}}, headers=H))

chk("POST /identities (duplicate -> 409)", C.post(f"{BASE}/api/v1/identities", json={
    "username": f"john.doe.{RUN}", "email": "x@y.local",
}, headers=H), expect=409)

# ── Lifecycle ─────────────────────────────────────────────────────────────────
print("\n=== Lifecycle ===")
d = chk("POST /lifecycle/join (PRE_HIRE)", C.post(f"{BASE}/api/v1/lifecycle/join", json={
    "username": f"jane.{RUN}", "email": f"jane.{RUN}@company.local",
    "first_name": "Jane", "last_name": "Smith",
    "start_date": "2099-01-01T00:00:00Z",
}, headers=H), expect=201)
jane_id = d.get("id", "")

d = chk("POST /lifecycle/join (immediate ACTIVE)", C.post(f"{BASE}/api/v1/lifecycle/join", json={
    "username": f"bob.{RUN}", "email": f"bob.{RUN}@company.local",
    "first_name": "Bob", "last_name": "Jones",
}, headers=H), expect=201)
bob_id = d.get("id", "")

if jane_id:
    chk("POST /lifecycle/{id}/activate", C.post(f"{BASE}/api/v1/lifecycle/{jane_id}/activate", headers=H))
if bob_id:
    chk("POST /lifecycle/{id}/move", C.post(f"{BASE}/api/v1/lifecycle/{bob_id}/move",
        json={"new_employee_id": "EMP-9001", "reason": "Department transfer"}, headers=H))
    chk("POST /lifecycle/{id}/lock", C.post(f"{BASE}/api/v1/lifecycle/{bob_id}/lock", headers=H))
    chk("POST /lifecycle/{id}/unlock", C.post(f"{BASE}/api/v1/lifecycle/{bob_id}/unlock", headers=H))
    chk("POST /lifecycle/{id}/leave", C.post(f"{BASE}/api/v1/lifecycle/{bob_id}/leave",
        json={"reason": "Medical leave"}, headers=H))
    chk("POST /lifecycle/{id}/return-from-leave", C.post(
        f"{BASE}/api/v1/lifecycle/{bob_id}/return-from-leave", headers=H))
    chk("POST /lifecycle/{id}/terminate", C.post(f"{BASE}/api/v1/lifecycle/{bob_id}/terminate",
        json={"reason": "Resigned", "revoke_access": True}, headers=H))

# ── Org Units ─────────────────────────────────────────────────────────────────
print("\n=== Org Units ===")
d = chk("POST /org-units (root)", C.post(f"{BASE}/api/v1/org-units",
    json={"name": "Acme Corp", "code": "ROOT"}, headers=H), expect=201)
root_id = d.get("id", "")

d = chk("POST /org-units (child)", C.post(f"{BASE}/api/v1/org-units",
    json={"name": "Engineering", "code": "ENG", "parent_id": root_id}, headers=H), expect=201)
eng_id = d.get("id", "")

chk("POST /org-units (grandchild)", C.post(f"{BASE}/api/v1/org-units",
    json={"name": "Backend Team", "code": "BACKEND", "parent_id": eng_id}, headers=H), expect=201)

chk("GET  /org-units",       C.get(f"{BASE}/api/v1/org-units", headers=H))
chk("GET  /org-units/tree",  C.get(f"{BASE}/api/v1/org-units/tree", headers=H))

# Delete grandchild (leaf)
tree = C.get(f"{BASE}/api/v1/org-units", headers=H).json()
leaf = next((u for u in tree if u.get("name") == "Backend Team"), None)
if leaf:
    chk("DELETE /org-units/{id} (leaf)", C.delete(f"{BASE}/api/v1/org-units/{leaf['id']}", headers=H), expect=204)

chk("DELETE /org-units/{id} (has children -> 409)", C.delete(
    f"{BASE}/api/v1/org-units/{root_id}", headers=H), expect=409)

# ── Summary ────────────────────────────────────────────────────────────────────
print()
print("=" * 55)
print(f"  Day 3 Results — Passed: {len(PASS)}   Failed: {len(FAIL)}")
if FAIL:
    for f in FAIL:
        print(f"    FAIL: {f}")
else:
    print("  All tests passed.")
print("=" * 55)
print()
print("  Swagger UI: http://localhost:8000/docs")
C.close()
if FAIL:
    sys.exit(1)
