"""Day 5 test — certifications + audit query."""
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
    for k in ["id", "name", "status", "total", "total_items",
              "certified_items", "revoked_items", "total_events",
              "message", "detail"]:
        if k in d:
            print(f"       {k}: {d[k]}")
    return d


# Login
d = chk("Login admin", C.post(f"{BASE}/api/v1/auth/login",
    json={"username": "admin", "password": "Admin1234!", "realm_id": "master"}))
H = {"Authorization": f"Bearer {d['access_token']}"}
admin_id = C.get(f"{BASE}/api/v1/auth/me", headers=H).json()["id"]

# Create identities + role + assignment for this run
d_u = chk("Create user for cert test", C.post(f"{BASE}/api/v1/identities",
    json={"username": f"cert.user.{RUN}", "email": f"cu.{RUN}@x.local",
          "password": "Cert1234!"}, headers=H), expect=201)
user_id = d_u.get("id", "")

d_r = chk("Create role for cert test", C.post(f"{BASE}/api/v1/roles",
    json={"name": f"Cert Role {RUN}", "role_type": "BUSINESS"}, headers=H), expect=201)
role_id = d_r.get("id", "")

d_a = chk("Assign role to user", C.post(
    f"{BASE}/api/v1/roles/assignments/identity/{user_id}",
    json={"role_id": role_id}, headers=H), expect=201)
assignment_id = d_a.get("id", "")

# ── Certifications ─────────────────────────────────────────────────────────────
print("\n=== Certification Campaigns ===")
d = chk("Create campaign (DRAFT)", C.post(f"{BASE}/api/v1/certifications",
    json={"name": f"Q4 Access Review {RUN}",
          "description": "Quarterly access certification"}, headers=H), expect=201)
camp_id = d.get("id", "")

chk("GET /certifications (list)", C.get(f"{BASE}/api/v1/certifications", headers=H))
chk("GET /certifications/{id}", C.get(f"{BASE}/api/v1/certifications/{camp_id}", headers=H))

# Launch — snapshot all active assignments, admin is reviewer
d = chk("Launch campaign", C.post(
    f"{BASE}/api/v1/certifications/{camp_id}/launch?reviewer_id={admin_id}",
    headers=H))
print(f"       total_items: {d.get('total_items')}")

chk("Launch again -> 400", C.post(
    f"{BASE}/api/v1/certifications/{camp_id}/launch?reviewer_id={admin_id}",
    headers=H), expect=400)

chk("GET campaign items (PENDING)", C.get(
    f"{BASE}/api/v1/certifications/{camp_id}/items?status=PENDING", headers=H))

# Get all items and find ours
items = C.get(f"{BASE}/api/v1/certifications/{camp_id}/items", headers=H).json()
our_item = next((i for i in items if i.get("assignment_id") == assignment_id), None)
other_items = [i for i in items if i.get("assignment_id") != assignment_id]

if our_item:
    item_id = our_item["id"]
    chk(f"CERTIFY item (our assignment)", C.post(
        f"{BASE}/api/v1/certifications/items/{item_id}/decide",
        json={"decision": "CERTIFIED", "comment": "Still needed"}, headers=H))
    chk("Decide already-decided -> 400", C.post(
        f"{BASE}/api/v1/certifications/items/{item_id}/decide",
        json={"decision": "CERTIFIED"}, headers=H), expect=400)

# Revoke another item to test revocation flow
revoke_item = next((i for i in other_items if i.get("status") == "PENDING"), None)
if revoke_item:
    chk("REVOKE another item", C.post(
        f"{BASE}/api/v1/certifications/items/{revoke_item['id']}/decide",
        json={"decision": "REVOKED", "comment": "No longer needed"}, headers=H))
    # Verify underlying assignment was revoked — must include non-active
    ra = C.get(
        f"{BASE}/api/v1/roles/assignments/identity/{revoke_item['identity_id']}?active_only=false",
        headers=H).json()
    revoked_found = any(a.get("id") == revoke_item["assignment_id"] and
                        a.get("status") == "REVOKED"
                        for a in ra)
    label = "Assignment revoked after cert REVOKE decision"
    (PASS if revoked_found else FAIL).append(label)
    print(f"[{'  OK  ' if revoked_found else ' FAIL '}] {label} -> {revoked_found}")

# Create a campaign to cancel
d2 = chk("Create campaign to cancel", C.post(f"{BASE}/api/v1/certifications",
    json={"name": f"To Cancel {RUN}"}, headers=H), expect=201)
camp2_id = d2.get("id", "")
if camp2_id:
    chk("Cancel campaign", C.post(
        f"{BASE}/api/v1/certifications/{camp2_id}/cancel", headers=H))
    chk("Cancel completed -> 400", C.post(
        f"{BASE}/api/v1/certifications/{camp2_id}/cancel", headers=H), expect=400)

# ── Audit Query ────────────────────────────────────────────────────────────────
print("\n=== Audit Query ===")
chk("GET /audit/events (all)", C.get(f"{BASE}/api/v1/audit/events", headers=H))
chk("GET /audit/events?action=CERT", C.get(
    f"{BASE}/api/v1/audit/events?action=CERT", headers=H))
chk("GET /audit/events?outcome=SUCCESS", C.get(
    f"{BASE}/api/v1/audit/events?outcome=SUCCESS", headers=H))
chk("GET /audit/events?search=campaign", C.get(
    f"{BASE}/api/v1/audit/events?search=campaign", headers=H))
chk("GET /audit/summary", C.get(f"{BASE}/api/v1/audit/summary", headers=H))
chk("GET /audit/identity/{id} (trail)", C.get(
    f"{BASE}/api/v1/audit/identity/{admin_id}", headers=H))

# Get a specific log entry
events = C.get(f"{BASE}/api/v1/audit/events?page_size=1", headers=H).json()
if events.get("items"):
    log_id = events["items"][0]["id"]
    chk("GET /audit/events/{id}", C.get(
        f"{BASE}/api/v1/audit/events/{log_id}", headers=H))

# ── Summary ────────────────────────────────────────────────────────────────────
print()
print("=" * 55)
print(f"  Day 5 — Passed: {len(PASS)}   Failed: {len(FAIL)}")
if FAIL:
    for f in FAIL:
        print(f"    FAIL: {f}")
else:
    print("  All tests passed.")
print("=" * 55)
C.close()
if FAIL:
    sys.exit(1)
