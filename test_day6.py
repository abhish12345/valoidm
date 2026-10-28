"""Day 6 test - connectors, SCIM 2.0, webhooks, CSV import."""
import httpx, sys, uuid, io

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
    for k in ["id", "name", "status", "connector_type", "records_created",
              "records_read", "total", "detail", "message", "totalResults"]:
        if k in d:
            print(f"       {k}: {d[k]}")
    return d


# Login
d = chk("Login admin", C.post(f"{BASE}/api/v1/auth/login",
    json={"username": "admin", "password": "Admin1234!", "realm_id": "master"}))
H = {"Authorization": f"Bearer {d['access_token']}"}

# ── Connectors CRUD ───────────────────────────────────────────────────────────
print("\n=== Connectors CRUD ===")
d = chk("Create LDAP connector", C.post(f"{BASE}/api/v1/connectors", json={
    "name": f"CorpAD {RUN}",
    "connector_type": "LDAP",
    "direction": "SOURCE",
    "config": {
        "host": "10.0.0.1",
        "port": 389,
        "bind_dn": "CN=svc,DC=corp,DC=local",
        "bind_password": "secret",
        "base_dn": "DC=corp,DC=local",
    },
}, headers=H), expect=201)
ldap_id = d.get("id", "")

d = chk("Create SCIM connector", C.post(f"{BASE}/api/v1/connectors", json={
    "name": f"ServiceNow SCIM {RUN}",
    "connector_type": "SCIM",
    "direction": "TARGET",
    "config": {"base_url": "https://dev.service-now.com/scim/v2", "token": "test"},
}, headers=H), expect=201)
scim_conn_id = d.get("id", "")

chk("GET /connectors (list)", C.get(f"{BASE}/api/v1/connectors", headers=H))
chk("GET /connectors/{id}", C.get(f"{BASE}/api/v1/connectors/{ldap_id}", headers=H))

chk("Test LDAP connection (expect fail - no real AD)", C.post(
    f"{BASE}/api/v1/connectors/{ldap_id}/test", headers=H))

chk("Invalid connector_type -> 400", C.post(f"{BASE}/api/v1/connectors", json={
    "name": "Bad", "connector_type": "ORACLE",
}, headers=H), expect=400)

# ── CSV Import ────────────────────────────────────────────────────────────────
print("\n=== CSV Bulk Import ===")
csv_content = """username,email,first_name,last_name,employee_id,status
csv.alice.{RUN},alice.{RUN}@corp.local,Alice,Smith,EMP001,active
csv.bob.{RUN},bob.{RUN}@corp.local,Bob,Jones,EMP002,active
csv.charlie.{RUN},charlie.{RUN}@corp.local,Charlie,Brown,EMP003,inactive
,bad@email.com,Bad,User,,active
good.one.{RUN},not-an-email,Good,User,,active
""".replace("{RUN}", RUN)

d = chk("POST /connectors/import/csv", C.post(
    f"{BASE}/api/v1/connectors/import/csv",
    files={"file": ("import.csv", csv_content.encode(), "text/csv")},
    headers=H,
))
assert d.get("records_created", 0) == 3, f"Expected 3 created, got {d.get('records_created')}"
assert len(d.get("errors", [])) >= 2, f"Expected >=2 errors, got {d.get('errors')}"
print(f"       errors: {d.get('errors')}")

chk("Import same CSV again (all update, no create)", C.post(
    f"{BASE}/api/v1/connectors/import/csv",
    files={"file": ("import.csv", csv_content.encode(), "text/csv")},
    headers=H,
))

chk("Import non-CSV -> 400", C.post(
    f"{BASE}/api/v1/connectors/import/csv",
    files={"file": ("data.txt", b"hello", "text/plain")},
    headers=H,
), expect=400)

# ── Webhooks ──────────────────────────────────────────────────────────────────
print("\n=== Webhook Subscriptions ===")
d = chk("Create webhook (all events)", C.post(f"{BASE}/api/v1/connectors/webhooks", json={
    "name": f"Slack Notify {RUN}",
    "subscriber_url": "https://httpbin.org/post",
    "event_types": "",
}, headers=H), expect=201)
wh_id = d.get("id", "")
print(f"       secret: {d.get('secret', '')[:12]}...")

d2 = chk("Create webhook (identity.* only)", C.post(f"{BASE}/api/v1/connectors/webhooks", json={
    "name": f"Identity Webhook {RUN}",
    "subscriber_url": "https://httpbin.org/post",
    "event_types": "identity.*",
}, headers=H), expect=201)
wh2_id = d2.get("id", "")

chk("GET /connectors/webhooks/all", C.get(f"{BASE}/api/v1/connectors/webhooks/all", headers=H))

# Test webhook fire (httpbin.org accepts POST so this should deliver)
if wh_id:
    chk("Test webhook ping", C.post(
        f"{BASE}/api/v1/connectors/webhooks/{wh_id}/test", headers=H))

if wh2_id:
    chk("Delete webhook", C.delete(
        f"{BASE}/api/v1/connectors/webhooks/{wh2_id}", headers=H), expect=204)
    chk("Delete again -> 404", C.delete(
        f"{BASE}/api/v1/connectors/webhooks/{wh2_id}", headers=H), expect=404)

# ── SCIM 2.0 Inbound ─────────────────────────────────────────────────────────
print("\n=== SCIM 2.0 Inbound Server ===")
chk("GET /scim/v2/ServiceProviderConfig", C.get(
    f"{BASE}/api/v1/scim/v2/ServiceProviderConfig", headers=H))

chk("GET /scim/v2/Users (list)", C.get(f"{BASE}/api/v1/scim/v2/Users", headers=H))

d = chk("POST /scim/v2/Users (create)", C.post(f"{BASE}/api/v1/scim/v2/Users", json={
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": f"scim.user.{RUN}",
    "name":     {"givenName": "Scim", "familyName": "User"},
    "emails":   [{"value": f"scim.{RUN}@corp.local", "primary": True}],
    "active":   True,
}, headers=H), expect=201)
scim_user_id = d.get("id", "")

chk("GET /scim/v2/Users/{id}", C.get(
    f"{BASE}/api/v1/scim/v2/Users/{scim_user_id}", headers=H))

chk("GET /scim/v2/Users?filter=userName", C.get(
    f'{BASE}/api/v1/scim/v2/Users?filter=userName eq "{f"scim.user.{RUN}"}"',
    headers=H))

chk("PUT /scim/v2/Users/{id} (replace)", C.put(
    f"{BASE}/api/v1/scim/v2/Users/{scim_user_id}", json={
        "schemas":  ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": f"scim.user.{RUN}",
        "name":     {"givenName": "Scim", "familyName": "Updated"},
        "emails":   [{"value": f"scim.updated.{RUN}@corp.local", "primary": True}],
        "active":   True,
    }, headers=H))

chk("PATCH /scim/v2/Users/{id} (disable)", C.patch(
    f"{BASE}/api/v1/scim/v2/Users/{scim_user_id}", json={
        "schemas":    ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "active", "value": False}],
    }, headers=H))

# Verify status is INACTIVE
identity_d = C.get(f"{BASE}/api/v1/identities/{scim_user_id}", headers=H).json()
scim_inactive = identity_d.get("status") == "INACTIVE"
(PASS if scim_inactive else FAIL).append("SCIM PATCH -> identity status INACTIVE")
print(f"[{'  OK  ' if scim_inactive else ' FAIL '}] SCIM PATCH -> identity status: {identity_d.get('status')}")

chk("DELETE /scim/v2/Users/{id}", C.delete(
    f"{BASE}/api/v1/scim/v2/Users/{scim_user_id}", headers=H), expect=204)

chk("GET deleted user -> 404", C.get(
    f"{BASE}/api/v1/scim/v2/Users/{scim_user_id}", headers=H), expect=404)

# ── Connector delete ──────────────────────────────────────────────────────────
print("\n=== Cleanup ===")
if ldap_id:
    chk("Delete LDAP connector", C.delete(
        f"{BASE}/api/v1/connectors/{ldap_id}", headers=H), expect=204)
    chk("Delete again -> 404", C.delete(
        f"{BASE}/api/v1/connectors/{ldap_id}", headers=H), expect=404)

# Summary
print()
print("=" * 55)
print(f"  Day 6 - Passed: {len(PASS)}   Failed: {len(FAIL)}")
if FAIL:
    for f in FAIL:
        print(f"    FAIL: {f}")
else:
    print("  All tests passed.")
print("=" * 55)
C.close()
if FAIL:
    sys.exit(1)
