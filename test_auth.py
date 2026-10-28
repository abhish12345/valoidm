"""
Quick end-to-end test of the auth endpoints.
Run with: python test_auth.py
"""
import httpx
import sys

BASE = "http://localhost:8000"
C = httpx.Client(timeout=30.0)
PASS = []
FAIL = []


def show(label, r, expect_ok=True):
    ok = (r.status_code < 400) == expect_ok
    mark = "  OK  " if ok else " FAIL "
    result = "OK" if ok else "FAIL"
    (PASS if ok else FAIL).append(label)
    print(f"[{mark}] {label} -> HTTP {r.status_code}")
    d = r.json()
    for k in ["id", "username", "realm_id", "message", "token_type", "mfa_required", "detail"]:
        if k in d:
            print(f"       {k}: {d[k]}")
    if "access_token" in d and d["access_token"]:
        tok = d["access_token"]
        print(f"       access_token: {tok[:40]}...")
    return d


print("=" * 55)
print("  ValoIDM Auth API — End-to-End Test")
print("=" * 55)
print()

# 1. Health check
show("GET /health", C.get(f"{BASE}/health"))

# 2. Register admin
show(
    "POST /auth/register  (admin user)",
    C.post(f"{BASE}/api/v1/auth/register", json={
        "username": "admin",
        "email": "admin@valoidm.local",
        "password": "Admin1234!",
        "is_admin": True,
        "realm_id": "master",
    }),
)

# 3. Register regular user
show(
    "POST /auth/register  (regular user)",
    C.post(f"{BASE}/api/v1/auth/register", json={
        "username": "abhishek",
        "email": "abhishek@valoidm.local",
        "password": "User1234!",
        "first_name": "Abhishek",
        "realm_id": "master",
    }),
)

# 4. Login as admin
d = show("POST /auth/login  (admin)", C.post(f"{BASE}/api/v1/auth/login", json={
    "username": "admin",
    "password": "Admin1234!",
    "realm_id": "master",
}))
token = d.get("access_token", "")
refresh = d.get("refresh_token", "")

# 5. GET /me with token
if token:
    show(
        "GET  /auth/me  (with token)",
        C.get(f"{BASE}/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}),
    )

# 6. GET /me without token — expect 401 (HTTPBearer returns 401)
show(
    "GET  /auth/me  (no token — expect 401)",
    C.get(f"{BASE}/api/v1/auth/me"),
    expect_ok=False,
)

# 7. Duplicate username — expect 409
show(
    "POST /auth/register  (duplicate — expect 409)",
    C.post(f"{BASE}/api/v1/auth/register", json={
        "username": "admin",
        "email": "admin2@valoidm.local",
        "password": "Admin1234!",
        "realm_id": "master",
    }),
    expect_ok=False,
)

# 8. Wrong password — expect 401
show(
    "POST /auth/login  (wrong password — expect 401)",
    C.post(f"{BASE}/api/v1/auth/login", json={
        "username": "admin",
        "password": "wrongpassword",
        "realm_id": "master",
    }),
    expect_ok=False,
)

# 9. Token refresh
if refresh:
    show(
        "POST /auth/refresh  (new token pair)",
        C.post(f"{BASE}/api/v1/auth/refresh", json={"refresh_token": refresh}),
    )

print()
print("=" * 55)
print(f"  Passed: {len(PASS)}   Failed: {len(FAIL)}")
if FAIL:
    print("  Failed tests:")
    for f in FAIL:
        print(f"    - {f}")
else:
    print("  All tests passed.")
print("=" * 55)
print()
print("  API docs: http://localhost:8000/docs")

C.close()
if FAIL:
    sys.exit(1)
