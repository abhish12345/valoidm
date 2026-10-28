"""
ValoIDM setup checker — run with: python check_setup.py
Checks all packages, env vars, and server connectivity.
"""
import sys
import os
import socket
import asyncio

# ── Load .env ─────────────────────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()

OK  = "[  OK  ]"
FAIL = "[ FAIL ]"
WARN = "[ WARN ]"

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)

# ── 1. Python version ──────────────────────────────────────────────────────────
section("1. Python Version")
v = sys.version_info
print(f"  Python {v.major}.{v.minor}.{v.micro}")
if v.major == 3 and v.minor >= 12:
    print(f"  {OK}  Python 3.{v.minor} — compatible")
else:
    print(f"  {WARN}  Python 3.{v.minor} — recommend 3.12+")

# ── 2. Required packages ───────────────────────────────────────────────────────
section("2. Required Packages")
packages = [
    ("fastapi",           "fastapi"),
    ("uvicorn",           "uvicorn"),
    ("sqlalchemy",        "sqlalchemy"),
    ("alembic",           "alembic"),
    ("asyncpg",           "asyncpg"),
    ("pydantic",          "pydantic"),
    ("pydantic_settings", "pydantic-settings"),
    ("jose",              "python-jose"),
    ("bcrypt",            "bcrypt"),
    ("redis",             "redis"),
    ("celery",            "celery"),
    ("pyotp",             "pyotp"),
    ("fido2",             "python-fido2"),
    ("authlib",           "authlib"),
    ("langgraph",         "langgraph"),
    ("langchain_ollama",  "langchain-ollama"),
    ("mcp",               "mcp"),
    ("ldap3",             "ldap3"),
    ("structlog",         "structlog"),
    ("httpx",             "httpx"),
    ("pytest",            "pytest"),
    ("ruff",              "ruff"),
]
missing = []
for imp, pkg in packages:
    try:
        __import__(imp)
        print(f"  {OK}  {pkg}")
    except ImportError:
        missing.append(pkg)
        print(f"  {FAIL}  {pkg}  <-- NOT INSTALLED")

if missing:
    print(f"\n  Fix: uv add {' '.join(missing)}")
else:
    print("\n  All packages installed.")

# ── 3. Environment variables ───────────────────────────────────────────────────
section("3. Environment Variables (.env)")
env_checks = [
    ("DATABASE_URL",        True),
    ("REDIS_URL",           True),
    ("OLLAMA_BASE_URL",     True),
    ("OLLAMA_MODEL",        True),
    ("JWT_SECRET_KEY",      True),
    ("JWT_ALGORITHM",       False),
    ("JWT_EXPIRE_MINUTES",  False),
    ("ENVIRONMENT",         False),
    ("APP_NAME",            False),
    ("DEFAULT_REALM",       False),
]
env_issues = []
for var, required in env_checks:
    val = os.getenv(var, "")
    stripped = val.strip()
    if not stripped and required:
        env_issues.append(var)
        print(f"  {FAIL}  {var}  <-- MISSING or EMPTY")
    elif val != stripped:
        env_issues.append(var)
        print(f"  {WARN}  {var}  <-- has whitespace, fix it")
    else:
        display = stripped[:40] + "..." if len(stripped) > 40 else stripped
        if "KEY" in var or "PASSWORD" in var:
            display = "*" * min(len(stripped), 8) + f"  ({len(stripped)} chars)"
        print(f"  {OK}  {var} = {display}")

# ── 4. JWT key strength ────────────────────────────────────────────────────────
section("4. JWT Secret Key Strength")
jwt_key = os.getenv("JWT_SECRET_KEY", "").strip()
if len(jwt_key) >= 64:
    print(f"  {OK}  64+ chars — strong")
elif len(jwt_key) >= 32:
    print(f"  {WARN}  {len(jwt_key)} chars — acceptable but 64 recommended")
else:
    print(f"  {FAIL}  {len(jwt_key)} chars — too short, regenerate with:")
    print("         python -c \"import secrets; print(secrets.token_hex(32))\"")

# ── 5. Network connectivity ────────────────────────────────────────────────────
section("5. Network Connectivity")
servers = [
    ("PostgreSQL",  "10.199.207.210", 5432),
    ("Redis",       "10.199.207.210", 6379),
    ("Ollama",      "10.199.207.232", 11434),
]
for name, host, port in servers:
    try:
        sock = socket.create_connection((host, port), timeout=3)
        sock.close()
        print(f"  {OK}  {name:12s}  {host}:{port}  — TCP reachable")
    except Exception as e:
        print(f"  {FAIL}  {name:12s}  {host}:{port}  — {e}")

# ── 6. PostgreSQL auth ─────────────────────────────────────────────────────────
section("6. PostgreSQL — Authenticated Connection")
async def check_postgres():
    try:
        import asyncpg
        url = os.getenv("DATABASE_URL", "").replace("postgresql+asyncpg", "postgresql")
        conn = await asyncpg.connect(url, timeout=5)
        ver = await conn.fetchval("SELECT version()")
        await conn.close()
        print(f"  {OK}  Connected — {ver[:55]}")
    except Exception as e:
        print(f"  {FAIL}  {e}")
        print("       Check: is the user/password correct? Is the DB created?")
        print("       Fix on Docker server:")
        print("         docker exec -it valoidm-postgres psql -U postgres")
        print("         CREATE USER valoidm WITH PASSWORD 'yourpassword';")
        print("         CREATE DATABASE valoidm OWNER valoidm;")
asyncio.run(check_postgres())

# ── 7. Redis auth ──────────────────────────────────────────────────────────────
section("7. Redis — Authenticated Connection")
try:
    import redis as redis_lib
    r = redis_lib.from_url(os.getenv("REDIS_URL", ""), socket_connect_timeout=3)
    r.ping()
    info = r.info("server")
    print(f"  {OK}  Connected — Redis {info['redis_version']}")
except Exception as e:
    print(f"  {FAIL}  {e}")

# ── 8. Ollama model check ──────────────────────────────────────────────────────
section("8. Ollama — Model Available")
try:
    import httpx
    base = os.getenv("OLLAMA_BASE_URL", "http://10.199.207.232:11434")
    model = os.getenv("OLLAMA_MODEL", "")
    resp = httpx.get(f"{base}/api/tags", timeout=5)
    models = [m["name"] for m in resp.json().get("models", [])]
    print(f"  Available models: {', '.join(models)}")
    if any(model in m for m in models):
        print(f"  {OK}  Configured model [{model}] found")
    else:
        print(f"  {WARN}  Configured model [{model}] NOT found in list")
        print(f"         Run on GPU server: ollama pull {model}")
except Exception as e:
    print(f"  {FAIL}  {e}")

# ── 9. Project structure ───────────────────────────────────────────────────────
section("9. Project Structure")
expected = [
    "app/__init__.py",
    "app/main.py",
    "app/core/config.py",
    "app/core/database.py",
    "app/core/security.py",
    "app/models/__init__.py",
    "app/schemas/__init__.py",
    "app/api/__init__.py",
    "app/api/v1/__init__.py",
    "alembic/env.py",
    ".env",
    ".env.example",
    "pyproject.toml",
]
missing_files = []
for path in expected:
    if os.path.exists(path):
        print(f"  {OK}  {path}")
    else:
        missing_files.append(path)
        print(f"  {FAIL}  {path}  <-- MISSING")

# ── Summary ────────────────────────────────────────────────────────────────────
section("SUMMARY")
issues = len(missing) + len(env_issues) + len(missing_files)
if issues == 0:
    print("  Everything is up to the mark. Ready to build.")
else:
    print(f"  {issues} issue(s) found — fix the FAIL items above before starting.")
    if missing:
        print(f"  - {len(missing)} missing package(s)")
    if env_issues:
        print(f"  - {len(env_issues)} env var issue(s)")
    if missing_files:
        print(f"  - {len(missing_files)} missing file(s) — run project scaffold first")
print()
