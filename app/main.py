from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1.routers import (
    auth, identities, lifecycle, org_units,
    roles, requests, certifications, audit,
    connectors, scim, agents,
)

app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0",
    description="Identity Governance & Administration — Python/FastAPI",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PREFIX = "/api/v1"
app.include_router(auth.router,            prefix=PREFIX)
app.include_router(identities.router,      prefix=PREFIX)
app.include_router(lifecycle.router,       prefix=PREFIX)
app.include_router(org_units.router,       prefix=PREFIX)
app.include_router(roles.router,           prefix=PREFIX)
app.include_router(requests.router,        prefix=PREFIX)
app.include_router(certifications.router,  prefix=PREFIX)
app.include_router(audit.router,           prefix=PREFIX)
app.include_router(connectors.router,      prefix=PREFIX)
app.include_router(scim.router,            prefix=PREFIX)
app.include_router(agents.router,          prefix=PREFIX)


@app.get("/health", tags=["system"])
async def health():
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "environment": settings.ENVIRONMENT,
        "version": "0.1.0",
    }


@app.get("/", tags=["system"])
async def root():
    return {"message": f"Welcome to {settings.APP_NAME}", "docs": "/docs"}
