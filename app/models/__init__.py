# Import all models here so Alembic autogenerate can detect them
from app.models.tenant import Tenant
from app.models.identity import Identity
from app.models.audit import AuditLog
from app.models.org_unit import OrgUnit
from app.models.role import Role, RoleConflict, RoleAssignment
from app.models.workflow import AccessRequest
from app.models.certification import CertificationCampaign, CertificationItem
from app.models.connector import Connector, WebhookSubscription

__all__ = [
    "Tenant", "Identity", "AuditLog", "OrgUnit",
    "Role", "RoleConflict", "RoleAssignment",
    "AccessRequest",
    "CertificationCampaign", "CertificationItem",
    "Connector", "WebhookSubscription",
]
