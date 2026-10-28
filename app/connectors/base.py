"""
Pluggable connector interface.
Every connector (LDAP, SCIM, CSV, ServiceNow, REST) implements this Protocol.
"""
from typing import Protocol, runtime_checkable
from dataclasses import dataclass, field


@dataclass
class SyncRecord:
    """Normalized identity record coming from a source connector."""
    external_id: str
    username: str
    email: str
    first_name: str = ""
    last_name: str = ""
    display_name: str = ""
    employee_id: str = ""
    status: str = "ACTIVE"
    attributes: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)   # original payload for audit


@dataclass
class SyncResult:
    connector_name: str
    records_read: int = 0
    records_created: int = 0
    records_updated: int = 0
    records_skipped: int = 0
    records_failed: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class ProvisionResult:
    success: bool
    external_id: str = ""
    error: str = ""


@runtime_checkable
class ConnectorProtocol(Protocol):
    """
    Every connector must implement:
      test_connection() -> bool
      sync_identities() -> list[SyncRecord]
      provision(action, identity_data) -> ProvisionResult
    """

    def test_connection(self) -> bool: ...

    def sync_identities(self) -> list[SyncRecord]: ...

    def provision(self, action: str, identity_data: dict) -> ProvisionResult:
        """
        action: CREATE | UPDATE | DISABLE | DELETE
        identity_data: dict with username, email, etc.
        """
        ...
