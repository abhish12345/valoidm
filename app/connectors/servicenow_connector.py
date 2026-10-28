"""
ServiceNow REST connector.
Creates/updates/disables users in ServiceNow sys_user table.
Config: instance_url, username, password (or oauth_token)
"""
import logging
import httpx
from .base import ConnectorProtocol, SyncRecord, ProvisionResult

log = logging.getLogger(__name__)


class ServiceNowConnector:
    def __init__(self, config: dict):
        self.instance_url = config.get("instance_url", "").rstrip("/")
        self.username     = config.get("username", "")
        self.password     = config.get("password", "")
        self.auth         = (self.username, self.password)

    def test_connection(self) -> bool:
        try:
            r = httpx.get(
                f"{self.instance_url}/api/now/table/sys_user?sysparm_limit=1",
                auth=self.auth, timeout=5,
            )
            return r.status_code < 300
        except Exception:
            return False

    def sync_identities(self) -> list[SyncRecord]:
        return []   # ServiceNow is typically a target, not a source

    def provision(self, action: str, identity_data: dict) -> ProvisionResult:
        if action == "CREATE":
            return self._create(identity_data)
        elif action in ("UPDATE", "DISABLE"):
            return self._update(identity_data, disable=(action == "DISABLE"))
        elif action == "DELETE":
            return self._disable_user(identity_data)  # soft-delete
        return ProvisionResult(success=False, error=f"Unsupported action: {action}")

    def _create(self, data: dict) -> ProvisionResult:
        payload = {
            "user_name":  data.get("username", ""),
            "email":      data.get("email", ""),
            "first_name": data.get("first_name", ""),
            "last_name":  data.get("last_name", ""),
            "active":     "true",
        }
        try:
            r = httpx.post(
                f"{self.instance_url}/api/now/table/sys_user",
                auth=self.auth, json=payload,
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                timeout=10,
            )
            if r.status_code in (200, 201):
                ext_id = r.json().get("result", {}).get("sys_id", "")
                return ProvisionResult(success=True, external_id=ext_id)
            return ProvisionResult(success=False, error=f"SN {r.status_code}: {r.text[:200]}")
        except Exception as exc:
            return ProvisionResult(success=False, error=str(exc))

    def _update(self, data: dict, disable: bool = False) -> ProvisionResult:
        ext_id = data.get("external_id", "")
        if not ext_id:
            return ProvisionResult(success=False, error="external_id (sys_id) required")
        payload: dict = {}
        if data.get("email"):
            payload["email"] = data["email"]
        if disable:
            payload["active"] = "false"
        try:
            r = httpx.patch(
                f"{self.instance_url}/api/now/table/sys_user/{ext_id}",
                auth=self.auth, json=payload,
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                timeout=10,
            )
            return ProvisionResult(success=r.status_code < 300, external_id=ext_id)
        except Exception as exc:
            return ProvisionResult(success=False, error=str(exc))

    def _disable_user(self, data: dict) -> ProvisionResult:
        return self._update(data, disable=True)
