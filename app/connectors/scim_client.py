"""
SCIM 2.0 outbound client — provisions identities to a SCIM-compliant target.
"""
import logging
import httpx
from .base import ConnectorProtocol, SyncRecord, ProvisionResult

log = logging.getLogger(__name__)


class SCIMClient:
    """
    Calls a remote SCIM 2.0 server to provision/deprovision users.
    Config keys: base_url, token, verify_ssl
    """

    def __init__(self, config: dict):
        self.base_url   = config.get("base_url", "").rstrip("/")
        self.token      = config.get("token", "")
        self.verify_ssl = config.get("verify_ssl", True)
        self._headers   = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type":  "application/scim+json",
            "Accept":        "application/scim+json",
        }

    def test_connection(self) -> bool:
        try:
            r = httpx.get(
                f"{self.base_url}/ServiceProviderConfig",
                headers=self._headers,
                verify=self.verify_ssl,
                timeout=5,
            )
            return r.status_code < 300
        except Exception:
            return False

    def sync_identities(self) -> list[SyncRecord]:
        # Outbound-only client — reading back is optional
        return []

    def provision(self, action: str, identity_data: dict) -> ProvisionResult:
        if action == "CREATE":
            return self._create(identity_data)
        elif action == "UPDATE":
            return self._update(identity_data)
        elif action == "DISABLE":
            return self._patch_active(identity_data, active=False)
        elif action == "DELETE":
            return self._delete(identity_data)
        return ProvisionResult(success=False, error=f"Unsupported action: {action}")

    def _create(self, data: dict) -> ProvisionResult:
        payload = {
            "schemas":    ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName":   data.get("username", ""),
            "name":       {
                "givenName":  data.get("first_name", ""),
                "familyName": data.get("last_name", ""),
            },
            "emails":     [{"value": data.get("email", ""), "primary": True}],
            "active":     True,
        }
        try:
            r = httpx.post(
                f"{self.base_url}/Users",
                json=payload, headers=self._headers,
                verify=self.verify_ssl, timeout=10,
            )
            if r.status_code in (200, 201):
                ext_id = r.json().get("id", "")
                return ProvisionResult(success=True, external_id=ext_id)
            return ProvisionResult(success=False, error=f"SCIM CREATE {r.status_code}: {r.text[:200]}")
        except Exception as exc:
            return ProvisionResult(success=False, error=str(exc))

    def _update(self, data: dict) -> ProvisionResult:
        ext_id = data.get("external_id", "")
        if not ext_id:
            return ProvisionResult(success=False, error="external_id required for UPDATE")
        payload = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "name": {
                "givenName":  data.get("first_name", ""),
                "familyName": data.get("last_name", ""),
            },
        }
        try:
            r = httpx.put(
                f"{self.base_url}/Users/{ext_id}",
                json=payload, headers=self._headers,
                verify=self.verify_ssl, timeout=10,
            )
            return ProvisionResult(success=r.status_code < 300, external_id=ext_id,
                                   error="" if r.status_code < 300 else r.text[:200])
        except Exception as exc:
            return ProvisionResult(success=False, error=str(exc))

    def _patch_active(self, data: dict, active: bool) -> ProvisionResult:
        ext_id = data.get("external_id", "")
        if not ext_id:
            return ProvisionResult(success=False, error="external_id required")
        payload = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": active}],
        }
        try:
            r = httpx.patch(
                f"{self.base_url}/Users/{ext_id}",
                json=payload, headers=self._headers,
                verify=self.verify_ssl, timeout=10,
            )
            return ProvisionResult(success=r.status_code < 300, external_id=ext_id)
        except Exception as exc:
            return ProvisionResult(success=False, error=str(exc))

    def _delete(self, data: dict) -> ProvisionResult:
        ext_id = data.get("external_id", "")
        if not ext_id:
            return ProvisionResult(success=False, error="external_id required")
        try:
            r = httpx.delete(
                f"{self.base_url}/Users/{ext_id}",
                headers=self._headers, verify=self.verify_ssl, timeout=10,
            )
            return ProvisionResult(success=r.status_code in (200, 204), external_id=ext_id)
        except Exception as exc:
            return ProvisionResult(success=False, error=str(exc))
