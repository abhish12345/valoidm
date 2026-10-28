"""
AD / LDAP connector using ldap3.
Supports: read (sync) + write (provision: create / update / disable / delete).

Config keys expected in connector.config:
    host          LDAP server hostname or IP
    port          389 (LDAP) or 636 (LDAPS) — default 389
    use_ssl       bool — default False
    bind_dn       e.g. CN=svc-account,DC=corp,DC=local
    bind_password stored as env-var reference in production
    base_dn       e.g. DC=corp,DC=local
    user_filter   LDAP filter e.g. (objectClass=person)
    user_base_dn  sub-OU for users e.g. OU=Users,DC=corp,DC=local
    attr_map      dict mapping LDAP attr → SyncRecord field
"""
import os
import logging
from .base import ConnectorProtocol, SyncRecord, SyncResult, ProvisionResult

log = logging.getLogger(__name__)

# Default attribute mapping  (AD field → SyncRecord field)
DEFAULT_ATTR_MAP = {
    "sAMAccountName":   "username",
    "mail":             "email",
    "givenName":        "first_name",
    "sn":               "last_name",
    "displayName":      "display_name",
    "employeeID":       "employee_id",
    "objectGUID":       "external_id",
    "userAccountControl": "_uac",   # used to derive status
}

# userAccountControl bit for DISABLED account
UAC_DISABLED = 0x0002


class LDAPConnector:
    """
    Real LDAP connector.  Falls back to a mock if ldap3 server is unreachable
    so the rest of the API keeps working during development without an AD server.
    """

    def __init__(self, config: dict):
        self.host     = config.get("host", "localhost")
        self.port     = int(config.get("port", 389))
        self.use_ssl  = bool(config.get("use_ssl", False))
        self.bind_dn  = config.get("bind_dn", "")
        # In prod, read secret from env var; fall back to config for dev
        self.password = os.getenv("LDAP_BIND_PASSWORD", config.get("bind_password", ""))
        self.base_dn  = config.get("base_dn", "")
        self.user_filter   = config.get("user_filter", "(objectClass=person)")
        self.user_base_dn  = config.get("user_base_dn") or self.base_dn
        self.attr_map = config.get("attr_map", DEFAULT_ATTR_MAP)
        self._conn = None

    # ── connection ────────────────────────────────────────────────────────────

    def _connect(self):
        try:
            from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, Tls
            server = Server(self.host, port=self.port, use_ssl=self.use_ssl, get_info=ALL)
            conn = Connection(
                server,
                user=self.bind_dn,
                password=self.password,
                authentication=SIMPLE,
                auto_bind=True,
            )
            self._conn = conn
            return True
        except Exception as exc:
            log.warning("LDAP connect failed: %s", exc)
            self._conn = None
            return False

    def test_connection(self) -> bool:
        ok = self._connect()
        if self._conn:
            self._conn.unbind()
            self._conn = None
        return ok

    # ── sync (read) ───────────────────────────────────────────────────────────

    def sync_identities(self) -> list[SyncRecord]:
        if not self._connect():
            log.warning("LDAP sync skipped — cannot connect, returning empty list")
            return []

        attrs = list(self.attr_map.keys())
        try:
            self._conn.search(
                search_base=self.user_base_dn,
                search_filter=self.user_filter,
                attributes=attrs,
            )
        except Exception as exc:
            log.error("LDAP search failed: %s", exc)
            return []

        records = []
        for entry in self._conn.entries:
            raw = {a: str(entry[a]) for a in attrs if a in entry}
            rec = self._map_entry(raw)
            if rec:
                records.append(rec)

        self._conn.unbind()
        self._conn = None
        return records

    def _map_entry(self, raw: dict) -> SyncRecord | None:
        mapped: dict = {}
        for ldap_attr, field_name in self.attr_map.items():
            val = raw.get(ldap_attr, "")
            if field_name.startswith("_"):
                continue
            mapped[field_name] = val

        if not mapped.get("username") or not mapped.get("email"):
            return None

        # Derive status from userAccountControl
        uac_raw = raw.get("userAccountControl", "0")
        try:
            uac = int(uac_raw)
            status = "INACTIVE" if uac & UAC_DISABLED else "ACTIVE"
        except ValueError:
            status = "ACTIVE"

        return SyncRecord(
            external_id=mapped.get("external_id", mapped["username"]),
            username=mapped["username"].lower(),
            email=mapped["email"].lower(),
            first_name=mapped.get("first_name", ""),
            last_name=mapped.get("last_name", ""),
            display_name=mapped.get("display_name", ""),
            employee_id=mapped.get("employee_id", ""),
            status=status,
            raw=raw,
        )

    # ── provisioning (write) ──────────────────────────────────────────────────

    def provision(self, action: str, identity_data: dict) -> ProvisionResult:
        if not self._connect():
            return ProvisionResult(success=False, error="Cannot connect to LDAP server")

        username = identity_data.get("username", "")
        dn = f"CN={username},{self.user_base_dn}"

        try:
            if action == "CREATE":
                return self._create_user(dn, identity_data)
            elif action == "UPDATE":
                return self._update_user(dn, identity_data)
            elif action == "DISABLE":
                return self._disable_user(dn)
            elif action == "DELETE":
                return self._delete_user(dn)
            else:
                return ProvisionResult(success=False, error=f"Unknown action: {action}")
        except Exception as exc:
            return ProvisionResult(success=False, error=str(exc))
        finally:
            if self._conn:
                self._conn.unbind()
                self._conn = None

    def _create_user(self, dn: str, data: dict) -> ProvisionResult:
        from ldap3 import MODIFY_REPLACE
        attrs = {
            "objectClass":    ["top", "person", "organizationalPerson", "user"],
            "sAMAccountName": data.get("username", ""),
            "mail":           data.get("email", ""),
            "givenName":      data.get("first_name", ""),
            "sn":             data.get("last_name", ""),
            "displayName":    data.get("display_name", data.get("username", "")),
        }
        ok = self._conn.add(dn, attributes=attrs)
        if ok:
            return ProvisionResult(success=True, external_id=dn)
        return ProvisionResult(success=False, error=str(self._conn.result))

    def _update_user(self, dn: str, data: dict) -> ProvisionResult:
        from ldap3 import MODIFY_REPLACE
        changes = {}
        if data.get("email"):
            changes["mail"] = [(MODIFY_REPLACE, [data["email"]])]
        if data.get("display_name"):
            changes["displayName"] = [(MODIFY_REPLACE, [data["display_name"]])]
        if not changes:
            return ProvisionResult(success=True, external_id=dn)
        ok = self._conn.modify(dn, changes)
        if ok:
            return ProvisionResult(success=True, external_id=dn)
        return ProvisionResult(success=False, error=str(self._conn.result))

    def _disable_user(self, dn: str) -> ProvisionResult:
        from ldap3 import MODIFY_REPLACE
        # Set userAccountControl bit 2 (disabled)
        ok = self._conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [514])]})
        if ok:
            return ProvisionResult(success=True, external_id=dn)
        return ProvisionResult(success=False, error=str(self._conn.result))

    def _delete_user(self, dn: str) -> ProvisionResult:
        ok = self._conn.delete(dn)
        if ok:
            return ProvisionResult(success=True, external_id=dn)
        return ProvisionResult(success=False, error=str(self._conn.result))
