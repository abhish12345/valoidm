"""
CSV bulk-import connector.
Parses an uploaded CSV file and returns SyncRecords.

Expected CSV columns (configurable via column_map):
    username, email, first_name, last_name, employee_id, status
"""
import csv
import io
import logging
from .base import ConnectorProtocol, SyncRecord, ProvisionResult

log = logging.getLogger(__name__)

DEFAULT_COLUMN_MAP = {
    "username":    ["username", "user_name", "login", "samaccountname"],
    "email":       ["email", "mail", "email_address"],
    "first_name":  ["first_name", "firstname", "givenname", "given_name"],
    "last_name":   ["last_name", "lastname", "surname", "sn"],
    "employee_id": ["employee_id", "employeeid", "emp_id", "staff_id"],
    "status":      ["status", "account_status", "active"],
}


class CSVConnector:
    def __init__(self, config: dict):
        self.column_map = config.get("column_map", DEFAULT_COLUMN_MAP)
        self.delimiter  = config.get("delimiter", ",")
        self.encoding   = config.get("encoding", "utf-8")

    def test_connection(self) -> bool:
        return True   # CSV is always "reachable"

    def sync_identities(self) -> list[SyncRecord]:
        # Not used directly — call parse_csv() instead
        return []

    def provision(self, action: str, identity_data: dict) -> ProvisionResult:
        # CSV is read-only — provisioning not supported
        return ProvisionResult(
            success=False,
            error="CSV connector is read-only (source only)"
        )

    def parse_csv(self, content: str | bytes) -> tuple[list[SyncRecord], list[str]]:
        """
        Parse CSV content.
        Returns (valid_records, error_lines).
        """
        if isinstance(content, bytes):
            content = content.decode(self.encoding, errors="replace")

        reader = csv.DictReader(io.StringIO(content), delimiter=self.delimiter)
        records: list[SyncRecord] = []
        errors: list[str] = []

        if not reader.fieldnames:
            return [], ["CSV file has no header row"]

        # Build header → field mapping
        headers = [h.strip().lower() for h in reader.fieldnames]
        col_idx: dict[str, str] = {}
        for field_name, aliases in self.column_map.items():
            for alias in aliases:
                if alias.lower() in headers:
                    col_idx[field_name] = alias.lower()
                    break

        if "username" not in col_idx or "email" not in col_idx:
            return [], ["CSV missing required columns: username, email"]

        for line_num, row in enumerate(reader, start=2):
            # Normalize keys
            row_lower = {k.strip().lower(): v.strip() for k, v in row.items() if k}

            username = row_lower.get(col_idx.get("username", ""), "").lower()
            email    = row_lower.get(col_idx.get("email", ""), "").lower()

            if not username:
                errors.append(f"Line {line_num}: missing username — skipped")
                continue
            if not email or "@" not in email:
                errors.append(f"Line {line_num}: invalid email '{email}' for user '{username}'")
                continue

            status_raw = row_lower.get(col_idx.get("status", ""), "active").lower()
            status = "ACTIVE" if status_raw in ("active", "true", "1", "yes", "") else "INACTIVE"

            records.append(SyncRecord(
                external_id=username,
                username=username,
                email=email,
                first_name=row_lower.get(col_idx.get("first_name", ""), ""),
                last_name=row_lower.get(col_idx.get("last_name", ""), ""),
                employee_id=row_lower.get(col_idx.get("employee_id", ""), ""),
                status=status,
                raw=dict(row_lower),
            ))

        return records, errors
