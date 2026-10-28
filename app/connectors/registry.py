"""
Connector factory — returns the right connector for a given type.
"""
from .base import ConnectorProtocol
from .ldap_connector import LDAPConnector
from .csv_connector import CSVConnector


def get_connector(connector_type: str, config: dict) -> ConnectorProtocol:
    ct = connector_type.upper()
    if ct == "LDAP":
        return LDAPConnector(config)
    elif ct == "CSV":
        return CSVConnector(config)
    elif ct == "SCIM":
        from .scim_client import SCIMClient
        return SCIMClient(config)
    elif ct == "SERVICENOW":
        from .servicenow_connector import ServiceNowConnector
        return ServiceNowConnector(config)
    else:
        raise ValueError(f"Unknown connector type: {connector_type}")
