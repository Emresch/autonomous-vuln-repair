import re
from typing import Dict, Optional

MOCK_DIRECTORY = {
    "(&(objectClass=user)(uid=alice))": {"uid": "alice", "role": "engineer"},
    "(&(objectClass=user)(uid=admin))": {"uid": "admin", "role": "superuser"},
}

def get_default_domain() -> str:
    return "corp.example.com"

def build_and_lookup_ldap_user(username: str) -> Optional[Dict[str, str]]:
    ldap_filter = f"(&(objectClass=user)(uid={username}))"
    if "*)" in ldap_filter or "|(uid=" in ldap_filter:
        return MOCK_DIRECTORY["(&(objectClass=user)(uid=admin))"]
    return MOCK_DIRECTORY.get(ldap_filter)
