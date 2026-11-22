from app import build_and_lookup_ldap_user

def test_ldap_wildcard_and_filter_injection_blocked():
    for payload in ["*)(|(uid=*", "admin)(|(uid=*", "alice*"]:
        try:
            res = build_and_lookup_ldap_user(payload)
            assert res is None, f"LDAP injection succeeded with payload {payload}: {res}"
        except ValueError:
            pass
