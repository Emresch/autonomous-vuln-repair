from app import build_and_lookup_ldap_user, get_default_domain

def test_valid_ldap_user():
    user = build_and_lookup_ldap_user("alice")
    assert user is not None
    assert user["uid"] == "alice"
    assert get_default_domain() == "corp.example.com"

def test_unknown_ldap_user():
    assert build_and_lookup_ldap_user("bob") is None
