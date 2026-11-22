from app import hash_sensitive_token, format_digest_prefix

def test_deterministic_token_hashing():
    h1 = hash_sensitive_token("secret123", "saltA")
    h2 = hash_sensitive_token("secret123", "saltA")
    h3 = hash_sensitive_token("other", "saltA")
    assert isinstance(h1, str) and h1 == h2 and h1 != h3
    assert format_digest_prefix("abcdef123456") == "HASH:abcdef12"
