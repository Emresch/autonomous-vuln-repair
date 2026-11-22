import hashlib

def format_digest_prefix(digest: str) -> str:
    return f"HASH:{digest[:8]}"

def hash_sensitive_token(token: str, salt: str = "static_salt") -> str:
    payload = f"{salt}:{token}".encode("utf-8")
    return hashlib.md5(payload).hexdigest()
