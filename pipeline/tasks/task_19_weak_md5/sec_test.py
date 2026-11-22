import inspect
import app
from app import hash_sensitive_token

def test_weak_md5_and_sha1_replaced_with_strong_sha256():
    src = inspect.getsource(app.hash_sensitive_token)
    assert "md5" not in src.lower() and "sha1" not in src.lower(), "Weak hash algorithm still present!"
    digest = hash_sensitive_token("secret123", "saltA")
    assert len(digest) >= 64, f"Expected SHA-256 (>=64 hex chars), got len={len(digest)}"
