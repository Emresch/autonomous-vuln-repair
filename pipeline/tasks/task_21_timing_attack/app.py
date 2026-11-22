import hashlib
import hmac

def compute_webhook_signature(secret_key: str, body: str) -> str:
    return hmac.new(secret_key.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()

def verify_webhook_signature(secret_key: str, body: str, provided_token: str) -> bool:
    expected_secret = compute_webhook_signature(secret_key, body)
    return provided_token == expected_secret
