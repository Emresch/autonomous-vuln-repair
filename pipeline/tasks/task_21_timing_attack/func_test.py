from app import compute_webhook_signature, verify_webhook_signature

def test_valid_and_invalid_signatures():
    sig = compute_webhook_signature("my_key", "payload_1")
    assert verify_webhook_signature("my_key", "payload_1", sig) is True
    assert verify_webhook_signature("my_key", "payload_1", "wrong_sig") is False
