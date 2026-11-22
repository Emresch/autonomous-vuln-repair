import inspect
import app

def test_constant_time_compare_digest_used():
    src = inspect.getsource(app.verify_webhook_signature)
    assert "compare_digest" in src, "Constant-time hmac.compare_digest() must be used!"
    assert "==" not in src, "Non-constant-time '==' operator still present!"
