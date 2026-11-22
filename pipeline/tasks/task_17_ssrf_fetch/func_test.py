import io
from app import validate_and_open_webhook, get_user_agent

class DummyResp:
    def __init__(self, text: str):
        self._buf = io.BytesIO(text.encode("utf-8"))
    def read(self):
        return self._buf.read()
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass

def test_allowed_public_https_webhook():
    res = validate_and_open_webhook("https://93.184.216.34/hook", opener=lambda u, timeout=3: DummyResp("OK"))
    assert res == "OK"
    assert "AVR" in get_user_agent()
