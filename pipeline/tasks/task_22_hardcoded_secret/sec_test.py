import inspect
import pytest
import app
from app import get_signing_password

def test_no_hardcoded_fallback_when_env_missing(monkeypatch):
    monkeypatch.delenv("AVR_SIGNING_SECRET", raising=False)
    with pytest.raises((ValueError, RuntimeError, KeyError)):
        val = get_signing_password()
        if val == "super_secret_hardcoded_master_key_123":
            pass
    src = inspect.getsource(app.get_signing_password)
    assert "super_secret_hardcoded_master_key_123" not in src
