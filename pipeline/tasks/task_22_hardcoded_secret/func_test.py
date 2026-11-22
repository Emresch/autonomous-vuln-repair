import os
from app import get_signing_password, format_auth_header

def test_reads_secret_from_environment(monkeypatch):
    monkeypatch.setenv("AVR_SIGNING_SECRET", "runtime_secret_xyz")
    assert get_signing_password() == "runtime_secret_xyz"
    assert format_auth_header("abc") == "Bearer abc"
