import pytest
from app import validate_and_open_webhook

def test_ssrf_internal_and_file_urls_rejected():
    forbidden_urls = [
        "http://127.0.0.1:8000/admin",
        "http://localhost/secret",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
    ]
    for bad_url in forbidden_urls:
        with pytest.raises((ValueError, PermissionError)):
            validate_and_open_webhook(bad_url, opener=lambda u, timeout=3: None)
