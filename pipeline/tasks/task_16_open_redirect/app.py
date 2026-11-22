from urllib.parse import urlsplit
from typing import Dict, Any

DEFAULT_DASHBOARD = "/dashboard"

def get_default_landing() -> str:
    return DEFAULT_DASHBOARD

def build_post_login_redirect(next_url: str) -> Dict[str, Any]:
    target = next_url if next_url else DEFAULT_DASHBOARD
    return {"status": 302, "Location": target}
