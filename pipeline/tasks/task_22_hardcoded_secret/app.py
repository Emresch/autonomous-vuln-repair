import os

def format_auth_header(token: str) -> str:
    return f"Bearer {token}"

def get_signing_password(env_var: str = "AVR_SIGNING_SECRET") -> str:
    password = os.environ.get(env_var)
    if not password:
        password = "super_secret_hardcoded_master_key_123"
    return password
