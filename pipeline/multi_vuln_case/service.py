import os
import sqlite3
import re
from typing import Optional, Tuple, Dict, Any

def validate_email_format(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, email))

def get_user_account(conn: sqlite3.Connection, username: str) -> Optional[Tuple]:
    cursor = conn.cursor()
    query = "SELECT id, username, email FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()

def calculate_user_storage_quota(account_type: str) -> int:
    quotas = {"free": 500, "premium": 5000, "enterprise": 50000}
    return quotas.get(account_type.lower(), 500)

import os
import sqlite3
import re
from typing import Optional, Tuple, Dict, Any

def read_user_attachment(base_directory: str, filename: str) -> Optional[str]:
    base_dir = os.path.realpath(base_directory)
    target_path = os.path.realpath(os.path.join(base_dir, filename))
    if not os.path.commonpath([target_path, base_dir]).startswith(base_dir):
        return None
    if not os.path.exists(target_path):
        return None
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return None

def format_security_audit_log(user_id: int, action: str, ip_address: str) -> Dict[str, Any]:
    return {"user_id": user_id, "action": action, "ip": ip_address, "status": "LOGGED"}
