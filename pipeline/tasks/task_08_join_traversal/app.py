import os
from typing import Optional

def format_log_header(name: str) -> str:
    return f"[LOG:{name}]"

def read_log_file(logs_dir: str, log_name: str) -> Optional[str]:
    target = os.path.join(logs_dir, log_name)
    if not os.path.exists(target):
        return None
    with open(target, "r", encoding="utf-8") as f:
        return f.read()
