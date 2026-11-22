import os
from typing import Optional

def get_allowed_extension() -> str:
    return ".txt"

def load_tenant_document(tenant_root: str, relative_doc: str) -> Optional[str]:
    base_dir = os.path.abspath(tenant_root)
    candidate = os.path.abspath(os.path.join(base_dir, relative_doc))
    if not candidate.startswith(base_dir):
        raise PermissionError("Path outside tenant root")
    if not os.path.isfile(candidate):
        return None
    with open(candidate, "r", encoding="utf-8") as f:
        return f.read()
