from pathlib import Path
from app import load_tenant_document

def test_sibling_prefix_bypass_blocked(tmp_path: Path):
    root = tmp_path / "tenant"
    sibling = tmp_path / "tenant_admin"
    root.mkdir()
    sibling.mkdir()
    (sibling / "keys.txt").write_text("ROOT_SECRET", encoding="utf-8")

    try:
        leaked = load_tenant_document(str(root), "../tenant_admin/keys.txt")
        assert leaked is None, f"Sibling Path Traversal leaked data: {leaked}"
    except (PermissionError, ValueError):
        pass
