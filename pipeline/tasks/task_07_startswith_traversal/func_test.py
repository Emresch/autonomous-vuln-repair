from pathlib import Path
from app import load_tenant_document, get_allowed_extension

def test_valid_tenant_doc(tmp_path: Path):
    root = tmp_path / "tenant"
    root.mkdir()
    (root / "notes.txt").write_text("hello tenant", encoding="utf-8")
    assert load_tenant_document(str(root), "notes.txt") == "hello tenant"
    assert load_tenant_document(str(root), "missing.txt") is None
    assert get_allowed_extension() == ".txt"
