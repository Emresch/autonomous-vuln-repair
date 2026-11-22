from pathlib import Path
from app import read_log_file

def test_absolute_and_parent_path_override_blocked(tmp_path: Path):
    logs = tmp_path / "logs"
    logs.mkdir()
    outside = tmp_path / "passwd.txt"
    outside.write_text("root:x:0:0", encoding="utf-8")

    for payload in ["../passwd.txt", str(outside.resolve())]:
        try:
            res = read_log_file(str(logs), payload)
            assert res is None, f"Path traversal read outside file with {payload}: {res}"
        except (ValueError, PermissionError):
            pass
