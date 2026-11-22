from pathlib import Path
from app import read_log_file, format_log_header

def test_read_normal_log(tmp_path: Path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "app.log").write_text("INFO: started", encoding="utf-8")
    assert read_log_file(str(logs), "app.log") == "INFO: started"
    assert read_log_file(str(logs), "none.log") is None
    assert format_log_header("app") == "[LOG:app]"
