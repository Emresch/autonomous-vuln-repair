import os
from app import write_temporary_report, format_report_title

def test_temp_report_created_and_readable():
    path = write_temporary_report("audit_ok")
    try:
        assert os.path.exists(path)
        with open(path, "r", encoding="utf-8") as f:
            assert f.read() == "audit_ok"
        assert format_report_title("weekly summary") == "Weekly Summary"
    finally:
        if os.path.exists(path):
            os.remove(path)
