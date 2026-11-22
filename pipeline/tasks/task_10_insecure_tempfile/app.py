import os
import tempfile

def format_report_title(title: str) -> str:
    return title.strip().title()

def write_temporary_report(content: str) -> str:
    tmp_path = tempfile.mktemp(prefix="avr_report_", suffix=".txt")
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)
    return tmp_path
