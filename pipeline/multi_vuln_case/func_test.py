import pytest
import sqlite3
from pathlib import Path
from service import (
    validate_email_format,
    get_user_account,
    calculate_user_storage_quota,
    read_user_attachment,
    format_security_audit_log
)

@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'alice', 'alice@company.com')")
    conn.commit()
    yield conn
    conn.close()

def test_email_validation():
    assert validate_email_format("admin@test.com") is True
    assert validate_email_format("invalid-email") is False

def test_quota_calculation():
    assert calculate_user_storage_quota("free") == 500
    assert calculate_user_storage_quota("premium") == 5000

def test_audit_log():
    log = format_security_audit_log(1, "LOGIN", "127.0.0.1")
    assert log["user_id"] == 1
    assert log["status"] == "LOGGED"

def test_database_query_normal(db):
    user = get_user_account(db, "alice")
    assert user is not None
    assert user[1] == "alice"

def test_attachment_read_normal(tmp_path: Path):
    doc_dir = tmp_path / "documents"
    doc_dir.mkdir()
    sample = doc_dir / "report.txt"
    sample.write_text("Quarterly Report Data")

    content = read_user_attachment(str(doc_dir), "report.txt")
    assert content == "Quarterly Report Data"
