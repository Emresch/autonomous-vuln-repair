import pytest
import sqlite3
from pathlib import Path
from service import get_user_account, read_user_attachment

@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'alice', 'alice@company.com')")
    conn.commit()
    yield conn
    conn.close()

def test_exploit_sql_injection(db):
    """Exploit 1: SQL Injection ile kimlik doğrulama baypası."""
    exploit_payload = "' OR '1'='1"
    user = get_user_account(db, exploit_payload)
    assert user is None, f"SQL Injection Zafiyeti Mevcut! Veri sızdı: {user}"

def test_exploit_path_traversal(tmp_path: Path):
    """Exploit 2: Path Traversal ile gizli dizindeki dosyayı okuma."""
    doc_dir = tmp_path / "documents"
    secret_dir = tmp_path / "documents_secret"
    doc_dir.mkdir()
    secret_dir.mkdir()

    secret_file = secret_dir / "passwords.txt"
    secret_file.write_text("SUPER_SECRET_KEYS")

    # Saldırgan ../documents_secret/passwords.txt ister
    content = read_user_attachment(str(doc_dir), "../documents_secret/passwords.txt")
    assert content is None, f"Path Traversal Zafiyeti Mevcut! Gizli dosya okundu: {content}"
