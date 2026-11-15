import sqlite3
import hashlib

def init_db(db_path=":memory:"):
    """Veritabanını ve örnek kullanıcı tablosunu oluşturur."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT
        )
    """)
    # Örnek veri ekle
    cursor.execute("INSERT OR IGNORE INTO users (username, email) VALUES ('alice', 'alice@example.com')")
    cursor.execute("INSERT OR IGNORE INTO users (username, email) VALUES ('bob', 'bob@example.com')")
    conn.commit()
    return conn

def hash_username(username: str) -> str:
    """Kullanıcı adının SHA-256 özetini döndüren yardımcı fonksiyon."""
    return hashlib.sha256(username.encode()).hexdigest()

def get_user_by_username(conn, username: str):
    """
    Belirtilen kullanıcı adına sahip kullanıcıyı getirir.
    DİKKAT: Burada bilinçli bir SQL Injection açığı bulunmaktadır (CWE-89).
    """
    cursor = conn.cursor()
    # Güvenli parametreli sorgu kullanımı (Bandit B608 uyarısı çözülür)
    query = "SELECT id, username, email FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()

def count_total_users(conn) -> int:
    """Toplam kayıtlı kullanıcı sayısını döndürür."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    res = cursor.fetchone()
    return res[0] if res else 0
