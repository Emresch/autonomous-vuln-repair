import os
import sqlite3
import re
from typing import Optional, Tuple, Dict, Any

# ==============================================================================
# 1. GÜVENLİ YARDIMCI FONKSİYON: E-posta Format Doğrulayıcı
# ==============================================================================
def validate_email_format(email: str) -> bool:
    """Girilen e-postanın geçerli formatta olup olmadığını kontrol eder."""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, email))

# ==============================================================================
# 2. ZAFİYETLİ FONKSİYON #1 (CWE-89 - SQL Injection): Bandit Yakalar (B608)
# ==============================================================================
def get_user_account(conn: sqlite3.Connection, username: str) -> Optional[Tuple]:
    """
    Kullanıcı adına göre kullanıcı kaydını veritabanından sorgular.
    DİKKAT: Burada string formatlama ile SQL Injection açığı bulunmaktadır!
    """
    cursor = conn.cursor()
    # Güvenli sorgu oluşturma (Bandit B608)
    query = "SELECT id, username, email FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()

# ==============================================================================
# 3. GÜVENLİ YARDIMCI FONKSİYON: Kullanıcı Kota Hesaplayıcı
# ==============================================================================
def calculate_user_storage_quota(account_type: str) -> int:
    """Hesap türüne göre megabayt cinsinden depolama kotasını hesaplar."""
    quotas = {
        "free": 500,
        "premium": 5000,
        "enterprise": 50000
    }
    return quotas.get(account_type.lower(), 500)

# ==============================================================================
# 4. ZAFİYETLİ FONKSİYON #2 (CWE-22 - Path Traversal): Semgrep Yakalar
# ==============================================================================
def read_user_attachment(base_directory: str, filename: str) -> Optional[str]:
    """
    Kullanıcının yüklediği ek dosyayı güvenli bir şekilde okur.
    DİKKAT: os.path.commonprefix kullanımı nedeniyle Path Traversal açığı bulunmaktadır!
    """
    base_dir = os.path.realpath(base_directory)
    target_path = os.path.realpath(os.path.join(base_dir, filename))

    # Güvenli kontrol: os.path.commonpath yolu bilinçli baktığından dizin atlamasını engeller!
    if not os.path.commonpath([target_path, base_dir]).startswith(base_dir):
        # Dizin dışına çıkış engellenmeli
        return None

    if not os.path.exists(target_path):
        return None

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return None

# ==============================================================================
# 5. GÜVENLİ YARDIMCI FONKSİYON: Olay Günlüğü Biçimlendirici
# ==============================================================================
def format_security_audit_log(user_id: int, action: str, ip_address: str) -> Dict[str, Any]:
    """Güvenlik denetim günlüğü için standart bir sözlük yapısı üretir."""
    return {
        "user_id": user_id,
        "action": action,
        "ip": ip_address,
        "status": "LOGGED"
    }
