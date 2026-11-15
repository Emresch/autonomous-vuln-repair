import pytest
from app import init_db, get_user_by_username

@pytest.fixture
def db():
    conn = init_db(":memory:")
    yield conn
    conn.close()

def test_sql_injection_bypass(db):
    """
    Exploit Testi:
    Kötü niyetli kullanıcı adı girişi (' OR '1'='1) ile kimlik denetimini aşma girişimi.
    - Kod ZAFİYETLİ ise: Enjeksiyon çalışır ve Alice'in verisini döner -> TEST BAŞARISIZ OLUR (FAIL).
    - Kod GÜVENLİ (yamalanmış) ise: Bu isimde bir kullanıcı olmadığı için None döner -> TEST GEÇER (PASS).
    """
    exploit_payload = "' OR '1'='1"
    user = get_user_by_username(db, exploit_payload)
    
    # Güvenli sistemde bu payload ile kullanıcı bulunamamalıdır (None dönmelidir)
    assert user is None, f"GÜVENLİK AÇIĞI TESPİT EDİLDİ! Exploit başarılı oldu, dönen veri: {user}"
