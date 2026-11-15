import pytest
from app import init_db, get_user_by_username, count_total_users

@pytest.fixture
def db():
    conn = init_db(":memory:")
    yield conn
    conn.close()

def test_get_existing_user(db):
    """Mevcut bir kullanıcının doğru şekilde getirildiğini test eder."""
    user = get_user_by_username(db, "alice")
    assert user is not None, "Alice bulunamadı!"
    assert user[1] == "alice"
    assert user[2] == "alice@example.com"

def test_get_nonexistent_user(db):
    """Olmayan bir kullanıcı sorgulandığında None döndüğünü test eder."""
    user = get_user_by_username(db, "charlie")
    assert user is None, "Olmayan kullanıcı için veri döndü!"

def test_user_count(db):
    """Toplam kullanıcı sayısının doğruluğunu test eder."""
    total = count_total_users(db)
    assert total == 2
