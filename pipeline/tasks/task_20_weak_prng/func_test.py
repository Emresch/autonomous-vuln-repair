from app import generate_password_reset_code, get_token_min_length, ALPHABET

def test_reset_code_format_and_length():
    code = generate_password_reset_code(24)
    assert len(code) == 24
    assert all(ch in ALPHABET for ch in code)
    assert get_token_min_length() == 16
