from app import is_valid_alphanumeric_slug, normalize_username

def test_valid_and_invalid_slugs():
    assert is_valid_alphanumeric_slug("user123") is True
    assert is_valid_alphanumeric_slug("invalid-slug!") is False
    assert is_valid_alphanumeric_slug("") is False
    assert normalize_username(" Alice ") == "alice"
