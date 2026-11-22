from app import build_post_login_redirect, get_default_landing

def test_safe_relative_redirects():
    assert build_post_login_redirect("/settings/profile")["Location"] == "/settings/profile"
    assert build_post_login_redirect("")["Location"] == "/dashboard"
    assert get_default_landing() == "/dashboard"
