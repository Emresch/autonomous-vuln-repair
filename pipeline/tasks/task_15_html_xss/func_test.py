from app import render_user_profile_card, format_badge_label

def test_normal_profile_render():
    out = render_user_profile_card("Alice", "Security Researcher")
    assert "<h2>Alice</h2>" in out
    assert "<p>Security Researcher</p>" in out
    assert format_badge_label("admin") == "ADMIN"
