from app import render_user_profile_card

def test_xss_script_tags_properly_escaped():
    out = render_user_profile_card("<script>alert(1)</script>", "<img src=x onerror=alert(2)>")
    assert "<script>" not in out, f"Unescaped <script> tag in output: {out}"
    assert "<img " not in out, f"Unescaped <img> tag in output: {out}"
    assert "&lt;script&gt;" in out
