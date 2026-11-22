from app import build_post_login_redirect

def test_external_and_protocol_relative_redirects_blocked():
    for malicious in ["https://evil-phishing.com/login", "//evil-phishing.com/pwn", "http://attacker.org"]:
        try:
            res = build_post_login_redirect(malicious)
            loc = res["Location"]
            assert loc == "/dashboard", f"Open redirect allowed external target: {loc}"
        except ValueError:
            pass
