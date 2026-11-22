from app import build_download_disposition_header

def test_crlf_response_splitting_blocked():
    payload = "report.pdf\r\nSet-Cookie: role=admin"
    try:
        hdr = build_download_disposition_header(payload)
        assert "\r" not in hdr and "\n" not in hdr, f"CRLF characters remained in header: {hdr!r}"
        assert len(hdr.splitlines()) == 1, f"HTTP header split into multiple lines: {hdr!r}"
    except ValueError:
        pass
