from app import build_download_disposition_header, get_cookie_path

def test_valid_disposition_header():
    hdr = build_download_disposition_header("report_2026.pdf")
    assert hdr == "Content-Disposition: attachment; filename=report_2026.pdf"
    assert get_cookie_path() == "/"
