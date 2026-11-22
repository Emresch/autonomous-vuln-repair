import re

def get_cookie_path() -> str:
    return "/"

def build_download_disposition_header(filename: str) -> str:
    return f"Content-Disposition: attachment; filename={filename}"
