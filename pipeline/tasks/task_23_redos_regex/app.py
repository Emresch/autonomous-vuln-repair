import re

def normalize_username(text: str) -> str:
    return text.strip().lower()

def is_valid_alphanumeric_slug(slug: str) -> bool:
    return bool(re.match(r"^([a-zA-Z0-9]+)+$", slug))
