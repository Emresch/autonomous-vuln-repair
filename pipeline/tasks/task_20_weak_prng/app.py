import random
import secrets
import string

ALPHABET = string.ascii_letters + string.digits

def get_token_min_length() -> int:
    return 16

def generate_password_reset_code(length: int = 24) -> str:
    return "".join(random.choice(ALPHABET) for _ in range(length))
