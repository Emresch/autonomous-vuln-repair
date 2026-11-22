import inspect
import random
import app
from app import generate_password_reset_code

def test_csprng_secrets_used_instead_of_mersenne_twister():
    random.seed(1337)
    t1 = generate_password_reset_code(24)
    random.seed(1337)
    t2 = generate_password_reset_code(24)
    assert t1 != t2, "Token generation is predictable via random.seed()!"
    src = inspect.getsource(app.generate_password_reset_code)
    assert "secrets." in src
