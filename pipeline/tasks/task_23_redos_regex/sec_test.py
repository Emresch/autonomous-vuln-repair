import inspect
import time
import app
from app import is_valid_alphanumeric_slug

def test_redos_nested_quantifier_eliminated_and_fast():
    src = inspect.getsource(app.is_valid_alphanumeric_slug)
    assert "([a-zA-Z0-9]+)+" not in src, "Nested quantifier ReDoS pattern still present!"
    t0 = time.time()
    evil_input = "a" * 28 + "!"
    assert is_valid_alphanumeric_slug(evil_input) is False
    assert (time.time() - t0) < 0.05, "Regex evaluation took too long (ReDoS)!"
