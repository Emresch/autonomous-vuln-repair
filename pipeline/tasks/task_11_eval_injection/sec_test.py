from app import parse_client_literal_payload

def test_arbitrary_code_execution_via_eval_blocked():
    exploit = "__import__('os').system('echo PWNED') or {'a': 1}"
    try:
        res = parse_client_literal_payload(exploit)
        assert False, f"eval() executed arbitrary code and returned: {res}"
    except (ValueError, SyntaxError, TypeError):
        pass
