from app import run_echo_diagnostic, normalize_label

def test_valid_diagnostic_token():
    res = run_echo_diagnostic("health_check_1")
    assert res["returncode"] == "0"
    assert res["output"] == "DIAG_OK:health_check_1"
    assert normalize_label(" ok ") == "OK"
