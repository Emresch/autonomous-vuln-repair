import pytest
from hive_hook import HiveCliHook

def test_run_cli_with_valid_schema():
    """Geçerli bir şema adı ile sorgunun sorunsuz çalıştığını doğrular."""
    hook = HiveCliHook()
    result = hook.run_cli("SELECT count(*) FROM users;", schema="analytics_prod")
    
    assert result["status"] == "SUCCESS"
    assert result["schema_used"] == "analytics_prod"
    assert "USE analytics_prod;\nSELECT count(*) FROM users;" in result["generated_script"]

def test_run_cli_with_default_schema():
    """Varsayılan şema ile sorgunun çalıştığını doğrular."""
    hook = HiveCliHook(default_schema="default")
    result = hook.run_cli("SHOW TABLES;")
    
    assert result["status"] == "SUCCESS"
    assert "USE default;\nSHOW TABLES;" in result["generated_script"]
