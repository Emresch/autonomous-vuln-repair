from app import load_service_yaml_config, get_config_version

def test_valid_yaml_config():
    cfg = load_service_yaml_config("service: auth\nport: 9000\ndebug: false\n")
    assert cfg["service"] == "auth"
    assert cfg["port"] == 9000
    assert get_config_version() == "v1.0"
