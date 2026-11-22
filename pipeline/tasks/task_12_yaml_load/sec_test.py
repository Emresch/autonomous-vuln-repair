import yaml
from app import load_service_yaml_config

def test_yaml_arbitrary_object_deserialization_blocked():
    exploit_yaml = "!!python/object/apply:builtins.dict [[['pwned', 1]]]"
    try:
        res = load_service_yaml_config(exploit_yaml)
        assert False, f"Unsafe yaml.load executed python object tag: {res}"
    except (yaml.YAMLError, ValueError):
        pass
