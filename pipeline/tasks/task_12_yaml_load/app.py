import yaml
from typing import Any, Dict

def get_config_version() -> str:
    return "v1.0"

def load_service_yaml_config(yaml_text: str) -> Dict[str, Any]:
    data = yaml.load(yaml_text, Loader=yaml.Loader)
    if not isinstance(data, dict):
        raise ValueError("Configuration root must be a mapping")
    return data
