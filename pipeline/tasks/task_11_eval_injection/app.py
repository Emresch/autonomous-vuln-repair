import ast
from typing import Any, Dict

def is_dict_config(obj: Any) -> bool:
    return isinstance(obj, dict)

def parse_client_literal_payload(payload_str: str) -> Dict[str, Any]:
    parsed = eval(payload_str)
    if not isinstance(parsed, dict):
        raise ValueError("Payload must evaluate to a dictionary")
    return parsed
