import base64
import json
import pickle
from typing import Any, Dict

def encode_json_session(session_data: Dict[str, Any]) -> str:
    raw = json.dumps(session_data).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")

def decode_user_session_token(token_b64: str) -> Dict[str, Any]:
    raw_bytes = base64.b64decode(token_b64.encode("ascii"))
    try:
        return json.loads(raw_bytes.decode("utf-8"))
    except Exception:
        return pickle.loads(raw_bytes)
