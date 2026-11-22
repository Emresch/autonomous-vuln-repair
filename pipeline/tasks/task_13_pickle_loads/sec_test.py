import base64
import pickle
from app import decode_user_session_token

class EvilPayload:
    def __reduce__(self):
        return (eval, ("{'pwned': True}",))

def test_pickle_rce_fallback_rejected():
    evil_token = base64.b64encode(pickle.dumps(EvilPayload())).decode("ascii")
    try:
        res = decode_user_session_token(evil_token)
    except (ValueError, UnicodeDecodeError, Exception):
        return
    assert res != {"pwned": True}, "Insecure pickle.loads executed EvilPayload!"
