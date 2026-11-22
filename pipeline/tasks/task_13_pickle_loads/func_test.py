from app import encode_json_session, decode_user_session_token

def test_valid_json_session_roundtrip():
    tok = encode_json_session({"user": "alice", "admin": False})
    decoded = decode_user_session_token(tok)
    assert decoded == {"user": "alice", "admin": False}
