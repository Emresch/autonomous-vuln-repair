from app import parse_client_literal_payload, is_dict_config

def test_valid_literal_dict_parsing():
    res = parse_client_literal_payload("{'host': 'localhost', 'port': 8080, 'tags': ['a', 'b']}")
    assert res["host"] == "localhost"
    assert res["port"] == 8080
    assert is_dict_config(res) is True
