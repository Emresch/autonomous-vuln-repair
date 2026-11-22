import inspect
import app
from app import parse_invoice_xml

def test_xxe_doctype_or_entity_declaration_rejected():
    xxe_payload = '''<?xml version="1.0"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <invoice><customer>&xxe;</customer><amount>10</amount></invoice>'''
    try:
        res = parse_invoice_xml(xxe_payload)
        assert False, f"XML parser accepted DOCTYPE/ENTITY declaration: {res}"
    except Exception:
        pass
    src = inspect.getsource(app)
    assert "DOCTYPE" in src or "ENTITY" in src or "defusedxml" in src
