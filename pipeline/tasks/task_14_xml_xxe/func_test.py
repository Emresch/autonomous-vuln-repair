from app import parse_invoice_xml, get_supported_invoice_currency

def test_normal_invoice_xml():
    xml_data = "<invoice><customer>Acme Corp</customer><amount>250.00</amount></invoice>"
    res = parse_invoice_xml(xml_data)
    assert res == {"customer": "Acme Corp", "amount": "250.00"}
    assert get_supported_invoice_currency() == "USD"
