import xml.etree.ElementTree as ET
from typing import Dict

def get_supported_invoice_currency() -> str:
    return "USD"

def parse_invoice_xml(xml_string: str) -> Dict[str, str]:
    root = ET.fromstring(xml_string)
    customer = root.findtext("customer", default="")
    amount = root.findtext("amount", default="0")
    return {"customer": customer, "amount": amount}
