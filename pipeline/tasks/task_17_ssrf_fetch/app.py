import ipaddress
import urllib.parse
import urllib.request

def get_user_agent() -> str:
    return "AVR-Webhook-Validator/1.0"

def validate_and_open_webhook(url: str, opener=urllib.request.urlopen) -> str:
    with opener(url, timeout=3) as resp:
        return resp.read().decode("utf-8")
