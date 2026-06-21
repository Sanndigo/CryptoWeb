import json
import jwt

def format_json_beautify(text: str) -> str:
    try:
        parsed = json.loads(text)
        return json.dumps(parsed, indent=4, ensure_ascii=False)
    except Exception:
        return "Invalid JSON"

def format_json_minify(text: str) -> str:
    try:
        parsed = json.loads(text)
        return json.dumps(parsed, separators=(',', ':'), ensure_ascii=False)
    except Exception:
        return "Invalid JSON"

def decode_jwt(text: str) -> str:
    try:
        # Decode only the payload, without verifying signature
        header = jwt.get_unverified_header(text)
        payload = jwt.decode(text, options={"verify_signature": False})
        return json.dumps({"header": header, "payload": payload}, indent=4)
    except Exception:
        return "Invalid JWT"
