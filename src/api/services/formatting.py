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
        header = jwt.get_unverified_header(text)
        # Explicitly whitelist known algorithms; rejects alg:none and unknown algos
        _ALLOWED_ALGS = [
            "HS256", "HS384", "HS512",
            "RS256", "RS384", "RS512",
            "ES256", "ES384", "ES512",
            "PS256", "PS384", "PS512",
        ]
        payload = jwt.decode(
            text,
            options={"verify_signature": False},
            algorithms=_ALLOWED_ALGS,
        )
        return json.dumps({"header": header, "payload": payload}, indent=4)
    except Exception:
        return "Invalid JWT"
