"""
Key generation service — isolated so main.py stays clean of stdlib imports.
Uses `secrets` module (CSPRNG) for all randomness.
"""
import base64
import secrets
import string


def generate(algorithm: str, fmt: str, length: int, include_symbols: bool) -> dict:
    """
    Generate a cryptographically secure key or password.

    Returns a dict with:
        key   – the generated key string
        bits  – key size in bits (None for passwords)
        bytes – key size in bytes
    """
    if algorithm == "password":
        charset = string.ascii_letters + string.digits
        if include_symbols:
            # Exclude chars that break shell quoting in copy-paste scenarios
            charset += r'!@#$%^&*()-_=+[]{}|;:,.<>?'
        key = ''.join(secrets.choice(charset) for _ in range(length))
        return {"key": key, "bits": None, "bytes": length}

    key_byte_sizes: dict[str, int] = {
        "aes-128": 16,
        "aes-192": 24,
        "aes-256": 32,
        "3des":    24,
        "xor":     length,
    }
    n = key_byte_sizes[algorithm]
    raw = secrets.token_bytes(n)
    key = raw.hex() if fmt == "hex" else base64.b64encode(raw).decode('utf-8')
    return {"key": key, "bits": n * 8, "bytes": n}
