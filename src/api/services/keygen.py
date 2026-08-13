"""
Key generation service — supports symmetric keys, secure passwords, and RSA/ECC keypairs.
"""
import base64
import secrets
import string
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization


def generate(algorithm: str, fmt: str = "base64", length: int = 32, include_symbols: bool = False) -> dict:
    alg_lower = algorithm.lower()
    
    # Asymmetric Key Pairs
    if alg_lower in ("rsa-2048", "rsa-4096", "ed25519"):
        if alg_lower == "rsa-2048":
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif alg_lower == "rsa-4096":
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        else:
            private_key = ed25519.Ed25519PrivateKey.generate()
            
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_key = private_key.public_key()
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return {
            "is_pair": True,
            "public_key": pem_public,
            "private_key": pem_private,
            "key": pem_private
        }

    if alg_lower == "password":
        charset = string.ascii_letters + string.digits
        if include_symbols:
            charset += r'!@#$%^&*()-_=+[]{}|;:,.<>?'
        key = ''.join(secrets.choice(charset) for _ in range(length))
        return {"is_pair": False, "key": key, "bits": None, "bytes": length}

    key_byte_sizes: dict[str, int] = {
        "aes-128": 16,
        "aes-192": 24,
        "aes-256": 32,
        "3des":    24,
        "xor":     length if length else 32,
        "randomhex": 32
    }
    n = key_byte_sizes.get(alg_lower, 32)
    raw = secrets.token_bytes(n)
    key = raw.hex() if fmt == "hex" or alg_lower == "randomhex" else base64.b64encode(raw).decode('utf-8')
    return {"is_pair": False, "key": key, "bits": n * 8, "bytes": n}
