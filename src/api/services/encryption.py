import codecs
import base64
import hashlib
import os

# AES-256-GCM (authenticated encryption)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# TripleDES moved to decrepit in cryptography ≥42; fallback for older versions
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES  # type: ignore

from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


# ── Key derivation ────────────────────────────────────────────────────────────

def _get_aes_key(key: str, key_bits: int = 256) -> bytes:
    """
    Derive an AES key from a passphrase using SHA-512.
    SHA-512 produces 64 bytes; we truncate to the requested size.
    Supports 128-bit (16B), 192-bit (24B), 256-bit (32B).
    """
    return hashlib.sha512(key.encode('utf-8')).digest()[:key_bits // 8]


def _get_3des_key(key: str) -> bytes:
    """Derive a 24-byte TripleDES key from a passphrase using SHA-256."""
    return hashlib.sha256(key.encode('utf-8')).digest()[:24]


def _encode_output(raw: bytes, fmt: str) -> str:
    """Encode raw bytes to Base64 or Hex string."""
    if fmt == "hex":
        return raw.hex()
    return base64.b64encode(raw).decode('utf-8')


def _decode_input(text: str, fmt: str) -> bytes:
    """Decode a Base64 or Hex string back to bytes."""
    if fmt == "hex":
        return bytes.fromhex(text.strip())
    return base64.b64decode(text.encode('utf-8'))


# ── AES-256-GCM ───────────────────────────────────────────────────────────────

def encrypt_aes(
    text: str,
    key: str,
    key_bits: int = 256,
    aad: str | None = None,
    output_format: str = "base64",
) -> str:
    if not key:
        return "Key is required for AES"
    try:
        key_bytes = _get_aes_key(key, key_bits)
        nonce = os.urandom(12)                          # 96-bit nonce for GCM
        aesgcm = AESGCM(key_bytes)
        aad_bytes = aad.encode('utf-8') if aad else None
        ct = aesgcm.encrypt(nonce, text.encode('utf-8'), aad_bytes)
        return _encode_output(nonce + ct, output_format)
    except Exception:
        return "Encryption error"


def decrypt_aes(
    text: str,
    key: str,
    key_bits: int = 256,
    aad: str | None = None,
    output_format: str = "base64",
) -> str:
    if not key:
        return "Key is required for AES"
    try:
        key_bytes = _get_aes_key(key, key_bits)
        raw_data = _decode_input(text, output_format)
        if len(raw_data) < 28:                          # 12 nonce + 16 tag minimum
            return "Decryption error: Invalid ciphertext"
        nonce = raw_data[:12]
        ct    = raw_data[12:]
        aesgcm = AESGCM(key_bytes)
        aad_bytes = aad.encode('utf-8') if aad else None
        plaintext = aesgcm.decrypt(nonce, ct, aad_bytes)
        return plaintext.decode('utf-8')
    except Exception:
        return "Decryption error or invalid key / AAD"


# ── 3DES-CBC ──────────────────────────────────────────────────────────────────

def encrypt_3des(text: str, key: str, output_format: str = "base64") -> str:
    if not key:
        return "Key is required for 3DES"
    try:
        key_bytes = _get_3des_key(key)
        iv = os.urandom(8)
        cipher = Cipher(TripleDES(key_bytes), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(64).padder()
        padded = padder.update(text.encode('utf-8')) + padder.finalize()
        ct = encryptor.update(padded) + encryptor.finalize()
        return _encode_output(iv + ct, output_format)
    except Exception:
        return "Encryption error"


def decrypt_3des(text: str, key: str, output_format: str = "base64") -> str:
    if not key:
        return "Key is required for 3DES"
    try:
        key_bytes = _get_3des_key(key)
        raw_data = _decode_input(text, output_format)
        if len(raw_data) < 8:
            return "Decryption error: Invalid ciphertext"
        iv = raw_data[:8]
        ct = raw_data[8:]
        cipher = Cipher(TripleDES(key_bytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(64).unpadder()
        data = unpadder.update(padded) + unpadder.finalize()
        return data.decode('utf-8')
    except Exception:
        return "Decryption error or invalid key"


# ── ROT-13 ────────────────────────────────────────────────────────────────────

def rot13(text: str) -> str:
    return codecs.encode(text, 'rot_13')


# ── XOR ───────────────────────────────────────────────────────────────────────

def xor_cipher(text: str, key: str, output_format: str = "base64") -> str:
    if not key:
        return "Key is required for XOR"
    try:
        text_bytes = text.encode('utf-8')
        key_bytes  = key.encode('utf-8')
        res = bytearray(text_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(text_bytes)))
        return _encode_output(bytes(res), output_format)
    except Exception:
        return "Encryption error"


def xor_decipher(text: str, key: str, output_format: str = "base64") -> str:
    if not key:
        return "Key is required for XOR"
    try:
        raw_bytes = _decode_input(text, output_format)
        key_bytes  = key.encode('utf-8')
        res = bytearray(raw_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(raw_bytes)))
        return res.decode('utf-8')
    except Exception:
        return "Error deciphering XOR"
