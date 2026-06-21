import codecs
import base64
import hashlib
import os

# AES-GCM (authenticated encryption) — replaces AES-CBC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# TripleDES moved to decrepit in cryptography ≥42; fall back for older versions
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES  # type: ignore

from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def _get_aes_key(key: str) -> bytes:
    """Derive a 32-byte AES-256 key via SHA-256."""
    return hashlib.sha256(key.encode('utf-8')).digest()


def _get_3des_key(key: str) -> bytes:
    """Derive a 24-byte 3DES key via SHA-256 (first 24 bytes)."""
    return hashlib.sha256(key.encode('utf-8')).digest()[:24]


# ── AES-256-GCM ──────────────────────────────────────────────────────────────

def encrypt_aes(text: str, key: str) -> str:
    if not key:
        return "Key is required for AES"
    try:
        key_bytes = _get_aes_key(key)
        nonce = os.urandom(12)           # 96-bit nonce recommended for GCM
        aesgcm = AESGCM(key_bytes)
        # encrypt() appends the 16-byte authentication tag to the ciphertext
        ct = aesgcm.encrypt(nonce, text.encode('utf-8'), None)
        return base64.b64encode(nonce + ct).decode('utf-8')
    except Exception:
        return "Encryption error"


def decrypt_aes(text: str, key: str) -> str:
    if not key:
        return "Key is required for AES"
    try:
        key_bytes = _get_aes_key(key)
        raw_data = base64.b64decode(text.encode('utf-8'))
        if len(raw_data) < 28:          # 12 nonce + 16 tag minimum
            return "Decryption error: Invalid ciphertext"
        nonce = raw_data[:12]
        ct = raw_data[12:]
        aesgcm = AESGCM(key_bytes)
        plaintext = aesgcm.decrypt(nonce, ct, None)
        return plaintext.decode('utf-8')
    except Exception:
        return "Decryption error or invalid key"


# ── 3DES-CBC ─────────────────────────────────────────────────────────────────

def encrypt_3des(text: str, key: str) -> str:
    if not key:
        return "Key is required for 3DES"
    try:
        key_bytes = _get_3des_key(key)
        iv = os.urandom(8)
        cipher = Cipher(TripleDES(key_bytes), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(text.encode('utf-8')) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ct).decode('utf-8')
    except Exception:
        return "Encryption error"


def decrypt_3des(text: str, key: str) -> str:
    if not key:
        return "Key is required for 3DES"
    try:
        key_bytes = _get_3des_key(key)
        raw_data = base64.b64decode(text.encode('utf-8'))
        if len(raw_data) < 8:
            return "Decryption error: Invalid ciphertext"
        iv = raw_data[:8]
        ct = raw_data[8:]
        cipher = Cipher(TripleDES(key_bytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(64).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode('utf-8')
    except Exception:
        return "Decryption error or invalid key"


# ── ROT-13 ───────────────────────────────────────────────────────────────────

def rot13(text: str) -> str:
    return codecs.encode(text, 'rot_13')


# ── XOR ──────────────────────────────────────────────────────────────────────

def xor_cipher(text: str, key: str) -> str:
    if not key:
        return "Key is required for XOR"
    try:
        text_bytes = text.encode('utf-8')
        key_bytes  = key.encode('utf-8')
        res = bytearray(text_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(text_bytes)))
        return base64.b64encode(res).decode('utf-8')
    except Exception:
        return "Encryption error"


def xor_decipher(text: str, key: str) -> str:
    if not key:
        return "Key is required for XOR"
    try:
        raw_bytes = base64.b64decode(text.encode('utf-8'))
        key_bytes  = key.encode('utf-8')
        res = bytearray(raw_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(raw_bytes)))
        return res.decode('utf-8')
    except Exception:
        return "Error deciphering XOR"
