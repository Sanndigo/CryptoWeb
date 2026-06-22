import codecs
import base64
import hashlib
import os
import functools

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


# ── PBKDF2 key derivation ─────────────────────────────────────────────────────
# Raw SHA hashes are cryptographically fast — bad for password-based keys.
# PBKDF2-HMAC-SHA256 with 100 000 iterations slows brute-force by ×100 000.
# A fixed application-specific salt prevents cross-application rainbow tables.
# For full production use, store a random per-ciphertext salt alongside the data.

_PBKDF2_ITERATIONS = 100_000
_AES_SALT  = b'cryptoweb-aes-kdf-v1'
_3DES_SALT = b'cryptoweb-3des-kdf-v1'


@functools.lru_cache(maxsize=64)
def _derive_key(passphrase: str, salt: bytes, key_bits: int) -> bytes:
    """
    Derive a key via PBKDF2-HMAC-SHA256.
    
    LRU-cached: repeated calls with the same (passphrase, salt, bits) are instant,
    so interactive use (live preview) stays responsive after the first derivation.
    
    SECURITY NOTE ON LRU CACHE:
    Caching keys in memory exposes them to memory leaks/dumps/side-channels.
    In a shared multi-tenant backend server, this cache retains the last 64
    cleartext keys/passphrases and their derived keys. For maximum security,
    especially in a production environment where you cannot guarantee memory
    isolation, remove the `@functools.lru_cache` decorator so keys are garbage-collected
    immediately after the request cycle completes.
    """
    return hashlib.pbkdf2_hmac(
        'sha256',
        passphrase.encode('utf-8'),
        salt,
        _PBKDF2_ITERATIONS,
        dklen=key_bits // 8,
    )


def _get_aes_key(key: str, key_bits: int = 256) -> bytes:
    """Derive an AES key (128 / 192 / 256-bit) from a passphrase."""
    return _derive_key(key, _AES_SALT, key_bits)


def _get_3des_key(key: str) -> bytes:
    """Derive a 24-byte (192-bit) TripleDES key from a passphrase."""
    return _derive_key(key, _3DES_SALT, 192)


# ── I/O encoding helpers ──────────────────────────────────────────────────────

def _encode_output(raw: bytes, fmt: str) -> str:
    if fmt == "hex":
        return raw.hex()
    return base64.b64encode(raw).decode('utf-8')


def _decode_input(text: str, fmt: str) -> bytes:
    if fmt == "hex":
        cleaned = text.strip().replace(' ', '')
        if len(cleaned) % 2 != 0:
            raise ValueError("Hex string must contain an even number of hex digits")
        if not all(c in '0123456789abcdefABCDEF' for c in cleaned):
            raise ValueError("Invalid hex characters in input")
        return bytes.fromhex(cleaned)
    return base64.b64decode(text.encode('utf-8'))


# ── Version Markers for Dynamic Salts ──────────────────────────────────────────
# Prepend unique prefixes to dynamic-salt ciphertexts to prevent false-positives
# and allow seamless fallback decryption for legacy static-salt ciphertexts.
_MAGIC_PREFIX_AES  = b'CWA1'  # CryptoWeb AES Version 1
_MAGIC_PREFIX_3DES = b'CWD1'  # CryptoWeb 3DES Version 1


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
        # Generate a unique 16-byte salt for this ciphertext
        salt = os.urandom(16)
        key_bytes = _derive_key(key, salt, key_bits)
        nonce = os.urandom(12)                          # 96-bit nonce for GCM
        aesgcm = AESGCM(key_bytes)
        aad_bytes = aad.encode('utf-8') if aad else None
        ct = aesgcm.encrypt(nonce, text.encode('utf-8'), aad_bytes)
        # Prepend magic prefix and salt to ciphertext
        payload = _MAGIC_PREFIX_AES + salt + nonce + ct
        return _encode_output(payload, output_format)
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
        raw_data = _decode_input(text, output_format)
        
        # Determine format: new dynamic salt vs legacy static salt
        # New format size: 4 (magic) + 16 (salt) + 12 (nonce) + tag (16) = min 48 bytes
        if len(raw_data) >= 48 and raw_data.startswith(_MAGIC_PREFIX_AES):
            salt      = raw_data[4:20]
            nonce     = raw_data[20:32]
            ct        = raw_data[32:]
            key_bytes = _derive_key(key, salt, key_bits)
        else:
            # Fallback to legacy static salt format
            if len(raw_data) < 28:                          # 12 nonce + 16 tag minimum
                return "Decryption error: Invalid ciphertext"
            nonce     = raw_data[:12]
            ct        = raw_data[12:]
            key_bytes = _derive_key(key, _AES_SALT, key_bits)

        aesgcm    = AESGCM(key_bytes)
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
        # Generate a unique 16-byte salt for this ciphertext
        salt = os.urandom(16)
        key_bytes = _derive_key(key, salt, 192)
        iv = os.urandom(8)
        cipher = Cipher(TripleDES(key_bytes), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(64).padder()
        padded = padder.update(text.encode('utf-8')) + padder.finalize()
        ct = encryptor.update(padded) + encryptor.finalize()
        # Prepend magic prefix and salt to ciphertext
        payload = _MAGIC_PREFIX_3DES + salt + iv + ct
        return _encode_output(payload, output_format)
    except Exception:
        return "Encryption error"


def decrypt_3des(text: str, key: str, output_format: str = "base64") -> str:
    if not key:
        return "Key is required for 3DES"
    try:
        raw_data = _decode_input(text, output_format)
        
        # Determine format: new dynamic salt vs legacy static salt
        # New format size: 4 (magic) + 16 (salt) + 8 (iv) + min 1 block ct (8) = min 36 bytes
        if len(raw_data) >= 36 and raw_data.startswith(_MAGIC_PREFIX_3DES):
            salt      = raw_data[4:20]
            iv        = raw_data[20:28]
            ct        = raw_data[28:]
            key_bytes = _derive_key(key, salt, 192)
        else:
            # Fallback to legacy static salt format
            if len(raw_data) < 8:
                return "Decryption error: Invalid ciphertext"
            iv        = raw_data[:8]
            ct        = raw_data[8:]
            key_bytes = _derive_key(key, _3DES_SALT, 192)

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

_XOR_MIN_KEY_BYTES = 8


def xor_cipher(text: str, key: str, output_format: str = "base64") -> str:
    if not key:
        return "Key is required for XOR"
    if len(key.encode('utf-8')) < _XOR_MIN_KEY_BYTES:
        return f"XOR key must be at least {_XOR_MIN_KEY_BYTES} characters"
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
    if len(key.encode('utf-8')) < _XOR_MIN_KEY_BYTES:
        return f"XOR key must be at least {_XOR_MIN_KEY_BYTES} characters"
    try:
        raw_bytes = _decode_input(text, output_format)
        key_bytes = key.encode('utf-8')
        res = bytearray(raw_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(raw_bytes)))
        return res.decode('utf-8')
    except Exception:
        return "Error deciphering XOR"
