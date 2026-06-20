from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import hashlib

def _get_aes_key(key: str) -> bytes:
    # Ensure key is 32 bytes for AES-256
    return hashlib.sha256(key.encode('utf-8')).digest()

def _get_des_key(key: str) -> bytes:
    # Ensure key is 8 bytes for DES
    return hashlib.md5(key.encode('utf-8')).digest()[:8]

def encrypt_aes(text: str, key: str) -> str:
    if not key:
        return "Key is required for AES"
    try:
        key_bytes = _get_aes_key(key)
        # Using ECB for simplicity in this tool, though CBC is more secure (requires IV).
        # We will use ECB since it's easier for stateless one-off text encryption without passing IV around,
        # but in real life CBC/GCM should be used.
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(text.encode('utf-8')) + padder.finalize()
        
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(ct).decode('utf-8')
    except Exception as e:
        return f"Encryption error: {str(e)}"

def decrypt_aes(text: str, key: str) -> str:
    if not key:
        return "Key is required for AES"
    try:
        key_bytes = _get_aes_key(key)
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        
        ct = base64.b64decode(text.encode('utf-8'))
        padded_data = decryptor.update(ct) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode('utf-8')
    except Exception as e:
        return "Decryption error or invalid key"

def encrypt_des(text: str, key: str) -> str:
    if not key:
        return "Key is required for DES"
    try:
        key_bytes = _get_des_key(key)
        cipher = Cipher(algorithms.TripleDES(key_bytes), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(text.encode('utf-8')) + padder.finalize()
        
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(ct).decode('utf-8')
    except Exception as e:
        return f"Encryption error: {str(e)}"

def decrypt_des(text: str, key: str) -> str:
    if not key:
        return "Key is required for DES"
    try:
        key_bytes = _get_des_key(key)
        cipher = Cipher(algorithms.TripleDES(key_bytes), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        
        ct = base64.b64decode(text.encode('utf-8'))
        padded_data = decryptor.update(ct) + decryptor.finalize()
        
        unpadder = padding.PKCS7(64).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode('utf-8')
    except Exception as e:
        return "Decryption error or invalid key"

def rot13(text: str) -> str:
    import codecs
    return codecs.encode(text, 'rot_13')

def xor_cipher(text: str, key: str) -> str:
    if not key:
        return "Key is required for XOR"
    # Simple repeating-key XOR
    res = []
    for i in range(len(text)):
        res.append(chr(ord(text[i]) ^ ord(key[i % len(key)])))
    return base64.b64encode(''.join(res).encode('utf-8')).decode('utf-8')

def xor_decipher(text: str, key: str) -> str:
    if not key:
        return "Key is required for XOR"
    try:
        raw_text = base64.b64decode(text.encode('utf-8')).decode('utf-8')
        res = []
        for i in range(len(raw_text)):
            res.append(chr(ord(raw_text[i]) ^ ord(key[i % len(key)])))
        return ''.join(res)
    except Exception:
        return "Error deciphering XOR"
