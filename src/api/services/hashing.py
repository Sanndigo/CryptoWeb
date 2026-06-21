import hashlib
import bcrypt
import base64

def hash_md5(text: str) -> str:
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def hash_sha256(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def hash_sha512(text: str) -> str:
    return hashlib.sha512(text.encode('utf-8')).hexdigest()

def hash_bcrypt(text: str) -> str:
    try:
        # Pre-hash with SHA-256 to bypass bcrypt's 72-byte limit
        sha256_hash = hashlib.sha256(text.encode('utf-8')).digest()
        b64_hash = base64.b64encode(sha256_hash)
        
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(b64_hash, salt)
        return hashed.decode('utf-8')
    except Exception:
        return "bcrypt error"
