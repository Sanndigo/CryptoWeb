import hashlib
import bcrypt

def hash_md5(text: str) -> str:
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def hash_sha256(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def hash_sha512(text: str) -> str:
    return hashlib.sha512(text.encode('utf-8')).hexdigest()

def hash_bcrypt(text: str) -> str:
    try:
        # bcrypt requires bytes, returns bytes. Max 72 bytes allowed.
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(text.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    except Exception as e:
        return f"bcrypt error: {str(e)}"
