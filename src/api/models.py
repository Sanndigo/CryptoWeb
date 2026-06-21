from pydantic import BaseModel
from typing import Optional, Literal

VALID_CATEGORIES = Literal["all", "hashing", "encoding", "encryption", "formatting"]
VALID_METHODS = Literal[
    "all", "MD5", "SHA-256", "SHA-512", "bcrypt",
    "Base64", "URL", "Hex", "Binary", "Morse",
    "AES-256", "3DES", "ROT13", "XOR",
    "JSON", "JWT Decoder"
]

class TextInput(BaseModel):
    text: str
    key: Optional[str] = None
    category: VALID_CATEGORIES = "all"
    method: VALID_METHODS = "all"
