from pydantic import BaseModel
from typing import Optional

class TextInput(BaseModel):
    text: str
    key: Optional[str] = None # For encryption/decryption where a key/password is needed

class CryptoResponse(BaseModel):
    result: str
    error: Optional[str] = None
