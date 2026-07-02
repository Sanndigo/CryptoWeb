from pydantic import BaseModel, Field
from typing import Optional, Literal

VALID_CATEGORIES = Literal["all", "hashing", "encoding", "encryption", "formatting"]
VALID_METHODS = Literal[
    "all", "MD5", "SHA-256", "SHA-512", "bcrypt",
    "Base64", "URL", "Hex", "Binary", "Morse",
    "AES-256", "3DES", "ROT13", "XOR",
    "JSON", "JWT Decoder"
]

class AdvancedOptions(BaseModel):
    aes_key_bits: Literal[128, 192, 256] = 256
    aes_aad: Optional[str] = None            # Additional Authenticated Data for GCM
    aes_output_format: Literal["base64", "hex"] = "base64"
    des_output_format: Literal["base64", "hex"] = "base64"
    xor_output_format: Literal["base64", "hex"] = "base64"

class TextInput(BaseModel):
    text: str
    key: Optional[str] = None
    category: VALID_CATEGORIES = "all"
    method: VALID_METHODS = "all"
    advanced: Optional[AdvancedOptions] = None

class KeyGenRequest(BaseModel):
    algorithm: Literal["aes-128", "aes-192", "aes-256", "3des", "xor", "password"]
    format: Literal["base64", "hex"] = "base64"
    length: int = Field(default=32, ge=8, le=512)  # bytes for XOR, chars for password
    include_symbols: bool = False

class ShareCreate(BaseModel):
    secret: str = Field(..., max_length=5000)

class ShareResponse(BaseModel):
    uuid: str
    expires_at: str

class ShareGet(BaseModel):
    secret: str
