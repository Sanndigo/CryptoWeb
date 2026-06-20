from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from models import TextInput, CryptoResponse
from services import hashing, encoding, encryption, formatting

app = FastAPI(title="CryptoWeb API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/process")
def process_all(payload: TextInput):
    text = payload.text
    key = payload.key or ""

    if not text:
        return {}

    # Gather all results in one massive dictionary (like dencode)
    return {
        "hashing": {
            "MD5": hashing.hash_md5(text),
            "SHA-256": hashing.hash_sha256(text),
            "SHA-512": hashing.hash_sha512(text),
            "bcrypt": hashing.hash_bcrypt(text)
        },
        "encoding": {
            "Base64": encoding.encode_base64(text),
            "Base64 Decode": encoding.decode_base64(text),
            "URL Encode": encoding.encode_url(text),
            "URL Decode": encoding.decode_url(text),
            "Hex": encoding.encode_hex(text),
            "Hex Decode": encoding.decode_hex(text),
            "Binary": encoding.encode_binary(text),
            "Binary Decode": encoding.decode_binary(text),
            "Morse": encoding.encode_morse(text),
            "Morse Decode": encoding.decode_morse(text)
        },
        "encryption": {
            "AES-256 Encrypt": encryption.encrypt_aes(text, key),
            "AES-256 Decrypt": encryption.decrypt_aes(text, key),
            "DES Encrypt": encryption.encrypt_des(text, key),
            "DES Decrypt": encryption.decrypt_des(text, key),
            "ROT13": encryption.rot13(text),
            "XOR Encrypt": encryption.xor_cipher(text, key),
            "XOR Decrypt": encryption.xor_decipher(text, key)
        },
        "formatting": {
            "JSON Beautifier": formatting.format_json_beautify(text),
            "JSON Minifier": formatting.format_json_minify(text),
            "JWT Decoder": formatting.decode_jwt(text)
        }
    }

