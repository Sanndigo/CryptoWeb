from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

# Relative imports since they are all in src/api
from .models import TextInput, CryptoResponse
from .services import hashing, encoding, encryption, formatting

app = FastAPI(title="CryptoWeb API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/process")
def process_all(payload: TextInput):
    text = payload.text
    key = payload.key or ""

    if len(text) > 1000:
        raise HTTPException(status_code=400, detail="Payload exceeds the maximum allowed length of 1000 characters.")
    
    if len(key) > 256:
        raise HTTPException(status_code=400, detail="Secret key exceeds the maximum allowed length of 256 characters.")

    if not text:
        return {}

    return {
        "hashing": {
            "MD5": hashing.hash_md5(text),
            "SHA-256": hashing.hash_sha256(text),
            "SHA-512": hashing.hash_sha512(text),
            "bcrypt": hashing.hash_bcrypt(text)
        },
        "encoding": {
            "Base64": {"Encode": encoding.encode_base64(text), "Decode": encoding.decode_base64(text)},
            "URL": {"Encode": encoding.encode_url(text), "Decode": encoding.decode_url(text)},
            "Hex": {"Encode": encoding.encode_hex(text), "Decode": encoding.decode_hex(text)},
            "Binary": {"Encode": encoding.encode_binary(text), "Decode": encoding.decode_binary(text)},
            "Morse": {"Encode": encoding.encode_morse(text), "Decode": encoding.decode_morse(text)}
        },
        "encryption": {
            "AES-256": {"Encrypt": encryption.encrypt_aes(text, key), "Decrypt": encryption.decrypt_aes(text, key)},
            "DES": {"Encrypt": encryption.encrypt_des(text, key), "Decrypt": encryption.decrypt_des(text, key)},
            "ROT13": encryption.rot13(text),
            "XOR": {"Encrypt": encryption.xor_cipher(text, key), "Decrypt": encryption.xor_decipher(text, key)}
        },
        "formatting": {
            "JSON": {"Beautify": formatting.format_json_beautify(text), "Minify": formatting.format_json_minify(text)},
            "JWT Decoder": formatting.decode_jwt(text)
        }
    }

# Mount Astro static files
# We ensure this is after API routes to prevent catching /api calls
DIST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "dist")

if os.path.isdir(DIST_DIR):
    # Mount everything else statically
    app.mount("/", StaticFiles(directory=DIST_DIR, html=True), name="static")
else:
    @app.get("/")
    def read_root():
        return {"status": "ok", "message": "API is running. Build Astro to see UI."}


