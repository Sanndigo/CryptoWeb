import base64
import secrets
import string

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os

from .models import TextInput, AdvancedOptions, KeyGenRequest
from .services import hashing, encoding, encryption, formatting

# ── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="CryptoWeb API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Process endpoint ──────────────────────────────────────────────────────────

@app.post("/api/process")
@limiter.limit("30/minute")
def process_all(request: Request, payload: TextInput):
    text = payload.text
    key  = payload.key or ""
    adv  = payload.advanced or AdvancedOptions()

    if len(text) > 1000:
        raise HTTPException(status_code=400, detail="Payload exceeds the maximum allowed length of 1000 characters.")
    if len(key) > 256:
        raise HTTPException(status_code=400, detail="Secret key exceeds the maximum allowed length of 256 characters.")
    if adv.aes_aad and len(adv.aes_aad) > 256:
        raise HTTPException(status_code=400, detail="AAD exceeds the maximum allowed length of 256 characters.")
    if not text:
        return {}

    return {
        "hashing": {
            "MD5":     hashing.hash_md5(text),
            "SHA-256": hashing.hash_sha256(text),
            "SHA-512": hashing.hash_sha512(text),
            "bcrypt":  hashing.hash_bcrypt(text),
        },
        "encoding": {
            "Base64": {"Encode": encoding.encode_base64(text), "Decode": encoding.decode_base64(text)},
            "URL":    {"Encode": encoding.encode_url(text),    "Decode": encoding.decode_url(text)},
            "Hex":    {"Encode": encoding.encode_hex(text),    "Decode": encoding.decode_hex(text)},
            "Binary": {"Encode": encoding.encode_binary(text), "Decode": encoding.decode_binary(text)},
            "Morse":  {"Encode": encoding.encode_morse(text),  "Decode": encoding.decode_morse(text)},
        },
        "encryption": {
            "AES-256": {
                "Encrypt": encryption.encrypt_aes(text, key, adv.aes_key_bits, adv.aes_aad, adv.aes_output_format),
                "Decrypt": encryption.decrypt_aes(text, key, adv.aes_key_bits, adv.aes_aad, adv.aes_output_format),
            },
            "3DES": {
                "Encrypt": encryption.encrypt_3des(text, key, adv.des_output_format),
                "Decrypt": encryption.decrypt_3des(text, key, adv.des_output_format),
            },
            "ROT13": encryption.rot13(text),
            "XOR": {
                "Encrypt": encryption.xor_cipher(text, key, adv.xor_output_format),
                "Decrypt": encryption.xor_decipher(text, key, adv.xor_output_format),
            },
        },
        "formatting": {
            "JSON":        {"Beautify": formatting.format_json_beautify(text), "Minify": formatting.format_json_minify(text)},
            "JWT Decoder": formatting.decode_jwt(text),
        },
    }


# ── Key generation endpoint ───────────────────────────────────────────────────

@app.post("/api/generate-key")
@limiter.limit("60/minute")
def generate_key(request: Request, payload: KeyGenRequest):
    algo   = payload.algorithm
    fmt    = payload.format
    length = payload.length

    if algo == "password":
        charset = string.ascii_letters + string.digits
        if payload.include_symbols:
            charset += string.punctuation
        key = ''.join(secrets.choice(charset) for _ in range(length))
        return {"key": key, "bits": None, "bytes": length}

    key_bytes_count = {
        "aes-128": 16,
        "aes-192": 24,
        "aes-256": 32,
        "3des":    24,
        "xor":     length,
    }[algo]

    raw = secrets.token_bytes(key_bytes_count)

    if fmt == "hex":
        key = raw.hex()
    else:
        key = base64.b64encode(raw).decode('utf-8')

    return {"key": key, "bits": key_bytes_count * 8, "bytes": key_bytes_count}


# ── Static files (Astro build) ────────────────────────────────────────────────
DIST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "dist")

if os.path.isdir(DIST_DIR):
    app.mount("/", StaticFiles(directory=DIST_DIR, html=True), name="static")
else:
    @app.get("/")
    def read_root():
        return {"status": "ok", "message": "API is running. Build Astro to see UI."}
