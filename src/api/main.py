import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .models import TextInput, AdvancedOptions, KeyGenRequest
from .services import hashing, encoding, encryption, formatting, keygen


# ── Rate limiter ──────────────────────────────────────────────────────────────
# When running behind a reverse proxy (nginx), set TRUST_PROXY=1 so that
# X-Forwarded-For is used instead of the always-localhost request.client.host.
# WARNING: Only enable TRUST_PROXY when the proxy is properly configured to
#          strip/replace X-Forwarded-For, otherwise clients can spoof IPs.

def _get_client_ip(request: Request) -> str:
    if os.getenv("TRUST_PROXY", "0") == "1":
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            # Leftmost IP is the original client; rightmost is the last proxy
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


limiter = Limiter(key_func=_get_client_ip)

app = FastAPI(title="CryptoWeb API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── CORS ──────────────────────────────────────────────────────────────────────
# Override via CORS_ORIGINS env var for production, e.g.:
#   CORS_ORIGINS=https://example.com,https://www.example.com
# Defaults to "*" for local development convenience only.

_cors_env = os.getenv("CORS_ORIGINS", "")
_cors_origins = [o.strip() for o in _cors_env.split(",") if o.strip()] or ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ── Process endpoint ──────────────────────────────────────────────────────────

@app.post("/api/process")
@limiter.limit("30/minute")
def process_all(request: Request, payload: TextInput):
    text = payload.text
    key  = payload.key or ""

    # Early return for empty input — no error, just no results
    if not text:
        return {}

    # Validate sizes before any processing
    if len(text) > 1000:
        raise HTTPException(status_code=400, detail="Payload exceeds the maximum allowed length of 1000 characters.")
    if len(key) > 256:
        raise HTTPException(status_code=400, detail="Secret key exceeds the maximum allowed length of 256 characters.")

    adv = payload.advanced or AdvancedOptions()

    if adv.aes_aad and len(adv.aes_aad) > 256:
        raise HTTPException(status_code=400, detail="AAD exceeds the maximum allowed length of 256 characters.")

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
    return keygen.generate(
        algorithm=payload.algorithm,
        fmt=payload.format,
        length=payload.length,
        include_symbols=payload.include_symbols,
    )


# ── Static files (Astro build) ────────────────────────────────────────────────
# Mounted AFTER API routes so /api/* is never intercepted by the static handler.

DIST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "dist")

if os.path.isdir(DIST_DIR):
    app.mount("/", StaticFiles(directory=DIST_DIR, html=True), name="static")
else:
    @app.get("/")
    def read_root():
        return {"status": "ok", "message": "API is running. Build Astro to see UI."}
