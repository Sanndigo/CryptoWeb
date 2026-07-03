import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi import Depends
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .models import TextInput, AdvancedOptions, KeyGenRequest, ShareCreate, ShareResponse, ShareGet
from .services import hashing, encoding, encryption, formatting, keygen
from .services.db import init_db, get_db, redis_client, ShareAuditLog
from sqlalchemy.ext.asyncio import AsyncSession
from contextlib import asynccontextmanager
import uuid
import datetime
import traceback
import sys
import re
from uuid import UUID

from dotenv import load_dotenv
load_dotenv()

from .logger import logger

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_USERNAME or not ADMIN_PASSWORD:
    print("FATAL ERROR: ADMIN_USERNAME and ADMIN_PASSWORD must be set in the environment.", file=sys.stderr)
    sys.exit(1)

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

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up: initializing DB and caching layers.")
    await init_db()
    yield
    logger.info("Shutting down: closing Redis connection.")
    await redis_client.aclose()

app = FastAPI(title="CryptoWeb API", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled server error: {exc}\n{traceback.format_exc()}")
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})


# ── CORS ──────────────────────────────────────────────────────────────────────
ENV = os.getenv("ENV", "development")
_cors_env = os.getenv("CORS_ORIGINS", "")

if ENV == "production":
    if not _cors_env:
        print("FATAL ERROR: CORS_ORIGINS must be set in production environment.", file=sys.stderr)
        sys.exit(1)
    _cors_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
else:
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
    client_ip = _get_client_ip(request)
    logger.info(f"Process request from {client_ip} | Category: {payload.category} | Method: {payload.method}")
    
    text = payload.text
    key  = payload.key or ""

    # Validate sizes before any processing
    if len(text) > 1000:
        raise HTTPException(status_code=400, detail="Payload exceeds the maximum allowed length of 1000 characters.")
    if len(key) > 256:
        raise HTTPException(status_code=400, detail="Secret key exceeds the maximum allowed length of 256 characters.")

    adv = payload.advanced or AdvancedOptions()

    if adv.aes_aad and len(adv.aes_aad) > 256:
        raise HTTPException(status_code=400, detail="AAD exceeds the maximum allowed length of 256 characters.")

    cat = payload.category
    meth = payload.method
    
    res = {}

    # Hashing
    if cat in ("all", "hashing") or meth in ("MD5", "SHA-256", "SHA-512", "bcrypt"):
        h_res = {}
        if meth in ("all", "MD5"): h_res["MD5"] = hashing.hash_md5(text)
        if meth in ("all", "SHA-256"): h_res["SHA-256"] = hashing.hash_sha256(text)
        if meth in ("all", "SHA-512"): h_res["SHA-512"] = hashing.hash_sha512(text)
        if meth in ("all", "bcrypt"): h_res["bcrypt"] = hashing.hash_bcrypt(text) if text else "Awaiting input..."
        if h_res: res["hashing"] = h_res

    # Encoding
    if cat in ("all", "encoding") or meth in ("Base64", "URL", "Hex", "Binary", "Morse"):
        e_res = {}
        if meth in ("all", "Base64"): e_res["Base64"] = {"Encode": encoding.encode_base64(text), "Decode": encoding.decode_base64(text)}
        if meth in ("all", "URL"): e_res["URL"] = {"Encode": encoding.encode_url(text), "Decode": encoding.decode_url(text)}
        if meth in ("all", "Hex"): e_res["Hex"] = {"Encode": encoding.encode_hex(text), "Decode": encoding.decode_hex(text)}
        if meth in ("all", "Binary"): e_res["Binary"] = {"Encode": encoding.encode_binary(text), "Decode": encoding.decode_binary(text)}
        if meth in ("all", "Morse"): e_res["Morse"] = {"Encode": encoding.encode_morse(text), "Decode": encoding.decode_morse(text)}
        if e_res: res["encoding"] = e_res

    # Encryption
    if cat in ("all", "encryption") or meth in ("AES-256", "3DES", "ROT13", "XOR"):
        enc_res = {}
        if meth in ("all", "AES-256"):
            enc_res["AES-256"] = {
                "Encrypt": encryption.encrypt_aes(text, key, adv.aes_key_bits, adv.aes_aad, adv.aes_output_format),
                "Decrypt": encryption.decrypt_aes(text, key, adv.aes_key_bits, adv.aes_aad, adv.aes_output_format),
            }
        if meth in ("all", "3DES"):
            enc_res["3DES"] = {
                "Encrypt": encryption.encrypt_3des(text, key, adv.des_output_format),
                "Decrypt": encryption.decrypt_3des(text, key, adv.des_output_format),
            }
        if meth in ("all", "ROT13"):
            enc_res["ROT13"] = encryption.rot13(text)
        if meth in ("all", "XOR"):
            enc_res["XOR"] = {
                "Encrypt": encryption.xor_cipher(text, key, adv.xor_output_format),
                "Decrypt": encryption.xor_decipher(text, key, adv.xor_output_format),
            }
        if enc_res: res["encryption"] = enc_res

    # Formatting
    if cat in ("all", "formatting") or meth in ("JSON", "JWT Decoder"):
        f_res = {}
        if meth in ("all", "JSON"):
            f_res["JSON"] = {"Beautify": formatting.format_json_beautify(text), "Minify": formatting.format_json_minify(text)}
        if meth in ("all", "JWT Decoder"):
            f_res["JWT Decoder"] = formatting.decode_jwt(text)
        if f_res: res["formatting"] = f_res

    return res


# ── Key generation endpoint ───────────────────────────────────────────────────

@app.post("/api/generate-key")
@limiter.limit("60/minute")
def generate_key(request: Request, payload: KeyGenRequest):
    logger.info(f"Key generation from {_get_client_ip(request)} | Algorithm: {payload.algorithm}")
    return keygen.generate(
        algorithm=payload.algorithm,
        fmt=payload.format,
        length=payload.length,
        include_symbols=payload.include_symbols,
    )


# ── Sharing endpoints ─────────────────────────────────────────────────────────

@app.post("/api/share", response_model=ShareResponse)
@limiter.limit("10/minute")
async def create_share(request: Request, payload: ShareCreate, db: AsyncSession = Depends(get_db)):
    share_id = str(uuid.uuid4())
    # Save to Redis with 24h TTL
    await redis_client.setex(f"share:{share_id}", 86400, payload.secret)
    
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    # Audit log
    audit = ShareAuditLog(id=share_id, expires_at=expires)
    db.add(audit)
    await db.commit()
    
    logger.info(f"Share link created: {share_id} by {_get_client_ip(request)}")
    return ShareResponse(uuid=share_id, expires_at=expires.isoformat())

@app.get("/api/share/{share_id}", response_model=ShareGet)
@limiter.limit("30/minute")
async def get_share(request: Request, share_id: UUID, db: AsyncSession = Depends(get_db)):
    share_id_str = str(share_id)
    secret = await redis_client.getdel(f"share:{share_id_str}")
    if not secret:
        logger.warning(f"Share link not found or already burned: {share_id_str} accessed by {_get_client_ip(request)}")
        raise HTTPException(status_code=404, detail="Link expired or already used.")
        
    audit = await db.get(ShareAuditLog, share_id_str)
    if audit:
        audit.accessed_at = datetime.datetime.now(datetime.timezone.utc)
        await db.commit()
        
    logger.info(f"Share link accessed and burned: {share_id_str} by {_get_client_ip(request)}")
    return ShareGet(secret=secret)


# ── Admin endpoints ───────────────────────────────────────────────────────────

from fastapi import Header
@app.get("/api/liquid-sector/admin/logs")
@limiter.limit("10/minute")
def get_admin_logs(request: Request, x_admin_user: str = Header(default=""), x_admin_pass: str = Header(default="")):
    username = x_admin_user
    password = x_admin_pass
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        logger.warning(f"Failed admin login attempt from {_get_client_ip(request)}")
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    from .logger import LOG_FILE
    if not os.path.exists(LOG_FILE):
        return {"logs": []}
        
    log_entries = []
    current_entry = None
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-2000:]
            for line in lines:
                match = re.match(r"^\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*)", line)
                if match:
                    if current_entry:
                        log_entries.append(current_entry)
                    current_entry = {
                        "timestamp": match.group(1),
                        "level": match.group(2),
                        "name": match.group(3),
                        "message": match.group(4)
                    }
                else:
                    if current_entry:
                        current_entry["message"] += "\n" + line.rstrip()
            if current_entry:
                log_entries.append(current_entry)
        
        # Return reversed (newest first) up to 1000 items
        return {"logs": log_entries[::-1][:1000]}
    except Exception as e:
        logger.error(f"Error reading logs: {e}")
        return {"logs": []}

@app.delete("/api/liquid-sector/admin/logs")
@limiter.limit("5/minute")
def clear_admin_logs(request: Request, x_admin_user: str = Header(default=""), x_admin_pass: str = Header(default="")):
    username = x_admin_user
    password = x_admin_pass
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        logger.warning(f"Failed admin log purge attempt from {_get_client_ip(request)}")
        raise HTTPException(status_code=401, detail="Unauthorized")
        
    from .logger import LOG_FILE
    try:
        open(LOG_FILE, 'w').close()
        logger.info(f"Logs purged by admin from {_get_client_ip(request)}")
        return {"status": "cleared"}
    except Exception as e:
        logger.error(f"Error clearing logs: {e}")
        raise HTTPException(status_code=500, detail="Could not clear logs")


# ── HTML page endpoints ───────────────────────────────────────────────────────

@app.get("/liquid-sector/admin/dbusage")
async def serve_admin_html():
    html_path = os.path.join(DIST_DIR, "liquid-sector", "admin", "dbusage", "index.html")
    if not os.path.exists(html_path):
        return FileResponse(os.path.join(DIST_DIR, "index.html"))
    return FileResponse(html_path)

@app.get("/share/{share_id}")
async def serve_share_html(share_id: str):
    html_path = os.path.join(DIST_DIR, "share", "index.html")
    if not os.path.exists(html_path):
        return FileResponse(os.path.join(DIST_DIR, "index.html"))
    return FileResponse(html_path)

# ── Static files (Astro build) ────────────────────────────────────────────────
# Mounted AFTER API routes so /api/* is never intercepted by the static handler.

DIST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "dist")

if os.path.isdir(DIST_DIR):
    app.mount("/", StaticFiles(directory=DIST_DIR, html=True), name="static")
else:
    @app.get("/")
    def read_root():
        return {"status": "ok", "message": "API is running. Build Astro to see UI."}
