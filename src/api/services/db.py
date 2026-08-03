import os
import sys
import redis.asyncio as redis
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL")

if not REDIS_URL:
    print("FATAL ERROR: REDIS_URL must be set in the environment.", file=sys.stderr)
    sys.exit(1)

# --- Redis Setup ---
redis_client = redis.from_url(REDIS_URL, decode_responses=True)
