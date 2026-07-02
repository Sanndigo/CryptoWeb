import logging
from logging.handlers import RotatingFileHandler
import os

# Create logs directory at the project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOGS_DIR, "backend.log")

def setup_logging():
    logger = logging.getLogger("cryptoweb")
    logger.setLevel(logging.INFO)

    # 5 MB max size per file, keep last 5 backups
    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5)
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Avoid duplicate handlers if imported multiple times
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    # Intercept and save Uvicorn logs
    uvicorn_error = logging.getLogger("uvicorn.error")
    uvicorn_access = logging.getLogger("uvicorn.access")
    
    # We add our file handler to uvicorn loggers so they write to backend.log too
    if not any(isinstance(h, RotatingFileHandler) for h in uvicorn_error.handlers):
        uvicorn_error.addHandler(file_handler)
    if not any(isinstance(h, RotatingFileHandler) for h in uvicorn_access.handlers):
        uvicorn_access.addHandler(file_handler)

    return logger

logger = setup_logging()
