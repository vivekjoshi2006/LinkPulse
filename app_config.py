import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

def _get_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, default))
    except (TypeError, ValueError):
        return default

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY") or "dev-only-change-this-secret-before-deploying"

    DB_ENGINE = os.getenv("DB_ENGINE", "auto").lower()
    SQLITE_PATH = os.getenv("SQLITE_PATH", str(BASE_DIR / "linkpulse.db"))

    DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
    DB_PORT = _get_int("DB_PORT", 3306)
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME = os.getenv("DB_NAME", "linkpulse")

    PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:5000").rstrip("/")
    CORS_ORIGINS = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "").split(",") if origin.strip()]

    CSV_MAX_BYTES = _get_int("CSV_MAX_BYTES", 2 * 1024 * 1024)
    MAX_IMPORT_ROWS = _get_int("MAX_IMPORT_ROWS", 2500)

    RATE_LIMIT_CREATE = _get_int("RATE_LIMIT_CREATE", 60)
    RATE_LIMIT_PASSWORD = _get_int("RATE_LIMIT_PASSWORD", 8)
    RATE_LIMIT_WINDOW_SECONDS = _get_int("RATE_LIMIT_WINDOW_SECONDS", 60)
