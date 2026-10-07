"""Environment-driven application configuration."""

from __future__ import annotations

import os
import secrets
from pathlib import Path


class Config:
    """Default application settings."""

    SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "5000"))
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
    MAX_REDIRECTS = 3
    REQUEST_TIMEOUT_SECONDS = 10
    MAX_RESPONSE_BYTES = 2_000_000
    MAX_CRAWL_DEPTH = 1
    MAX_CRAWL_PAGES = 10
    REQUEST_RATE_LIMIT_SECONDS = 0.25
    ALLOW_LOCAL_TARGETS = os.getenv("ALLOW_LOCAL_TARGETS", "0") == "1"
    REQUEST_HEADERS = {
        "User-Agent": "WebVulnerabilityScanner/1.0 (+https://github.com/)",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    }

    @staticmethod
    def database_path() -> Path:
        return Path(os.getenv("DATABASE_PATH", "database/scanner.db"))
