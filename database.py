"""SQLite persistence for scan history and reports."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    final_url TEXT,
    scanned_at TEXT NOT NULL,
    status TEXT NOT NULL,
    score INTEGER NOT NULL,
    summary TEXT NOT NULL,
    response_status INTEGER,
    response_size INTEGER,
    results_json TEXT NOT NULL,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    contact TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
"""

MIGRATIONS = (
    "ALTER TABLE scans ADD COLUMN final_url TEXT",
    "ALTER TABLE scans ADD COLUMN response_status INTEGER",
    "ALTER TABLE scans ADD COLUMN response_size INTEGER",
)


class ScanStore:
    """Small SQLite wrapper around the scanner's persisted records."""

    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(SCHEMA)
            for migration in MIGRATIONS:
                try:
                    connection.execute(migration)
                except sqlite3.OperationalError as exc:
                    if "duplicate column name" not in str(exc).lower():
                        raise

    def save_scan(self, result: dict[str, Any]) -> int:
        scanned_at = datetime.now(timezone.utc).isoformat()
        payload = {
            "findings": result.get("findings", []),
            "discovered_urls": result.get("discovered_urls", []),
            "severity": result.get("severity"),
            "risk_level": result.get("risk_level"),
        }
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scans
                    (target, final_url, scanned_at, status, score, summary,
                     response_status, response_size, results_json, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result["target"],
                    result.get("final_url"),
                    scanned_at,
                    result["status"],
                    result["score"],
                    result["summary"],
                    result.get("response_status"),
                    result.get("response_size"),
                    json.dumps(payload, ensure_ascii=False),
                    result.get("error_message"),
                ),
            )
            return int(cursor.lastrowid)

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        try:
            scan_id_int = int(scan_id)
        except ValueError:
            return None
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id_int,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def fetch_recent_scans(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def create_user(
        self,
        name: str,
        email: str,
        password_hash: str,
        contact: str,
    ) -> int:
        created_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (name, email, password_hash, contact, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (name, email.lower(), password_hash, contact, created_at),
            )
        return int(cursor.lastrowid)

    def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE email = ?", (email.lower(),)
            ).fetchone()
        return dict(row) if row is not None else None

    def get_user(self, user_id: int) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        payload = json.loads(data.pop("results_json"))
        if isinstance(payload, dict):
            data["findings"] = payload.get("findings", [])
            data["discovered_urls"] = payload.get("discovered_urls", [])
            data["severity"] = payload.get("severity") or data.get("severity")
            data["risk_level"] = payload.get("risk_level") or data.get("risk_level")
        else:
            data["findings"] = payload
            data["discovered_urls"] = []
            data["severity"] = None
            data["risk_level"] = None
        return data


def initialize_database(database_path: str | Path) -> None:
    ScanStore(database_path)._initialize()


def get_db(database_path: str | Path) -> ScanStore:
    return ScanStore(database_path)
