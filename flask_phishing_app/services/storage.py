from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    import psycopg
except Exception:  # pragma: no cover
    psycopg = None


class HistoryStore:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self.kind = "postgres" if database_url.startswith(("postgresql://", "postgres://")) else "sqlite"
        self.placeholder = "%s" if self.kind == "postgres" else "?"
        if self.kind == "sqlite" and database_url.startswith("sqlite:///"):
            self.db_path = database_url.replace("sqlite:///", "", 1)
        else:
            self.db_path = database_url

    def _connect(self):
        if self.kind == "postgres":
            if psycopg is None:
                raise RuntimeError("psycopg is required for PostgreSQL support")
            return psycopg.connect(self.database_url)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(self.db_path, timeout=30)

    def _fetchall(self, query: str, params: tuple = ()) -> list[tuple]:
        with self._connect() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            return rows

    def _fetchone(self, query: str, params: tuple = ()) -> tuple | None:
        with self._connect() as conn:
            cursor = conn.execute(query, params)
            return cursor.fetchone()

    def _execute(self, query: str, params: tuple = ()) -> None:
        with self._connect() as conn:
            conn.execute(query, params)
            conn.commit()

    def init_db(self) -> None:
        if self.kind == "postgres":
            self._init_postgres()
        else:
            self._init_sqlite()

    def _init_sqlite(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    first_name TEXT NOT NULL,
                    last_name TEXT,
                    mobile TEXT UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            user_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
            if "last_name" not in user_columns:
                conn.execute("ALTER TABLE users ADD COLUMN last_name TEXT")
            if "mobile" not in user_columns:
                conn.execute("ALTER TABLE users ADD COLUMN mobile TEXT")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    normalized_url TEXT NOT NULL,
                    username TEXT,
                    auth_provider TEXT,
                    verdict TEXT,
                    risk_score REAL,
                    ml_probability REAL,
                    cache_hit INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    payload TEXT NOT NULL
                )
                """
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(analysis_history)").fetchall()}
            if "username" not in columns:
                conn.execute("ALTER TABLE analysis_history ADD COLUMN username TEXT")
            if "auth_provider" not in columns:
                conn.execute("ALTER TABLE analysis_history ADD COLUMN auth_provider TEXT")
            if "cache_hit" not in columns:
                conn.execute("ALTER TABLE analysis_history ADD COLUMN cache_hit INTEGER DEFAULT 0")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER NOT NULL,
                    note TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(analysis_id) REFERENCES analysis_history(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER NOT NULL,
                    normalized_url TEXT NOT NULL,
                    username TEXT,
                    helpful INTEGER NOT NULL,
                    corrected_label TEXT,
                    note TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(analysis_id) REFERENCES analysis_history(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS background_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    payload TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 5,
                    last_error TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    not_before DATETIME DEFAULT CURRENT_TIMESTAMP,
                    reserved_at DATETIME,
                    worker_id TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_history_created_at ON analysis_history(created_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_history_username ON analysis_history(username)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status_not_before ON background_jobs(status, not_before)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_mobile ON users(mobile)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_url ON analysis_feedback(normalized_url)")
            conn.commit()

    def _init_postgres(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    first_name TEXT NOT NULL,
                    last_name TEXT,
                    mobile TEXT UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id BIGSERIAL PRIMARY KEY,
                    url TEXT NOT NULL,
                    normalized_url TEXT NOT NULL,
                    username TEXT,
                    auth_provider TEXT,
                    verdict TEXT,
                    risk_score DOUBLE PRECISION,
                    ml_probability DOUBLE PRECISION,
                    cache_hit BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    payload JSONB NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_notes (
                    id BIGSERIAL PRIMARY KEY,
                    analysis_id BIGINT NOT NULL REFERENCES analysis_history(id) ON DELETE CASCADE,
                    note TEXT NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_feedback (
                    id BIGSERIAL PRIMARY KEY,
                    analysis_id BIGINT NOT NULL REFERENCES analysis_history(id) ON DELETE CASCADE,
                    normalized_url TEXT NOT NULL,
                    username TEXT,
                    helpful BOOLEAN NOT NULL,
                    corrected_label TEXT,
                    note TEXT,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS background_jobs (
                    id BIGSERIAL PRIMARY KEY,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    payload JSONB NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 5,
                    last_error TEXT,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    not_before TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    reserved_at TIMESTAMPTZ,
                    worker_id TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_history_created_at ON analysis_history(created_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_history_username ON analysis_history(username)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status_not_before ON background_jobs(status, not_before)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_mobile ON users(mobile)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_url ON analysis_feedback(normalized_url)")
            conn.commit()

    def create_user(self, username: str, first_name: str, last_name: str, mobile: str, password_hash: str) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                f"""
                INSERT INTO users (username, first_name, last_name, mobile, password_hash)
                VALUES ({self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder})
                """,
                (username.lower().strip(), first_name.strip(), last_name.strip(), mobile.strip(), password_hash),
            )
            conn.commit()
            if self.kind == "postgres":
                row = conn.execute("SELECT LASTVAL()").fetchone()
                return int(row[0])
            return int(cursor.lastrowid)

    def get_user_by_username(self, username: str) -> dict | None:
        row = self._fetchone(
            f"""
            SELECT id, username, first_name, last_name, mobile, password_hash, created_at
            FROM users
            WHERE username = {self.placeholder}
            """,
            (username.lower().strip(),),
        )
        if not row:
            return None
        return {
            "id": row[0],
            "username": row[1],
            "first_name": row[2],
            "last_name": row[3],
            "mobile": row[4],
            "password_hash": row[5],
            "created_at": str(row[6]),
        }

    def get_user_by_mobile(self, mobile: str) -> dict | None:
        row = self._fetchone(
            f"""
            SELECT id, username, first_name, last_name, mobile, password_hash, created_at
            FROM users
            WHERE mobile = {self.placeholder}
            """,
            (mobile.strip(),),
        )
        if not row:
            return None
        return {
            "id": row[0],
            "username": row[1],
            "first_name": row[2],
            "last_name": row[3],
            "mobile": row[4],
            "password_hash": row[5],
            "created_at": str(row[6]),
        }

    def count_users(self) -> int:
        row = self._fetchone("SELECT COUNT(*) FROM users")
        return int(row[0] if row else 0)

    def save(self, result: dict, username: str | None = None, auth_provider: str | None = None) -> int:
        payload = json.dumps(result, default=str)
        params = (
            result.get("input_url", ""),
            result.get("url", ""),
            username,
            auth_provider,
            result.get("verdict", "Unknown"),
            float(result.get("hybrid_score", 0)),
            float(result.get("ml", {}).get("probability", 0)),
            bool(result.get("cache", {}).get("hit")),
            payload if self.kind == "sqlite" else json.loads(payload),
        )
        query = f"""
            INSERT INTO analysis_history (
                url, normalized_url, username, auth_provider, verdict, risk_score, ml_probability, cache_hit, payload
            ) VALUES ({self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder})
        """
        with self._connect() as conn:
            cursor = conn.execute(query, params)
            conn.commit()
            if self.kind == "postgres":
                row = conn.execute("SELECT LASTVAL()").fetchone()
                return int(row[0])
            return int(cursor.lastrowid)

    def fetch_recent(self, limit: int = 20, username: str | None = None) -> list[dict]:
        if username:
            rows = self._fetchall(
                f"""
                SELECT id, url, normalized_url, username, auth_provider, verdict, risk_score, ml_probability, cache_hit, created_at
                FROM analysis_history
                WHERE username = {self.placeholder}
                ORDER BY id DESC
                LIMIT {self.placeholder}
                """,
                (username, limit),
            )
        else:
            rows = self._fetchall(
                f"""
                SELECT id, url, normalized_url, username, auth_provider, verdict, risk_score, ml_probability, cache_hit, created_at
                FROM analysis_history
                ORDER BY id DESC
                LIMIT {self.placeholder}
                """,
                (limit,),
            )
        return [
            {
                "id": row[0],
                "url": row[1],
                "normalized_url": row[2],
                "username": row[3],
                "auth_provider": row[4],
                "verdict": row[5],
                "risk_score": row[6],
                "ml_probability": row[7],
                "cache_hit": bool(row[8]),
                "created_at": str(row[9]),
            }
            for row in rows
        ]

    def get_analysis(self, analysis_id: int) -> dict | None:
        row = self._fetchone(
            f"SELECT id, payload FROM analysis_history WHERE id = {self.placeholder}",
            (analysis_id,),
        )
        if not row:
            return None
        payload = row[1] if isinstance(row[1], dict) else json.loads(row[1])
        payload["analysis_id"] = row[0]
        payload["notes"] = self.fetch_notes(row[0])
        return payload

    def update_analysis(self, analysis_id: int, result: dict) -> None:
        payload = json.dumps(result, default=str)
        self._execute(
            f"""
            UPDATE analysis_history
            SET verdict = {self.placeholder},
                risk_score = {self.placeholder},
                ml_probability = {self.placeholder},
                cache_hit = {self.placeholder},
                payload = {self.placeholder}
            WHERE id = {self.placeholder}
            """,
            (
                result.get("verdict", "Unknown"),
                float(result.get("hybrid_score", 0)),
                float(result.get("ml", {}).get("probability", 0)),
                bool(result.get("cache", {}).get("hit")),
                payload if self.kind == "sqlite" else json.loads(payload),
                analysis_id,
            ),
        )

    def save_note(self, analysis_id: int, note: str) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                f"INSERT INTO analysis_notes (analysis_id, note) VALUES ({self.placeholder}, {self.placeholder})",
                (analysis_id, note),
            )
            conn.commit()
            if self.kind == "postgres":
                row = conn.execute("SELECT LASTVAL()").fetchone()
                return int(row[0])
            return int(cursor.lastrowid)

    def fetch_notes(self, analysis_id: int) -> list[dict]:
        rows = self._fetchall(
            f"""
            SELECT id, note, created_at
            FROM analysis_notes
            WHERE analysis_id = {self.placeholder}
            ORDER BY id DESC
            """,
            (analysis_id,),
        )
        return [{"id": row[0], "note": row[1], "created_at": str(row[2])} for row in rows]

    def save_feedback(
        self,
        analysis_id: int,
        normalized_url: str,
        username: str | None,
        helpful: bool,
        corrected_label: str | None,
        note: str | None,
    ) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                f"""
                INSERT INTO analysis_feedback (analysis_id, normalized_url, username, helpful, corrected_label, note)
                VALUES ({self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder})
                """,
                (
                    analysis_id,
                    normalized_url,
                    username,
                    bool(helpful),
                    (corrected_label or "").strip() or None,
                    (note or "").strip() or None,
                ),
            )
            conn.commit()
            if self.kind == "postgres":
                row = conn.execute("SELECT LASTVAL()").fetchone()
                return int(row[0])
            return int(cursor.lastrowid)

    def feedback_summary_for_url(self, normalized_url: str) -> dict:
        rows = self._fetchall(
            f"""
            SELECT helpful, corrected_label, note, username, created_at
            FROM analysis_feedback
            WHERE normalized_url = {self.placeholder}
            ORDER BY id DESC
            LIMIT 25
            """,
            (normalized_url,),
        )
        helpful = 0
        not_helpful = 0
        corrected: dict[str, int] = {}
        recent = []
        for row in rows:
            if bool(row[0]):
                helpful += 1
            else:
                not_helpful += 1
            label = (row[1] or "").strip()
            if label:
                corrected[label] = corrected.get(label, 0) + 1
            recent.append(
                {
                    "helpful": bool(row[0]),
                    "corrected_label": row[1],
                    "note": row[2],
                    "username": row[3],
                    "created_at": str(row[4]),
                }
            )
        top_corrected = sorted(corrected.items(), key=lambda item: item[1], reverse=True)
        return {
            "available": bool(rows),
            "helpful_count": helpful,
            "not_helpful_count": not_helpful,
            "top_corrected_labels": [{"label": label, "count": count} for label, count in top_corrected[:3]],
            "recent": recent[:5],
            "caution": "Community feedback is advisory only and may include malicious or low-quality submissions.",
        }

    def enqueue_job(self, kind: str, payload: dict, max_attempts: int = 5) -> int:
        payload_json = json.dumps(payload, default=str)
        with self._connect() as conn:
            cursor = conn.execute(
                f"""
                INSERT INTO background_jobs (kind, status, payload, attempts, max_attempts)
                VALUES ({self.placeholder}, 'pending', {self.placeholder}, 0, {self.placeholder})
                """,
                (kind, payload_json if self.kind == "sqlite" else json.loads(payload_json), max_attempts),
            )
            conn.commit()
            if self.kind == "postgres":
                row = conn.execute("SELECT LASTVAL()").fetchone()
                return int(row[0])
            return int(cursor.lastrowid)

    def count_pending_jobs(self) -> int:
        row = self._fetchone(
            """
            SELECT COUNT(*) FROM background_jobs
            WHERE status IN ('pending', 'retry')
            """
        )
        return int(row[0] if row else 0)

    def claim_job(self, worker_id: str, stale_after_seconds: int) -> dict | None:
        if self.kind == "postgres":
            return self._claim_job_postgres(worker_id)
        return self._claim_job_sqlite(worker_id, stale_after_seconds)

    def _claim_job_sqlite(self, worker_id: str, stale_after_seconds: int) -> dict | None:
        stale_before = (datetime.now(timezone.utc) - timedelta(seconds=stale_after_seconds)).strftime("%Y-%m-%d %H:%M:%S")
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, kind, payload, attempts, max_attempts
                FROM background_jobs
                WHERE status IN ('pending', 'retry')
                  AND datetime(not_before) <= datetime('now')
                  AND (reserved_at IS NULL OR datetime(reserved_at) < ?)
                ORDER BY id ASC
                LIMIT 1
                """,
                (stale_before,),
            ).fetchone()
            if not row:
                return None
            conn.execute(
                """
                UPDATE background_jobs
                SET status = 'running', attempts = attempts + 1, reserved_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP, worker_id = ?
                WHERE id = ?
                """,
                (worker_id, row[0]),
            )
            conn.commit()
            return {
                "id": row[0],
                "kind": row[1],
                "payload": json.loads(row[2]) if isinstance(row[2], str) else row[2],
                "attempts": row[3] + 1,
                "max_attempts": row[4],
            }

    def _claim_job_postgres(self, worker_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                WITH claimed AS (
                    SELECT id
                    FROM background_jobs
                    WHERE status IN ('pending', 'retry')
                      AND not_before <= CURRENT_TIMESTAMP
                    ORDER BY id ASC
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )
                UPDATE background_jobs
                SET status = 'running',
                    attempts = attempts + 1,
                    reserved_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP,
                    worker_id = %s
                WHERE id IN (SELECT id FROM claimed)
                RETURNING id, kind, payload, attempts, max_attempts
                """,
                (worker_id,),
            ).fetchone()
            conn.commit()
            if not row:
                return None
            return {
                "id": row[0],
                "kind": row[1],
                "payload": row[2] if isinstance(row[2], dict) else json.loads(row[2]),
                "attempts": row[3],
                "max_attempts": row[4],
            }

    def complete_job(self, job_id: int) -> None:
        self._execute(
            f"UPDATE background_jobs SET status = 'completed', updated_at = CURRENT_TIMESTAMP WHERE id = {self.placeholder}",
            (job_id,),
        )

    def fail_job(self, job_id: int, error: str, retryable: bool) -> None:
        status = "retry" if retryable else "failed"
        if self.kind == "postgres":
            self._execute(
                f"""
                UPDATE background_jobs
                SET status = %s,
                    last_error = %s,
                    updated_at = CURRENT_TIMESTAMP,
                    not_before = CURRENT_TIMESTAMP + INTERVAL '30 seconds'
                WHERE id = %s
                """,
                (status, error[:2000], job_id),
            )
        else:
            self._execute(
                """
                UPDATE background_jobs
                SET status = ?,
                    last_error = ?,
                    updated_at = CURRENT_TIMESTAMP,
                    not_before = datetime('now', '+30 seconds')
                WHERE id = ?
                """,
                (status, error[:2000], job_id),
            )

    def healthcheck(self) -> bool:
        try:
            row = self._fetchone("SELECT 1")
            return bool(row and row[0] == 1)
        except Exception:
            return False
