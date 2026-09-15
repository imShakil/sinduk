"""
Self-hosted zero-knowledge relay/sync server for pacli teams.

The server only stores and routes encrypted blobs. It has no key derivation material,
passwords, or access to plaintext secrets.
"""

import os
import time
import uuid
import hashlib
import sqlite3
import secrets
from flask import Flask, request, jsonify, Response, g
from functools import wraps
from .log import get_logger

logger = get_logger("sinduk.server")

SERVER_DIR = os.path.expanduser("~/.config/sinduk/server")
SERVER_DB_PATH = os.path.join(SERVER_DIR, "server.db")


class SyncServerDB:
    """Database store for the self-hosted sync server."""

    def __init__(self, db_path=SERVER_DB_PATH):
        self.db_path = os.path.expanduser(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_conn(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tokens (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'member',
                    created_at INTEGER NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vault_blobs (
                    vault_name TEXT PRIMARY KEY,
                    blob BLOB NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    checksum TEXT NOT NULL,
                    updated_by TEXT,
                    updated_at INTEGER NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS server_audit (
                    id TEXT PRIMARY KEY,
                    token_id TEXT,
                    vault_name TEXT,
                    action TEXT NOT NULL,
                    ip TEXT,
                    timestamp INTEGER NOT NULL
                )
            """)
            conn.commit()

    def create_token(self, name: str, role: str = "member") -> tuple[str, str]:
        """
        Generate a new access token.

        Returns:
            (token_id, raw_token)
        """
        raw_token = f"sinduk_tok_{secrets.token_urlsafe(32)}"
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        token_id = uuid.uuid4().hex[:8]
        now = int(time.time())

        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO tokens (id, name, token_hash, role, created_at, active) VALUES (?, ?, ?, ?, ?, 1)",
                (token_id, name, token_hash, role, now),
            )
            conn.commit()

        logger.info(f"Created token {token_id} for {name} ({role})")
        return token_id, raw_token

    def verify_token(self, raw_token: str) -> dict | None:
        """Verify token and return token info if valid."""
        if not raw_token:
            return None
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT id, name, role, created_at, active FROM tokens WHERE token_hash = ? AND active = 1",
                (token_hash,),
            ).fetchone()
            if row:
                return {
                    "id": row[0],
                    "name": row[1],
                    "role": row[2],
                    "created_at": row[3],
                    "active": bool(row[4]),
                }
        return None

    def list_tokens(self) -> list[dict]:
        """List all tokens."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT id, name, role, created_at, active FROM tokens ORDER BY created_at DESC"
            ).fetchall()
            return [
                {
                    "id": r[0],
                    "name": r[1],
                    "role": r[2],
                    "created_at": r[3],
                    "active": bool(r[4]),
                }
                for r in rows
            ]

    def revoke_token(self, token_id: str) -> bool:
        """Revoke a token."""
        with self._get_conn() as conn:
            cursor = conn.execute("UPDATE tokens SET active = 0 WHERE id = ?", (token_id,))
            conn.commit()
            return cursor.rowcount > 0

    def save_blob(self, vault_name: str, blob_bytes: bytes, updated_by: str = "") -> dict:
        """Store or update an encrypted vault blob."""
        checksum = hashlib.sha256(blob_bytes).hexdigest()
        now = int(time.time())

        with self._get_conn() as conn:
            existing = conn.execute(
                "SELECT version, checksum FROM vault_blobs WHERE vault_name = ?", (vault_name,)
            ).fetchone()

            if existing:
                # If content is identical, don't bump version
                if existing[1] == checksum:
                    return {"version": existing[0], "checksum": checksum, "updated": False}

                version = existing[0] + 1
                conn.execute(
                    "UPDATE vault_blobs SET blob = ?, version = ?, checksum = ?, updated_by = ?, updated_at = ? "
                    "WHERE vault_name = ?",
                    (blob_bytes, version, checksum, updated_by, now, vault_name),
                )
            else:
                version = 1
                conn.execute(
                    "INSERT INTO vault_blobs (vault_name, blob, version, checksum, updated_by, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (vault_name, blob_bytes, version, checksum, updated_by, now),
                )

            conn.commit()

        logger.info(f"Saved blob for vault '{vault_name}' (version {version}) by {updated_by}")
        return {"version": version, "checksum": checksum, "updated": True}

    def get_blob(self, vault_name: str) -> tuple[bytes, dict] | tuple[None, None]:
        """Retrieve an encrypted vault blob and metadata."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT blob, version, checksum, updated_by, updated_at FROM vault_blobs WHERE vault_name = ?",
                (vault_name,),
            ).fetchone()
            if row:
                blob = row[0]
                meta = {
                    "vault_name": vault_name,
                    "version": row[1],
                    "checksum": row[2],
                    "updated_by": row[3],
                    "updated_at": row[4],
                    "size": len(blob),
                }
                return blob, meta
        return None, None

    def get_status(self, vault_name: str) -> dict | None:
        """Get status metadata of a vault blob without reading entire blob payload."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT version, checksum, updated_by, updated_at, LENGTH(blob) FROM vault_blobs WHERE vault_name = ?",
                (vault_name,),
            ).fetchone()
            if row:
                return {
                    "vault_name": vault_name,
                    "version": row[0],
                    "checksum": row[1],
                    "updated_by": row[2],
                    "updated_at": row[3],
                    "size": row[4],
                }
        return None

    def log_audit(self, token_id: str, vault_name: str, action: str, ip: str = ""):
        """Log a sync action."""
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO server_audit (id, token_id, vault_name, action, ip, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (uuid.uuid4().hex[:8], token_id, vault_name, action, ip, int(time.time())),
            )
            conn.commit()


def _build_require_token(db: SyncServerDB):
    def require_token(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            token = ""
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
            elif request.headers.get("X-Sinduk-Token"):
                token = request.headers.get("X-Sinduk-Token", "").strip()
            elif request.headers.get("X-Pacli-Token"):
                token = request.headers.get("X-Pacli-Token", "").strip()

            if not token:
                return jsonify({"error": "Unauthorized — Bearer token required"}), 401

            token_info = db.verify_token(token)
            if not token_info:
                return jsonify({"error": "Invalid or revoked token"}), 401

            g.token_info = token_info
            return f(*args, **kwargs)

        return decorated

    return require_token


def _register_sync_server_routes(app: Flask, db: SyncServerDB, require_token):
    @app.route("/health", methods=["GET"])
    @app.route("/api/v1/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "service": "sinduk-sync-server"})

    @app.route("/api/v1/auth/verify", methods=["GET"])
    @require_token
    def verify_auth():
        token_info = getattr(g, "token_info", {})
        return jsonify(
            {
                "valid": True,
                "token_id": token_info.get("id"),
                "name": token_info.get("name"),
                "role": token_info.get("role"),
                "service": "sinduk-sync-server",
            }
        )

    @app.route("/api/v1/sync/push/<vault_name>", methods=["POST"])
    @require_token
    def push_blob(vault_name):
        vault_name = vault_name.strip().lower()
        blob_bytes = request.get_data()

        if not blob_bytes:
            return jsonify({"error": "Empty payload"}), 400

        token_info = getattr(g, "token_info", {})
        default_user = token_info.get("name", "")
        token_id = token_info.get("id", "")

        user_name = request.headers.get("X-Sinduk-User") or request.headers.get("X-Pacli-User") or default_user
        result = db.save_blob(vault_name, blob_bytes, updated_by=user_name)
        db.log_audit(token_id, vault_name, "push", request.remote_addr or "")

        return jsonify(
            {
                "success": True,
                "vault": vault_name,
                "version": result["version"],
                "checksum": result["checksum"],
                "updated": result["updated"],
            }
        )

    @app.route("/api/v1/sync/pull/<vault_name>", methods=["GET"])
    @require_token
    def pull_blob(vault_name):
        vault_name = vault_name.strip().lower()
        blob, meta = db.get_blob(vault_name)

        if blob is None or meta is None:
            return jsonify({"error": f"Vault '{vault_name}' not found on server"}), 404

        client_checksum = request.headers.get("If-None-Match", "").strip()
        if client_checksum and client_checksum == meta["checksum"]:
            return Response(status=304)

        token_info = getattr(g, "token_info", {})
        token_id = token_info.get("id", "")
        db.log_audit(token_id, vault_name, "pull", request.remote_addr or "")

        return Response(
            blob,
            mimetype="application/octet-stream",
            headers={
                "X-Vault-Version": str(meta["version"]),
                "X-Vault-Checksum": str(meta["checksum"]),
                "X-Vault-Updated-By": str(meta["updated_by"] or ""),
                "X-Vault-Updated-At": str(meta["updated_at"]),
                "ETag": str(meta["checksum"]),
            },
        )

    @app.route("/api/v1/sync/status/<vault_name>", methods=["GET"])
    @require_token
    def status_blob(vault_name):
        vault_name = vault_name.strip().lower()
        status = db.get_status(vault_name)
        if status is None:
            return jsonify({"error": f"Vault '{vault_name}' not found on server"}), 404

        return jsonify({"status": "found", **status})


def create_sync_server_app(db: SyncServerDB | None = None) -> Flask:
    """
    Create Flask application for the sync server.

    Security Note (CSRF Exemption):
        CSRF protection is not applicable here because this is a purely stateless REST API
        consumed by CLI clients and automated sync jobs. Authentication relies exclusively
        on custom HTTP headers (`Authorization: Bearer <token>` or `X-Pacli-Token`), with no
        cookie-based ambient session credentials.
    """
    if db is None:
        db = SyncServerDB()

    app = Flask("sinduk_sync_server")  # NOSONAR - python:S4502: Stateless REST API using Bearer token auth
    require_token = _build_require_token(db)
    _register_sync_server_routes(app, db, require_token)
    return app
