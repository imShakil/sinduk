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


def _hash_user_password(password: str, salt_bytes: bytes | None = None) -> tuple[str, str]:
    """Hash password using PBKDF2-HMAC-SHA256 (100,000 iterations). Returns (hex_hash, hex_salt)."""
    if salt_bytes is None:
        salt_bytes = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 100_000)
    return hashed.hex(), salt_bytes.hex()


def _verify_user_password(password: str, expected_hash_hex: str, salt_hex: str) -> bool:
    """Verify password against stored hash and salt."""
    try:
        salt_bytes = bytes.fromhex(salt_hex)
        actual_hash_hex, _ = _hash_user_password(password, salt_bytes)
        return secrets.compare_digest(actual_hash_hex, expected_hash_hex)
    except Exception:
        return False


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
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    display_name TEXT NOT NULL,
                    auth_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    public_key TEXT,
                    enc_private_key TEXT,
                    role TEXT NOT NULL DEFAULT 'member',
                    created_at INTEGER NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS device_codes (
                    code TEXT PRIMARY KEY,
                    session_id TEXT UNIQUE NOT NULL,
                    user_id TEXT,
                    token TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
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

    def register_user(
        self,
        email: str,
        password: str,
        display_name: str,
        role: str = "member",
        public_key: str = "",
        enc_private_key: str = "",
    ) -> tuple[dict, str]:
        """Register a new user account and return (user_dict, raw_token)."""
        email = email.strip().lower()
        display_name = display_name.strip()
        user_id = uuid.uuid4().hex[:12]
        auth_hash, salt = _hash_user_password(password)
        now = int(time.time())

        with self._get_conn() as conn:
            existing = conn.execute("SELECT user_id FROM users WHERE email = ?", (email,)).fetchone()
            if existing:
                raise ValueError(f"User with email '{email}' already exists.")

            conn.execute(
                "INSERT INTO users "
                "(user_id, email, display_name, auth_hash, salt, public_key, enc_private_key, role, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, email, display_name, auth_hash, salt, public_key, enc_private_key, role, now),
            )
            conn.commit()

        # Generate active bearer token for this registered session
        _, raw_token = self.create_token(name=f"{display_name} ({email})", role=role)
        user_dict = {
            "user_id": user_id,
            "email": email,
            "display_name": display_name,
            "role": role,
            "public_key": public_key,
            "enc_private_key": enc_private_key,
            "created_at": now,
        }
        logger.info(f"Registered user '{email}' (ID: {user_id})")
        return user_dict, raw_token

    def authenticate_user(self, email: str, password: str) -> tuple[dict | None, str | None]:
        """Authenticate user credentials. Returns (user_dict, raw_token) if successful."""
        email = email.strip().lower()
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT user_id, email, display_name, auth_hash, salt, public_key, enc_private_key, role, created_at "
                "FROM users WHERE email = ?",
                (email,),
            ).fetchone()
            if not row:
                return None, None

            user_id, user_email, display_name, auth_hash, salt, pub_key, enc_priv_key, role, created_at = row
            if not _verify_user_password(password, auth_hash, salt):
                return None, None

        _, raw_token = self.create_token(name=f"{display_name} ({user_email})", role=role)
        user_dict = {
            "user_id": user_id,
            "email": user_email,
            "display_name": display_name,
            "role": role,
            "public_key": pub_key or "",
            "enc_private_key": enc_priv_key or "",
            "created_at": created_at,
        }
        return user_dict, raw_token

    def get_user_by_email(self, email: str) -> dict | None:
        """Fetch user by email."""
        email = email.strip().lower()
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT user_id, email, display_name, role, public_key, enc_private_key, created_at "
                "FROM users WHERE email = ?",
                (email,),
            ).fetchone()
            if row:
                return {
                    "user_id": row[0],
                    "email": row[1],
                    "display_name": row[2],
                    "role": row[3],
                    "public_key": row[4] or "",
                    "enc_private_key": row[5] or "",
                    "created_at": row[6],
                }
        return None

    def create_device_code(self, expires_in: int = 600) -> tuple[str, str]:
        """Generate a user-friendly device code and session ID for CLI pairing."""
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        part1 = "".join(secrets.choice(alphabet) for _ in range(4))
        part2 = "".join(secrets.choice(alphabet) for _ in range(4))
        device_code = f"{part1}-{part2}"
        session_id = f"sinduk_sess_{secrets.token_urlsafe(24)}"
        now = int(time.time())
        expires_at = now + expires_in

        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO device_codes (code, session_id, status, created_at, expires_at) "
                "VALUES (?, ?, 'pending', ?, ?)",
                (device_code, session_id, now, expires_at),
            )
            conn.commit()

        return device_code, session_id

    def authorize_device_code(self, code_or_session: str, user_id: str, raw_token: str) -> bool:
        """Authorize a pending device code by assigning the authenticated user and token."""
        code_clean = code_or_session.strip().upper()
        now = int(time.time())
        with self._get_conn() as conn:
            cursor = conn.execute(
                "UPDATE device_codes SET user_id = ?, token = ?, status = 'authorized' "
                "WHERE (code = ? OR session_id = ?) AND status = 'pending' AND expires_at > ?",
                (user_id, raw_token, code_clean, code_or_session, now),
            )
            conn.commit()
            return cursor.rowcount > 0

    def poll_device_code(self, session_id: str) -> dict:
        """Check status of a device code session."""
        now = int(time.time())
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT status, user_id, token, expires_at FROM device_codes WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if not row:
                return {"status": "not_found"}

            status, user_id, token, expires_at = row
            if status == "pending" and now > expires_at:
                conn.execute("UPDATE device_codes SET status = 'expired' WHERE session_id = ?", (session_id,))
                conn.commit()
                return {"status": "expired"}

            if status == "authorized":
                return {"status": "authorized", "user_id": user_id, "token": token}

            return {"status": status}

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


def _register_health_routes(app: Flask):
    @app.route("/health", methods=["GET"])
    @app.route("/api/v1/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "service": "sinduk-sync-server"})


def _register_auth_verify_route(app: Flask, require_token):
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


def _register_user_auth_routes(app: Flask, db: SyncServerDB):
    @app.route("/api/v1/auth/register", methods=["POST"])
    def register():
        data = request.get_json(silent=True) or {}
        email = data.get("email", "").strip()
        password = data.get("password", "")
        display_name = data.get("display_name", "").strip() or email.split("@")[0]
        role = data.get("role", "member")
        public_key = data.get("public_key", "")
        enc_private_key = data.get("enc_private_key", "")

        if not email or not password:
            return jsonify({"error": "Email and password are required."}), 400

        try:
            user, token = db.register_user(
                email=email,
                password=password,
                display_name=display_name,
                role=role,
                public_key=public_key,
                enc_private_key=enc_private_key,
            )
            return jsonify({"success": True, "token": token, "user": user}), 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 409
        except Exception as e:
            logger.error(f"Error registering user: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/v1/auth/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) or {}
        email = data.get("email", "").strip()
        password = data.get("password", "")

        if not email or not password:
            return jsonify({"error": "Email and password are required."}), 400

        user, token = db.authenticate_user(email=email, password=password)
        if not user or not token:
            return jsonify({"error": "Invalid email or password."}), 401

        return jsonify({"success": True, "token": token, "user": user}), 200


def _register_device_auth_routes(app: Flask, db: SyncServerDB, require_token):
    @app.route("/api/v1/auth/device/code", methods=["POST"])
    def create_device_code_route():
        device_code, session_id = db.create_device_code(expires_in=600)
        return jsonify(
            {
                "device_code": device_code,
                "session_id": session_id,
                "verification_uri": "/auth/device",
                "expires_in": 600,
            }
        )

    @app.route("/api/v1/auth/device/authorize", methods=["POST"])
    @require_token
    def authorize_device_code_route():
        data = request.get_json(silent=True) or {}
        code = data.get("device_code", "").strip() or data.get("session_id", "").strip()
        if not code:
            return jsonify({"error": "device_code or session_id is required."}), 400

        token_info = getattr(g, "token_info", {})
        user_name = token_info.get("name", "")
        # Generate a distinct session token for the authorized CLI client
        _, cli_token = db.create_token(name=f"{user_name} (CLI Session)", role=token_info.get("role", "member"))

        success = db.authorize_device_code(code, token_info.get("id", ""), cli_token)
        if not success:
            return jsonify({"error": "Invalid or expired device code."}), 400

        return jsonify({"success": True, "message": "Device successfully authorized."})

    @app.route("/api/v1/auth/device/poll", methods=["GET"])
    def poll_device_code_route():
        session_id = request.args.get("session_id", "").strip()
        if not session_id:
            return jsonify({"error": "session_id parameter is required."}), 400

        res = db.poll_device_code(session_id)
        if res.get("status") == "authorized":
            return jsonify({"status": "authorized", "token": res.get("token")})
        if res.get("status") == "expired":
            return jsonify({"status": "expired", "error": "Device code has expired."}), 400
        if res.get("status") == "not_found":
            return jsonify({"status": "not_found", "error": "Session not found."}), 404

        return jsonify({"status": "pending"})


def _register_sync_push_route(app: Flask, db: SyncServerDB, require_token):
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


def _register_sync_pull_route(app: Flask, db: SyncServerDB, require_token):
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


def _register_sync_status_route(app: Flask, db: SyncServerDB, require_token):
    @app.route("/api/v1/sync/status/<vault_name>", methods=["GET"])
    @require_token
    def status_blob(vault_name):
        vault_name = vault_name.strip().lower()
        status = db.get_status(vault_name)
        if status is None:
            return jsonify({"error": f"Vault '{vault_name}' not found on server"}), 404

        return jsonify({"status": "found", **status})


def _register_sync_server_routes(app: Flask, db: SyncServerDB, require_token):
    _register_health_routes(app)
    _register_auth_verify_route(app, require_token)
    _register_user_auth_routes(app, db)
    _register_device_auth_routes(app, db, require_token)
    _register_sync_push_route(app, db, require_token)
    _register_sync_pull_route(app, db, require_token)
    _register_sync_status_route(app, db, require_token)


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
