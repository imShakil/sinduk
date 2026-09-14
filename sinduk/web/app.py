import os
import uuid
from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from functools import wraps
from datetime import datetime
from urllib.parse import urlparse
from ..store import SecretStore
from ..vault import VaultManager, get_user_identity
from ..log import get_logger
from .ssh_handler import SSHConnectionManager

logger = get_logger("sinduk.web")
ERR_SECRET_NOT_FOUND = "Secret not found"


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = os.environ.get("SINDUK_WEB_SECRET_KEY") or os.environ.get(
        "PACLI_WEB_SECRET_KEY", "sinduk-dev-secret-key-change-in-production"
    )

    app.config["SESSION_PERMANENT"] = True
    app.config["PERMANENT_SESSION_LIFETIME"] = 86400 * 7
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    store = SecretStore()
    ssh_manager = SSHConnectionManager()
    vault_manager = VaultManager()
    socketio = SocketIO(app)  # type: ignore

    _register_csrf_same_origin_protection(app)
    require_auth = _build_require_auth(store)

    _register_page_routes(app)
    _register_auth_routes(app, store)
    _register_secret_routes(app, store, require_auth)
    _register_backup_routes(app, store, require_auth)
    _register_ssh_rest_routes(app, store, ssh_manager, require_auth)
    _register_socket_handlers(socketio, store, ssh_manager)
    _register_vault_routes(app, store, vault_manager, require_auth)

    return app, socketio


def _is_same_origin(source_url, host_url):
    if not source_url:
        return False
    source = urlparse(source_url)
    host = urlparse(host_url)
    return source.scheme == host.scheme and source.netloc == host.netloc


def _register_csrf_same_origin_protection(app):
    @app.before_request
    def _csrf_same_origin_protection():
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return None
        if request.path.startswith("/socket.io"):
            return None

        origin = request.headers.get("Origin")
        referer = request.headers.get("Referer")
        request_source = origin or referer

        if _is_same_origin(request_source, request.host_url):
            return None

        logger.warning(
            "Rejected due to CSRF origin check failure: path=%s origin=%s referer=%s",
            request.path,
            origin,
            referer,
        )
        return jsonify({"error": "CSRF validation failed"}), 403


def _build_require_auth(store):
    def require_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "authenticated" not in session:
                return jsonify({"error": "Unauthorized"}), 401
            if store.fernet is None:
                session.clear()
                return jsonify({"error": "Session expired. Please sign in again."}), 401
            return f(*args, **kwargs)

        return decorated

    return require_auth


def _serialize_secret_row(secret_row):
    return {
        "id": secret_row[0],
        "label": secret_row[1],
        "type": secret_row[2],
        "creation_time": secret_row[3],
        "update_time": secret_row[4],
        "creation_date": datetime.fromtimestamp(secret_row[3]).strftime("%Y-%m-%d %H:%M"),
        "update_date": datetime.fromtimestamp(secret_row[4]).strftime("%Y-%m-%d %H:%M"),
    }


def _serialize_vault_secret_row(s):
    return {
        "id": s[0],
        "label": s[1],
        "type": s[2],
        "created_by": s[3],
        "creation_time": s[4],
        "update_time": s[5],
        "creation_date": datetime.fromtimestamp(s[4]).strftime("%Y-%m-%d %H:%M") if s[4] else "",
        "update_date": datetime.fromtimestamp(s[5]).strftime("%Y-%m-%d %H:%M") if s[5] else "",
    }


def _register_page_routes(app):
    @app.route("/", methods=["GET"])
    def index():
        return render_template("index.html")


def _register_auth_routes(app, store):
    _register_setup_status_route(app, store)
    _register_setup_init_route(app, store)
    _register_auth_check_route(app, store)
    _register_auth_login_route(app, store)
    _register_auth_logout_route(app)


def _register_setup_status_route(app, store):
    @app.route("/api/setup/status", methods=["GET"])
    def setup_status():
        return jsonify({"configured": store.is_master_set()})


def _register_setup_init_route(app, store):
    @app.route("/api/setup/init", methods=["POST"])
    def setup_init():
        if store.is_master_set():
            return jsonify({"error": "Already configured"}), 400  # Noncompliant

        data = request.get_json()
        password = data.get("password", "")
        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400

        confirm = data.get("confirm", "")
        if password != confirm:
            return jsonify({"error": "Passwords do not match"}), 400  # Noncompliant

        from ..store import get_salt, PASSWORD_HASH_PATH, SALT_PATH
        import hashlib

        salt = get_salt()
        with open(SALT_PATH + ".set", "w") as f:
            f.write("set")
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        with open(PASSWORD_HASH_PATH, "w") as f:
            f.write(password_hash)
        store.fernet = store._derive_fernet(password, salt)

        session.permanent = True
        session["authenticated"] = True
        logger.info("Master password set via Web UI.")
        return jsonify({"success": True})


def _register_auth_check_route(app, store):
    @app.route("/api/auth/check", methods=["GET"])
    def check_auth():
        authenticated = "authenticated" in session and store.fernet is not None
        if not authenticated and "authenticated" in session and store.fernet is None:
            session.clear()
        return jsonify(
            {
                "authenticated": authenticated,
                "configured": store.is_master_set(),
            }
        )


def _register_auth_login_route(app, store):
    @app.route("/api/auth/login", methods=["POST"])
    def login():
        data = request.get_json()
        password = data.get("password")
        if not password:
            return jsonify({"error": "Password required"}), 400
        if not store.is_master_set():
            return jsonify({"error": "Not configured", "configured": False}), 400
        if store.verify_master_password(password):
            session.permanent = True
            session["authenticated"] = True
            store.require_fernet(password)
            return jsonify({"success": True})
        return jsonify({"error": "Invalid master password"}), 401


def _register_auth_logout_route(app):
    @app.route("/api/auth/logout", methods=["POST"])
    def logout():
        session.clear()
        return jsonify({"success": True})


def _register_secret_routes(app, store, require_auth):
    _register_get_secrets_route(app, store, require_auth)
    _register_get_secret_route(app, store, require_auth)
    _register_reveal_secret_route(app, store, require_auth)
    _register_create_secret_route(app, store, require_auth)
    _register_update_secret_route(app, store, require_auth)
    _register_delete_secret_route(app, store, require_auth)
    _register_search_secrets_route(app, store, require_auth)


def _register_get_secrets_route(app, store, require_auth):
    @app.route("/api/secrets", methods=["GET"])
    @require_auth
    def get_secrets():
        try:
            secrets = store.list_secrets()
            return jsonify({"secrets": [_serialize_secret_row(s) for s in secrets]})
        except Exception as e:
            logger.error(f"Error getting secrets: {e}")
            return jsonify({"error": str(e)}), 500


def _register_get_secret_route(app, store, require_auth):
    @app.route("/api/secrets/<secret_id>", methods=["GET"])
    @require_auth
    def get_secret(secret_id):
        try:
            secret = store.get_secret_by_id(secret_id)
            if secret:
                return jsonify(
                    {
                        "id": secret.get("id"),
                        "label": secret.get("label"),
                        "type": secret.get("type"),
                        "creation_time": secret.get("creation_time"),
                        "update_time": secret.get("update_time"),
                    }
                )
            return jsonify({"error": ERR_SECRET_NOT_FOUND}), 404
        except Exception as e:
            logger.error(f"Error getting secret {secret_id}: {e}")
            return jsonify({"error": str(e)}), 500


def _register_reveal_secret_route(app, store, require_auth):
    @app.route("/api/secrets/<secret_id>/reveal", methods=["GET"])
    @require_auth
    def reveal_secret(secret_id):
        try:
            secret = store.get_secret_by_id(secret_id)
            if secret:
                return jsonify(
                    {
                        "secret": secret.get("secret"),
                        "type": secret.get("type"),
                        "label": secret.get("label"),
                    }
                )
            return jsonify({"error": ERR_SECRET_NOT_FOUND}), 404
        except Exception as e:
            logger.error(f"Error revealing secret {secret_id}: {e}")
            return jsonify({"error": str(e)}), 500


def _register_create_secret_route(app, store, require_auth):
    @app.route("/api/secrets", methods=["POST"])
    @require_auth
    def create_secret():
        try:
            data = request.get_json()
            label = data.get("label", "").strip()
            secret = data.get("secret", "").strip()
            secret_type = data.get("type", "password")
            if not label or not secret:
                return jsonify({"error": "Label and secret are required"}), 400
            if secret_type not in ("password", "token", "ssh"):
                return jsonify({"error": "Invalid secret type"}), 400
            store.save_secret(label, secret, secret_type)
            return jsonify({"success": True, "message": "Secret created"}), 201
        except Exception as e:
            logger.error(f"Error creating secret: {e}")
            return jsonify({"error": str(e)}), 500


def _register_update_secret_route(app, store, require_auth):
    @app.route("/api/secrets/<secret_id>", methods=["PUT"])
    @require_auth
    def update_secret(secret_id):
        try:
            data = request.get_json()
            secret = data.get("secret", "").strip()
            if not secret:
                return jsonify({"error": "Secret value is required"}), 400
            store.update_secret(secret_id, secret)
            return jsonify({"success": True, "message": "Secret updated"})
        except Exception as e:
            logger.error(f"Error updating secret {secret_id}: {e}")
            return jsonify({"error": str(e)}), 500


def _register_delete_secret_route(app, store, require_auth):
    @app.route("/api/secrets/<secret_id>", methods=["DELETE"])
    @require_auth
    def delete_secret(secret_id):
        try:
            store.delete_secret(secret_id)
            return jsonify({"success": True, "message": "Secret deleted"})
        except Exception as e:
            logger.error(f"Error deleting secret {secret_id}: {e}")
            return jsonify({"error": str(e)}), 500


def _register_search_secrets_route(app, store, require_auth):
    @app.route("/api/secrets/search", methods=["GET"])
    @require_auth
    def search_secrets():
        try:
            query = request.args.get("q", "").lower()
            if not query:
                return jsonify({"secrets": []})
            secrets = store.list_secrets()
            filtered = [_serialize_secret_row(s) for s in secrets if query in s[1].lower()]
            return jsonify({"secrets": filtered})
        except Exception as e:
            logger.error(f"Error searching secrets: {e}")
            return jsonify({"error": str(e)}), 500


def _register_backup_routes(app, store, require_auth):
    @app.route("/api/backup/export", methods=["POST"])
    @require_auth
    def api_backup_export():
        try:
            data = request.get_json()
            backup_password = data.get("password", "")
            if len(backup_password) < 6:
                return jsonify({"error": "Backup password must be at least 6 characters"}), 400
            blob = store.export_encrypted_backup(backup_password)
            from flask import Response

            return Response(
                blob,
                mimetype="application/octet-stream",
                headers={"Content-Disposition": "attachment; filename=sinduk_backup.sinduk"},
            )
        except Exception as e:
            logger.error(f"Backup export failed: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/backup/import", methods=["POST"])
    @require_auth
    def api_backup_import():
        try:
            backup_password = request.form.get("password", "")
            overwrite = request.form.get("overwrite", "false").lower() == "true"
            if "file" not in request.files:
                return jsonify({"error": "No file uploaded"}), 400
            file_obj = request.files["file"]
            blob = file_obj.read()
            stats = store.import_encrypted_backup(blob, backup_password, merge=not overwrite)
            return jsonify({"success": True, **stats})
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.error(f"Backup import failed: {e}")
            return jsonify({"error": str(e)}), 500


def _register_ssh_rest_routes(app, store, ssh_manager, require_auth):
    _register_ssh_connect_route(app, store, ssh_manager, require_auth)
    _register_ssh_disconnect_route(app, ssh_manager, require_auth)
    _register_ssh_execute_route(app, ssh_manager, require_auth)
    _register_ssh_output_route(app, ssh_manager, require_auth)


def _register_ssh_connect_route(app, store, ssh_manager, require_auth):
    @app.route("/api/ssh/connect", methods=["POST"])
    @require_auth
    def ssh_connect():
        try:
            data = request.get_json()
            hostname, username, port, password, key_id, ssh_key = _extract_ssh_params(data)

            if key_id and not hostname:
                result = _resolve_stored_ssh(store, key_id)
                if isinstance(result, str) and result.startswith("error:"):
                    return jsonify({"error": result[6:]}), 400
                # Unpack host details from the stored secret.
                # `password` retains whatever the user typed in the modal —
                # this is the fix for Bug 1: password was silently dropped here.
                username, hostname, port = result

            if not hostname or not username:
                return jsonify({"error": "Hostname and username are required"}), 400

            key_filename = _resolve_key(store, ssh_key, key_id)

            connection_id = str(uuid.uuid4())
            success = ssh_manager.create_connection(connection_id, hostname, username, port, password, key_filename)
            if success:
                return (
                    jsonify(
                        {
                            "success": True,
                            "connection_id": connection_id,
                            "message": f"Connected to {username}@{hostname}",
                        }
                    ),
                    201,
                )
            return jsonify({"error": "SSH connection failed. Check credentials and host."}), 400
        except Exception as e:
            logger.error(f"SSH connect error: {e}")
            return jsonify({"error": str(e)}), 500


def _register_ssh_disconnect_route(app, ssh_manager, require_auth):
    @app.route("/api/ssh/disconnect/<connection_id>", methods=["POST"])
    @require_auth
    def ssh_disconnect(connection_id):
        try:
            ssh_manager.close_connection(connection_id)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500


def _register_ssh_execute_route(app, ssh_manager, require_auth):
    @app.route("/api/ssh/execute", methods=["POST"])
    @require_auth
    def ssh_execute():
        try:
            data = request.get_json()
            connection_id = data.get("connection_id")
            command = data.get("command", "")
            if not connection_id:
                return jsonify({"error": "connection_id required"}), 400

            terminal = ssh_manager.get_connection(connection_id)
            if not terminal:
                return jsonify({"error": "Connection not found or timed out"}), 404

            if terminal.send_command(command + "\n"):
                import time

                timeout = 2
                start = time.time()
                output = ""

                while time.time() - start < timeout:
                    chunk = terminal.get_output()
                    if chunk:
                        output += chunk
                        break
                    time.sleep(0.05)
                return jsonify({"success": True, "output": output})
            return jsonify({"error": "Failed to send command"}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 500


def _register_ssh_output_route(app, ssh_manager, require_auth):
    @app.route("/api/ssh/output/<connection_id>", methods=["GET"])
    @require_auth
    def ssh_get_output(connection_id):
        """Poll endpoint for SSH output - used by REST fallback mode."""
        try:
            terminal = ssh_manager.get_connection(connection_id)
            if not terminal:
                return jsonify({"output": "", "disconnected": True})
            output = terminal.get_output()
            return jsonify(
                {
                    "output": output,
                    "connected": terminal.connected,
                    "disconnected": not terminal.connected,
                }
            )
        except Exception as e:
            return jsonify({"output": "", "disconnected": True, "error": str(e)})


def _register_socket_handlers(socketio, store, ssh_manager):
    _register_socket_connect_handler(socketio)
    _register_socket_disconnect_handler(socketio)
    _register_socket_ssh_connect_handler(socketio, store, ssh_manager)
    _register_socket_ssh_command_handler(socketio, ssh_manager)
    _register_socket_ssh_disconnect_handler(socketio, ssh_manager)


def _register_socket_connect_handler(socketio):
    @socketio.on("connect")
    def handle_connect():
        emit("response", {"data": "Connected"})


def _register_socket_disconnect_handler(socketio):
    @socketio.on("disconnect")
    def handle_disconnect():
        logger.info("WebSocket client disconnected")


def _register_socket_ssh_connect_handler(socketio, store, ssh_manager):
    @socketio.on("ssh_connect")
    def handle_ssh_connect(data):
        if "authenticated" not in session:
            emit("error", {"message": "Unauthorized"})
            return
        if store.fernet is None:
            session.clear()
            emit("error", {"message": "Session expired. Please sign in again."})
            return
        try:
            hostname = data.get("hostname")
            username = data.get("username")
            port = data.get("port", 22)
            password = data.get("password")
            key_id = data.get("key_id")
            ssh_key = data.get("ssh_key")

            if key_id and not hostname:
                result = _resolve_stored_ssh(store, key_id)
                if isinstance(result, str) and result.startswith("error:"):
                    emit("error", {"message": result[6:]})
                    return
                # Preserve the password the user typed — fix for Bug 1 (WS path).
                username, hostname, port = result

            if not hostname or not username:
                emit("error", {"message": "Hostname and username required"})
                return

            key_filename = _resolve_key(store, ssh_key, None)
            connection_id = str(uuid.uuid4())

            if ssh_manager.create_connection(connection_id, hostname, username, port, password, key_filename):
                join_room(connection_id)
                emit(
                    "ssh_connected",
                    {
                        "connection_id": connection_id,
                        "message": f"Connected to {username}@{hostname}:{port}",
                    },
                )
                _start_output_streaming(socketio, ssh_manager, connection_id)
            else:
                emit("error", {"message": "SSH connection failed. Check credentials and host."})
        except Exception as e:
            logger.error(f"WS SSH connect error: {e}")
            emit("error", {"message": str(e)})


def _register_socket_ssh_command_handler(socketio, ssh_manager):
    @socketio.on("ssh_command")
    def handle_ssh_command(data):
        try:
            connection_id = data.get("connection_id")
            command = data.get("command", "")
            if not connection_id:
                emit("error", {"message": "connection_id required"})
                return

            terminal = ssh_manager.get_connection(connection_id)
            if not terminal:
                emit("error", {"message": "Connection not found or timed out"})
                return

            terminal.send_command(command + "\n")
        except Exception as e:
            emit("error", {"message": str(e)})


def _register_socket_ssh_disconnect_handler(socketio, ssh_manager):
    @socketio.on("ssh_disconnect")
    def handle_ssh_disconnect(data):
        try:
            connection_id = data.get("connection_id")
            if connection_id:
                ssh_manager.close_connection(connection_id)
                leave_room(connection_id)
                emit(
                    "ssh_disconnected",
                    {
                        "connection_id": connection_id,
                        "message": "Disconnected",
                    },
                )
        except Exception as e:
            emit("error", {"message": str(e)})


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _extract_ssh_params(data):
    """Extract SSH connection parameters from request data."""
    hostname = data.get("hostname")
    username = data.get("username")
    port = data.get("port", 22)
    password = data.get("password")
    key_id = data.get("key_id")
    ssh_key = data.get("ssh_key")
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 22
    return hostname, username, port, password, key_id, ssh_key


def _resolve_stored_ssh(store, key_id):
    """
    Parse a stored SSH secret into (username, hostname, port).
    Returns error string on failure.
    """
    secret = store.get_secret_by_id(key_id)
    if not secret:
        return "error:SSH server not found"

    ssh_data = secret.get("secret", "")
    parts = ssh_data.split("|")
    user_ip = parts[0]

    if ":" not in user_ip:
        return "error:Invalid SSH secret format — expected user:host"

    username, hostname = user_ip.split(":", 1)
    port = 22

    for part in parts[1:]:
        if part.startswith("port:"):
            try:
                port = int(part[5:])
            except ValueError:
                pass

    if not username or not hostname:
        return "error:SSH secret is missing username or hostname"

    return username, hostname, port


def _resolve_key(store, ssh_key_text, key_id):
    """Normalize and store SSH key safely."""
    import tempfile
    import os

    key_text = None

    if ssh_key_text:
        key_text = ssh_key_text.strip() + "\n"
        key_text = key_text.replace("\r\n", "\n")

    elif key_id:
        secret = store.get_secret_by_id(key_id)
        if secret:
            key_text = secret.get("secret", "").strip() + "\n"

    if key_text:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as f:
            f.write(key_text)
            path = f.name
        os.chmod(path, 0o600)
        return path

    return None


def _start_output_streaming(socketio, ssh_manager, connection_id):
    """
    Background thread that continuously reads SSH output and pushes it
    to the WebSocket room.
    """
    import threading
    import time

    def stream():
        while True:
            terminal = ssh_manager.get_connection(connection_id)
            if not terminal or not terminal.connected:
                socketio.emit(
                    "ssh_disconnected",
                    {"connection_id": connection_id, "message": "Connection closed"},
                    to=connection_id,
                )
                break
            output = terminal.get_output()
            if output:
                socketio.emit(
                    "ssh_output",
                    {"connection_id": connection_id, "output": output},
                    to=connection_id,
                )
            time.sleep(0.1)

    t = threading.Thread(target=stream, daemon=True)
    t.start()


# ------------------------------------------------------------------
# Vault / Team Routes (Phase 3)
# ------------------------------------------------------------------


def _register_vault_routes(app, store, vault_manager, require_auth):
    """Register all vault/team API endpoints."""
    _register_vault_crud_routes(app, store, vault_manager, require_auth)
    _register_vault_secrets_routes(app, store, vault_manager, require_auth)
    _register_vault_members_routes(app, store, vault_manager, require_auth)
    _register_vault_audit_routes(app, vault_manager, require_auth)


def _register_vault_crud_routes(app, store, vault_manager, require_auth):
    """Register vault CRUD endpoints."""

    @app.route("/api/vaults", methods=["GET"])
    @require_auth
    def list_vaults():
        try:
            vaults = vault_manager.list_vaults()
            return jsonify({"vaults": vaults})
        except Exception as e:
            logger.error(f"Error listing vaults: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/vaults", methods=["POST"])
    @require_auth
    def create_vault():
        try:
            data = request.get_json()
            name = data.get("name", "").strip().lower()
            description = data.get("description", "").strip()
            if not name:
                return jsonify({"error": "Vault name is required"}), 400
            meta = vault_manager.create_vault(name, description=description, master_fernet=store.fernet)
            return jsonify({"success": True, "vault": meta}), 201
        except (ValueError, RuntimeError) as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.error(f"Error creating vault: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/vaults/<vault_name>", methods=["GET"])
    @require_auth
    def get_vault(vault_name):
        try:
            meta = vault_manager.get_vault(vault_name)
            if not meta:
                return jsonify({"error": "Vault not found"}), 404
            members = vault_manager.list_members(vault_name)
            return jsonify({"vault": meta, "members": members})
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403

    @app.route("/api/vaults/<vault_name>", methods=["DELETE"])
    @require_auth
    def delete_vault(vault_name):
        try:
            vault_manager.delete_vault(vault_name)
            return jsonify({"success": True, "message": f"Vault '{vault_name}' deleted"})
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except ValueError as e:
            return jsonify({"error": str(e)}), 404
        except Exception as e:
            logger.error(f"Error deleting vault: {e}")
            return jsonify({"error": str(e)}), 500


def _register_vault_secrets_routes(app, store, vault_manager, require_auth):
    """Register vault secrets endpoints."""
    _register_list_vault_secrets_route(app, vault_manager, require_auth)
    _register_create_vault_secret_route(app, store, vault_manager, require_auth)
    _register_reveal_vault_secret_route(app, store, vault_manager, require_auth)
    _register_update_vault_secret_route(app, store, vault_manager, require_auth)
    _register_delete_vault_secret_route(app, vault_manager, require_auth)


def _register_list_vault_secrets_route(app, vault_manager, require_auth):
    @app.route("/api/vaults/<vault_name>/secrets", methods=["GET"])
    @require_auth
    def list_vault_secrets(vault_name):
        try:
            secrets = vault_manager.list_secrets(vault_name)
            return jsonify({"secrets": [_serialize_vault_secret_row(s) for s in secrets]})
        except (PermissionError, ValueError) as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            logger.error(f"Error listing vault secrets: {e}")
            return jsonify({"error": str(e)}), 500


def _register_create_vault_secret_route(app, store, vault_manager, require_auth):
    @app.route("/api/vaults/<vault_name>/secrets", methods=["POST"])
    @require_auth
    def create_vault_secret(vault_name):
        try:
            data = request.get_json()
            label = data.get("label", "").strip()
            secret = data.get("secret", "").strip()
            secret_type = data.get("type", "password")
            if not label or not secret:
                return jsonify({"error": "Label and secret are required"}), 400
            if secret_type not in ("password", "token", "ssh"):
                return jsonify({"error": "Invalid secret type"}), 400
            vault_manager.save_secret(vault_name, label, secret, secret_type, store.fernet)
            return jsonify({"success": True, "message": "Secret created in vault"}), 201
        except (PermissionError, ValueError) as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            logger.error(f"Error creating vault secret: {e}")
            return jsonify({"error": str(e)}), 500


def _register_reveal_vault_secret_route(app, store, vault_manager, require_auth):
    @app.route("/api/vaults/<vault_name>/secrets/<secret_id>/reveal", methods=["GET"])
    @require_auth
    def reveal_vault_secret(vault_name, secret_id):
        try:
            secret = vault_manager.get_secret_by_id(vault_name, secret_id, store.fernet)
            if secret:
                return jsonify(
                    {
                        "secret": secret.get("secret"),
                        "type": secret.get("type"),
                        "label": secret.get("label"),
                    }
                )
            return jsonify({"error": ERR_SECRET_NOT_FOUND}), 404
        except (PermissionError, ValueError) as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            logger.error(f"Error revealing vault secret: {e}")
            return jsonify({"error": str(e)}), 500


def _register_update_vault_secret_route(app, store, vault_manager, require_auth):
    @app.route("/api/vaults/<vault_name>/secrets/<secret_id>", methods=["PUT"])
    @require_auth
    def update_vault_secret(vault_name, secret_id):
        try:
            data = request.get_json()
            secret = data.get("secret", "").strip()
            if not secret:
                return jsonify({"error": "Secret value is required"}), 400
            vault_manager.update_secret(vault_name, secret_id, secret, store.fernet)
            return jsonify({"success": True, "message": "Secret updated"})
        except (PermissionError, ValueError) as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            logger.error(f"Error updating vault secret: {e}")
            return jsonify({"error": str(e)}), 500


def _register_delete_vault_secret_route(app, vault_manager, require_auth):
    @app.route("/api/vaults/<vault_name>/secrets/<secret_id>", methods=["DELETE"])
    @require_auth
    def delete_vault_secret(vault_name, secret_id):
        try:
            vault_manager.delete_secret(vault_name, secret_id)
            return jsonify({"success": True, "message": "Secret deleted"})
        except (PermissionError, ValueError) as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            logger.error(f"Error deleting vault secret: {e}")
            return jsonify({"error": str(e)}), 500


def _register_vault_members_routes(app, store, vault_manager, require_auth):
    """Register vault member management endpoints."""
    _register_list_vault_members_route(app, vault_manager, require_auth)
    _register_add_vault_member_route(app, store, vault_manager, require_auth)
    _register_remove_vault_member_route(app, store, vault_manager, require_auth)
    _register_set_vault_member_role_route(app, vault_manager, require_auth)
    _register_vault_crypto_routes(app, store, vault_manager, require_auth)


def _register_list_vault_members_route(app, vault_manager, require_auth):
    @app.route("/api/vaults/<vault_name>/members", methods=["GET"])
    @require_auth
    def list_vault_members(vault_name):
        try:
            members = vault_manager.list_members(vault_name)
            return jsonify({"members": members})
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except ValueError as e:
            return jsonify({"error": str(e)}), 404
        except Exception as e:
            return jsonify({"error": str(e)}), 500


def _register_add_vault_member_route(app, store, vault_manager, require_auth):
    @app.route("/api/vaults/<vault_name>/members", methods=["POST"])
    @require_auth
    def add_vault_member(vault_name):
        try:
            data = request.get_json()
            user_id = data.get("user_id", "").strip()
            user_name = data.get("user_name", "").strip()
            role = data.get("role", "viewer")
            public_key = data.get("public_key", "").strip() or None
            if not user_id or not user_name:
                return jsonify({"error": "user_id and user_name are required"}), 400
            vault_manager.add_member(vault_name, user_id, user_name, role, store.fernet, target_public_key=public_key)
            return jsonify({"success": True, "message": f"Added {user_name} as {role}"}), 201
        except (PermissionError, ValueError) as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            logger.error(f"Error adding vault member: {e}")
            return jsonify({"error": str(e)}), 500


def _register_remove_vault_member_route(app, store, vault_manager, require_auth):
    @app.route("/api/vaults/<vault_name>/members/<user_id>", methods=["DELETE"])
    @require_auth
    def remove_vault_member(vault_name, user_id):
        try:
            data = request.get_json(silent=True) or {}
            rotate_key = data.get("rotate_key", True)
            vault_manager.remove_member(vault_name, user_id, master_fernet=store.fernet, rotate_key=rotate_key)
            return jsonify({"success": True, "message": "Member removed"})
        except (PermissionError, ValueError) as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 500


def _register_set_vault_member_role_route(app, vault_manager, require_auth):
    @app.route("/api/vaults/<vault_name>/members/<user_id>/role", methods=["PUT"])
    @require_auth
    def set_vault_member_role(vault_name, user_id):
        try:
            data = request.get_json()
            role = data.get("role", "")
            if not role:
                return jsonify({"error": "Role is required"}), 400
            vault_manager.set_member_role(vault_name, user_id, role)
            return jsonify({"success": True, "message": f"Role updated to {role}"})
        except (PermissionError, ValueError) as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 500


def _register_vault_crypto_routes(app, store, vault_manager, require_auth):
    @app.route("/api/vaults/<vault_name>/rotate-key", methods=["POST"])
    @require_auth
    def rotate_vault_key_route(vault_name):
        try:
            res = vault_manager.rotate_vault_key(vault_name, store.fernet)
            return jsonify({"success": True, "details": res})
        except (PermissionError, ValueError) as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            logger.error(f"Error rotating vault key: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/vaults/<vault_name>/invite", methods=["POST"])
    @require_auth
    def create_vault_invite_route(vault_name):
        try:
            data = request.get_json() or {}
            role = data.get("role", "viewer")
            expires_hours = data.get("expires_hours", 24)
            token = vault_manager.create_vault_invite(vault_name, role, store.fernet, expires_in_hours=expires_hours)
            return jsonify({"success": True, "token": token, "role": role, "expires_hours": expires_hours})
        except (PermissionError, ValueError) as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            logger.error(f"Error creating vault invite: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/vaults/accept-invite", methods=["POST"])
    @require_auth
    def accept_vault_invite_route():
        try:
            data = request.get_json() or {}
            token = data.get("token", "").strip()
            if not token:
                return jsonify({"error": "Invite token is required"}), 400
            res = vault_manager.accept_vault_invite(token, store.fernet)
            return jsonify({"success": True, "vault": res})
        except (PermissionError, ValueError) as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.error(f"Error accepting vault invite: {e}")
            return jsonify({"error": str(e)}), 500


def _register_vault_audit_routes(app, vault_manager, require_auth):
    """Register vault audit and identity endpoints."""

    @app.route("/api/vaults/<vault_name>/audit", methods=["GET"])
    @require_auth
    def vault_audit_log(vault_name):
        try:
            limit = request.args.get("limit", 50, type=int)
            entries = vault_manager.get_audit_log(vault_name, limit=limit)
            # Enrich with formatted timestamps
            for e in entries:
                if e.get("timestamp"):
                    e["timestamp_formatted"] = datetime.fromtimestamp(e["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            return jsonify({"entries": entries})
        except (PermissionError, ValueError) as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            logger.error(f"Error getting audit log: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/vaults/<vault_name>/identity", methods=["GET"])
    @require_auth
    def vault_identity(vault_name):
        """Return the current user's identity and role in this vault."""
        identity = get_user_identity()
        if not identity:
            return jsonify({"error": "No team identity set"}), 400
        members = vault_manager.list_members(vault_name)
        my_role = None
        for m in members:
            if m["user_id"] == identity["user_id"]:
                my_role = m["role"]
                break
        return jsonify(
            {
                "user_id": identity["user_id"],
                "user_name": identity["user_name"],
                "role": my_role,
            }
        )
