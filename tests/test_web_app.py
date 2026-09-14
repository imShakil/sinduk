import io
from flask import Flask


def _make_store(configured=True, valid_password="secret123"):
    class Store:
        def __init__(self):
            self.fernet = object()
            self._configured = configured
            self._valid_password = valid_password
            self.saved = []
            self.updated = []
            self.deleted = []

        def is_master_set(self):
            return self._configured

        def _derive_fernet(self, password, salt):
            return "derived"

        def verify_master_password(self, password):
            return password == self._valid_password

        def require_fernet(self, password=None):
            self.fernet = object()

        def list_secrets(self):
            return [("id1", "github", "token", 1710000000, 1710000001)]

        def get_secret_by_id(self, secret_id):
            if secret_id == "missing":
                return None
            return {
                "id": secret_id,
                "label": "github",
                "secret": "abc",
                "type": "token",
                "creation_time": 1,
                "update_time": 2,
            }

        def save_secret(self, label, secret, secret_type):
            self.saved.append((label, secret, secret_type))

        def update_secret(self, secret_id, secret):
            self.updated.append((secret_id, secret))

        def delete_secret(self, secret_id):
            self.deleted.append(secret_id)

        def export_encrypted_backup(self, backup_password):
            return b"blob"

        def import_encrypted_backup(self, blob, backup_password, merge=True):
            if backup_password == "bad":
                raise ValueError("wrong")
            return {"imported": 1, "skipped": 0, "errors": 0}

    return Store()


def _build_app_with_basic_routes(store):
    import sinduk.web.app as web_app

    app = Flask(__name__)
    app.secret_key = "test"

    require_auth = web_app._build_require_auth(store)
    web_app._register_csrf_same_origin_protection(app)
    web_app._register_setup_status_route(app, store)
    web_app._register_auth_check_route(app, store)
    web_app._register_auth_login_route(app, store)
    web_app._register_auth_logout_route(app)
    web_app._register_get_secrets_route(app, store, require_auth)
    web_app._register_get_secret_route(app, store, require_auth)
    web_app._register_reveal_secret_route(app, store, require_auth)
    web_app._register_create_secret_route(app, store, require_auth)
    web_app._register_update_secret_route(app, store, require_auth)
    web_app._register_delete_secret_route(app, store, require_auth)
    web_app._register_search_secrets_route(app, store, require_auth)
    web_app._register_backup_routes(app, store, require_auth)

    return app


def test_is_same_origin():
    import sinduk.web.app as web_app

    assert web_app._is_same_origin("http://localhost:5000/x", "http://localhost:5000/") is True
    assert web_app._is_same_origin("https://localhost:5000/x", "http://localhost:5000/") is False
    assert web_app._is_same_origin("", "http://localhost:5000/") is False


def test_extract_and_resolve_ssh_helpers(tmp_path):
    import sinduk.web.app as web_app

    data = {"hostname": "h", "username": "u", "port": "2200", "password": "p", "key_id": "k", "ssh_key": "pem"}
    hostname, username, port, password, key_id, ssh_key = web_app._extract_ssh_params(data)
    assert (hostname, username, port, password, key_id, ssh_key) == ("h", "u", 2200, "p", "k", "pem")

    class Store:
        def get_secret_by_id(self, key_id):
            if key_id == "bad":
                return None
            if key_id == "invalid":
                return {"secret": "no-colon"}
            if key_id == "key":
                return {"secret": "-----BEGIN KEY-----"}
            return {"secret": "ubuntu:10.0.0.1|port:2222"}

    store = Store()
    assert web_app._resolve_stored_ssh(store, "bad").startswith("error:")
    assert web_app._resolve_stored_ssh(store, "invalid").startswith("error:")
    assert web_app._resolve_stored_ssh(store, "ok") == ("ubuntu", "10.0.0.1", 2222)

    key_path = web_app._resolve_key(store, "PRIVATE KEY", None)
    assert key_path is not None

    key_path_from_id = web_app._resolve_key(store, None, "key")
    assert key_path_from_id is not None


def test_serialize_secret_row():
    import sinduk.web.app as web_app

    row = ("id1", "label", "token", 1710000000, 1710000010)
    out = web_app._serialize_secret_row(row)
    assert out["id"] == "id1"
    assert out["label"] == "label"
    assert "creation_date" in out


def test_csrf_same_origin_blocks_cross_site():
    app = Flask(__name__)
    app.secret_key = "test"

    import sinduk.web.app as web_app

    web_app._register_csrf_same_origin_protection(app)

    @app.route("/submit", methods=["POST"])
    def submit():
        return "ok"

    client = app.test_client()

    blocked = client.post("/submit", headers={"Origin": "http://evil.local"}, base_url="http://localhost")
    assert blocked.status_code == 403

    allowed = client.post("/submit", headers={"Origin": "http://localhost"}, base_url="http://localhost")
    assert allowed.status_code == 200


def test_auth_and_secret_routes_happy_path_and_errors():
    store = _make_store(configured=True, valid_password="secret123")
    app = _build_app_with_basic_routes(store)
    client = app.test_client()
    same_origin = {"Origin": "http://localhost"}

    r = client.get("/api/setup/status")
    assert r.status_code == 200
    assert r.get_json()["configured"] is True

    r = client.post("/api/auth/login", json={}, headers=same_origin, base_url="http://localhost")
    assert r.status_code == 400

    r = client.post("/api/auth/login", json={"password": "wrong"}, headers=same_origin, base_url="http://localhost")
    assert r.status_code == 401

    r = client.post(
        "/api/auth/login",
        json={"password": "secret123"},
        headers=same_origin,
        base_url="http://localhost",
    )
    assert r.status_code == 200

    r = client.get("/api/secrets")
    assert r.status_code == 200
    assert len(r.get_json()["secrets"]) == 1

    r = client.get("/api/secrets/id1")
    assert r.status_code == 200

    r = client.get("/api/secrets/missing")
    assert r.status_code == 404

    r = client.get("/api/secrets/id1/reveal")
    assert r.status_code == 200

    r = client.post(
        "/api/secrets",
        json={"label": "", "secret": "x", "type": "token"},
        headers=same_origin,
        base_url="http://localhost",
    )
    assert r.status_code == 400

    r = client.post(
        "/api/secrets",
        json={"label": "api", "secret": "token", "type": "token"},
        headers=same_origin,
        base_url="http://localhost",
    )
    assert r.status_code == 201
    assert store.saved == [("api", "token", "token")]

    r = client.put(
        "/api/secrets/id1",
        json={"secret": ""},
        headers=same_origin,
        base_url="http://localhost",
    )
    assert r.status_code == 400

    r = client.put(
        "/api/secrets/id1",
        json={"secret": "new"},
        headers=same_origin,
        base_url="http://localhost",
    )
    assert r.status_code == 200
    assert store.updated == [("id1", "new")]

    r = client.delete("/api/secrets/id1", headers=same_origin, base_url="http://localhost")
    assert r.status_code == 200
    assert store.deleted == ["id1"]

    r = client.get("/api/secrets/search?q=git")
    assert r.status_code == 200
    assert len(r.get_json()["secrets"]) == 1

    r = client.post(
        "/api/backup/export",
        json={"password": "123"},
        headers=same_origin,
        base_url="http://localhost",
    )
    assert r.status_code == 400

    r = client.post(
        "/api/backup/export",
        json={"password": "123456"},
        headers=same_origin,
        base_url="http://localhost",
    )
    assert r.status_code == 200

    data = {"password": "ok", "overwrite": "false"}
    upload = {"file": (io.BytesIO(b"blob"), "x.sinduk")}
    r = client.post(
        "/api/backup/import",
        data={**data, **upload},
        content_type="multipart/form-data",
        headers=same_origin,
        base_url="http://localhost",
    )
    assert r.status_code == 200


def test_unauthorized_and_session_expired_branches():
    store = _make_store(configured=True, valid_password="secret123")
    app = _build_app_with_basic_routes(store)
    client = app.test_client()

    r = client.get("/api/secrets")
    assert r.status_code == 401

    with client.session_transaction() as sess:
        sess["authenticated"] = True
    store.fernet = None

    r = client.get("/api/secrets")
    assert r.status_code == 401
    assert "Session expired" in r.get_json()["error"]


def test_start_output_streaming_emits_disconnect(monkeypatch):
    import sinduk.web.app as web_app

    emitted = []

    class Socket:
        def emit(self, event, payload, to=None):
            emitted.append((event, payload, to))

    class Manager:
        def get_connection(self, connection_id):
            return None

    class ImmediateThread:
        def __init__(self, target, daemon):
            self.target = target

        def start(self):
            self.target()

    monkeypatch.setattr("threading.Thread", ImmediateThread)

    web_app._start_output_streaming(Socket(), Manager(), "cid-1")
    assert emitted
    assert emitted[0][0] == "ssh_disconnected"
