"""Unit tests for SyncServerDB user authentication and device code pairing."""

import os
import pytest
from sinduk.server import SyncServerDB, create_sync_server_app, _hash_user_password, _verify_user_password


@pytest.fixture
def server_db(tmp_path):
    db_file = os.path.join(str(tmp_path), "server_test.db")
    return SyncServerDB(db_file)


class TestServerUserAuth:
    def test_password_hash_and_verify(self):
        pwd = "superSecureMasterPassword123!"
        h, s = _hash_user_password(pwd)
        assert len(h) == 64
        assert len(s) == 32
        assert _verify_user_password(pwd, h, s) is True
        assert _verify_user_password("wrongPassword", h, s) is False

    def test_user_registration_and_login(self, server_db):
        user, token = server_db.register_user(
            email="alice@company.com",
            password="alicePassword123",
            display_name="Alice Admin",
            role="admin",
            public_key="pubkey_alice_abc",
        )
        assert user["email"] == "alice@company.com"
        assert user["display_name"] == "Alice Admin"
        assert user["role"] == "admin"
        assert token.startswith("sinduk_tok_")

        # Duplicate email should raise ValueError
        with pytest.raises(ValueError, match="already exists"):
            server_db.register_user("alice@company.com", "pass", "Alice 2")

        # Login with correct password
        auth_user, auth_token = server_db.authenticate_user("alice@company.com", "alicePassword123")
        assert auth_user is not None
        assert auth_user["email"] == "alice@company.com"
        assert auth_token is not None
        assert auth_token.startswith("sinduk_tok_")

        # Login with incorrect password
        bad_user, bad_token = server_db.authenticate_user("alice@company.com", "wrongPassword")
        assert bad_user is None
        assert bad_token is None

        # Login with non-existent user
        non_user, non_token = server_db.authenticate_user("ghost@company.com", "password")
        assert non_user is None
        assert non_token is None

    def test_device_code_lifecycle(self, server_db):
        code, session_id = server_db.create_device_code(expires_in=600)
        assert len(code) == 9  # e.g. ABCD-1234
        assert session_id.startswith("sinduk_sess_")

        # Initial poll is pending
        poll_init = server_db.poll_device_code(session_id)
        assert poll_init["status"] == "pending"

        # Authorize device code
        _, raw_tok = server_db.create_token(name="Alice CLI", role="member")
        ok = server_db.authorize_device_code(code, "alice_uid", raw_tok)
        assert ok is True

        # Polling now returns authorized and token
        poll_done = server_db.poll_device_code(session_id)
        assert poll_done["status"] == "authorized"
        assert poll_done["token"] == raw_tok
        assert poll_done["user_id"] == "alice_uid"


class TestServerAuthEndpoints:
    def test_register_and_login_api(self, tmp_path):
        db_file = os.path.join(str(tmp_path), "api_test.db")
        db = SyncServerDB(db_file)
        app = create_sync_server_app(db)
        client = app.test_client()

        # 1. Register endpoint
        res_reg = client.post(
            "/api/v1/auth/register",
            json={
                "email": "bob@company.com",
                "password": "bobPassword123",
                "display_name": "Bob Dev",
            },
        )
        assert res_reg.status_code == 201
        data_reg = res_reg.get_json()
        assert data_reg["success"] is True
        token = data_reg["token"]
        assert token.startswith("sinduk_tok_")

        # 2. Login endpoint
        res_login = client.post(
            "/api/v1/auth/login",
            json={
                "email": "bob@company.com",
                "password": "bobPassword123",
            },
        )
        assert res_login.status_code == 200
        data_login = res_login.get_json()
        assert data_login["success"] is True
        assert data_login["user"]["email"] == "bob@company.com"

        # 3. Invalid login -> 401
        res_bad = client.post(
            "/api/v1/auth/login",
            json={
                "email": "bob@company.com",
                "password": "wrong",
            },
        )
        assert res_bad.status_code == 401

    def test_device_pairing_api(self, tmp_path):
        db_file = os.path.join(str(tmp_path), "api_device.db")
        db = SyncServerDB(db_file)
        _, admin_token = db.create_token(name="Admin", role="admin")
        app = create_sync_server_app(db)
        client = app.test_client()

        # 1. Request device code
        res_code = client.post("/api/v1/auth/device/code")
        assert res_code.status_code == 200
        code_data = res_code.get_json()
        device_code = code_data["device_code"]
        session_id = code_data["session_id"]

        # 2. Poll before auth -> pending
        res_poll1 = client.get(f"/api/v1/auth/device/poll?session_id={session_id}")
        assert res_poll1.status_code == 200
        assert res_poll1.get_json()["status"] == "pending"

        # 3. Authorize with bearer token
        res_auth = client.post(
            "/api/v1/auth/device/authorize",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"device_code": device_code},
        )
        assert res_auth.status_code == 200
        assert res_auth.get_json()["success"] is True

        # 4. Poll after auth -> authorized with new token
        res_poll2 = client.get(f"/api/v1/auth/device/poll?session_id={session_id}")
        assert res_poll2.status_code == 200
        poll2_data = res_poll2.get_json()
        assert poll2_data["status"] == "authorized"
        assert poll2_data["token"].startswith("sinduk_tok_")
