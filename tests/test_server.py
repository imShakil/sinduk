"""
Tests for self-hosted pacli sync server (Option B) and server CLI commands.
"""

import os
import pytest
from click.testing import CliRunner
from cryptography.fernet import Fernet

from sinduk.cli import cli
from sinduk.server import SyncServerDB, create_sync_server_app
from sinduk.vault import set_user_identity


@pytest.fixture(autouse=True)
def isolated_pacli_dir(tmp_path, monkeypatch):
    test_config = str(tmp_path / "sinduk_config")
    os.makedirs(test_config, exist_ok=True)

    monkeypatch.setattr("sinduk.vault.PACLI_DIR", test_config)
    monkeypatch.setattr("sinduk.vault.VAULTS_DIR", os.path.join(test_config, "vaults"))
    monkeypatch.setattr("sinduk.vault.REGISTRY_PATH", os.path.join(test_config, "vaults", "vault_registry.json"))
    monkeypatch.setattr("sinduk.vault.USER_IDENTITY_PATH", os.path.join(test_config, "user_identity.json"))

    store_salt_path = os.path.join(test_config, "salt.bin")
    store_hash_path = os.path.join(test_config, "password_hash.bin")
    monkeypatch.setattr("sinduk.store.SALT_PATH", store_salt_path)
    monkeypatch.setattr("sinduk.store.PASSWORD_HASH_PATH", store_hash_path)

    server_dir = os.path.join(test_config, "server")
    monkeypatch.setattr("sinduk.server.SERVER_DIR", server_dir)
    monkeypatch.setattr("sinduk.server.SERVER_DB_PATH", os.path.join(server_dir, "server.db"))
    monkeypatch.setattr("sinduk.commands.server.SERVER_DIR", server_dir)
    monkeypatch.setattr("sinduk.commands.server.SERVER_PID_PATH", os.path.join(server_dir, "server.pid"))
    monkeypatch.setattr("sinduk.commands.server.SERVER_STATE_PATH", os.path.join(server_dir, "server_state.json"))
    monkeypatch.setattr("sinduk.commands.server.SERVER_LOG_PATH", os.path.join(server_dir, "server.log"))

    sync_cfg_path = os.path.join(test_config, "sync_config.json")
    monkeypatch.setattr("sinduk.sync_client.SYNC_CONFIG_PATH", sync_cfg_path)

    yield test_config


@pytest.fixture
def master_fernet():
    return Fernet(Fernet.generate_key())


@pytest.fixture
def user_identity(isolated_pacli_dir):
    return set_user_identity("ServerTester")


@pytest.fixture
def runner():
    return CliRunner()


class TestSyncServerDB:
    def test_token_lifecycle(self, isolated_pacli_dir):
        db = SyncServerDB(os.path.join(isolated_pacli_dir, "server", "server.db"))

        token_id, raw_token = db.create_token("Alice", role="admin")
        assert raw_token.startswith("sinduk_tok_")
        assert len(token_id) == 8

        # Verify token
        info = db.verify_token(raw_token)
        assert info is not None
        assert info["name"] == "Alice"
        assert info["role"] == "admin"
        assert info["active"] is True

        # Invalid token
        assert db.verify_token("invalid_token_123") is None
        assert db.verify_token("") is None

        # List tokens
        tokens = db.list_tokens()
        assert len(tokens) == 1
        assert tokens[0]["id"] == token_id

        # Revoke token
        assert db.revoke_token(token_id) is True
        assert db.verify_token(raw_token) is None

    def test_blob_storage_and_versioning(self, isolated_pacli_dir):
        db = SyncServerDB(os.path.join(isolated_pacli_dir, "server", "server.db"))

        blob1 = b"encrypted_vault_data_v1"
        res1 = db.save_blob("team-alpha", blob1, updated_by="Alice")
        assert res1["version"] == 1
        assert res1["updated"] is True

        # Fetch blob
        data, meta = db.get_blob("team-alpha")
        assert data == blob1
        assert meta["version"] == 1
        assert meta["updated_by"] == "Alice"

        # Check status
        status = db.get_status("team-alpha")
        assert status["version"] == 1
        assert status["size"] == len(blob1)

        # Save same blob (no change)
        res_same = db.save_blob("team-alpha", blob1, updated_by="Alice")
        assert res_same["version"] == 1
        assert res_same["updated"] is False

        # Save new blob (bump version)
        blob2 = b"encrypted_vault_data_v2"
        res2 = db.save_blob("team-alpha", blob2, updated_by="Bob")
        assert res2["version"] == 2
        assert res2["updated"] is True

        data2, meta2 = db.get_blob("team-alpha")
        assert data2 == blob2
        assert meta2["version"] == 2
        assert meta2["updated_by"] == "Bob"


class TestSyncServerAppEndpoints:
    def test_health_and_auth(self, isolated_pacli_dir):
        db = SyncServerDB(os.path.join(isolated_pacli_dir, "server", "server.db"))
        app = create_sync_server_app(db)
        client = app.test_client()

        # Health
        res = client.get("/health")
        assert res.status_code == 200
        assert res.get_json()["status"] == "ok"

        # Push without auth -> 401
        res_unauth = client.post("/api/v1/sync/push/vault1", data=b"blob")
        assert res_unauth.status_code == 401

    def test_push_pull_flow(self, isolated_pacli_dir):
        db = SyncServerDB(os.path.join(isolated_pacli_dir, "server", "server.db"))
        _, token = db.create_token("TeamDev")
        app = create_sync_server_app(db)
        client = app.test_client()

        auth_headers = {"Authorization": f"Bearer {token}"}

        # 1. Status 404 before push
        res_stat404 = client.get("/api/v1/sync/status/dev-vault", headers=auth_headers)
        assert res_stat404.status_code == 404

        # 2. Push blob
        test_blob = b"sample_encrypted_payload"
        res_push = client.post("/api/v1/sync/push/dev-vault", data=test_blob, headers=auth_headers)
        assert res_push.status_code == 200
        data = res_push.get_json()
        assert data["success"] is True
        assert data["version"] == 1
        checksum = data["checksum"]

        # 3. Status check
        res_stat = client.get("/api/v1/sync/status/dev-vault", headers=auth_headers)
        assert res_stat.status_code == 200
        assert res_stat.get_json()["version"] == 1

        # 4. Pull blob
        res_pull = client.get("/api/v1/sync/pull/dev-vault", headers=auth_headers)
        assert res_pull.status_code == 200
        assert res_pull.data == test_blob
        assert res_pull.headers.get("X-Vault-Version") == "1"

        # 5. Conditional pull with ETag / If-None-Match (304)
        res_pull_304 = client.get(
            "/api/v1/sync/pull/dev-vault",
            headers={"Authorization": f"Bearer {token}", "If-None-Match": checksum},
        )
        assert res_pull_304.status_code == 304


class TestServerCliAndSyncClient:
    def test_token_cli_commands(self, runner, isolated_pacli_dir):
        # Create token
        res_create = runner.invoke(cli, ["server", "token", "create", "--name", "QA", "--role", "admin"])
        assert res_create.exit_code == 0
        assert "New Sync Server Token Generated" in res_create.output
        assert "Token ID:" in res_create.output

        # List tokens
        res_list = runner.invoke(cli, ["server", "token", "list"])
        assert res_list.exit_code == 0
        assert "QA" in res_list.output

    def test_sync_config_cli(self, runner, isolated_pacli_dir):
        # Config set
        res_set = runner.invoke(
            cli, ["sync", "config", "set", "--server", "http://127.0.0.1:58380", "--token", "tok123"]
        )
        assert res_set.exit_code == 0
        assert "Sync configuration updated" in res_set.output

        # Config show
        res_show = runner.invoke(cli, ["sync", "config", "show"])
        assert res_show.exit_code == 0
        assert "http://127.0.0.1:58380" in res_show.output

    def test_server_status_stopped(self, runner, isolated_pacli_dir):
        res = runner.invoke(cli, ["server", "status"])
        assert res.exit_code == 0
        assert "Stopped" in res.output
