"""
Tests for Web UI vault and team API endpoints (Phase 3).
"""

import os
import pytest
from flask import Flask
from cryptography.fernet import Fernet

import sinduk.web.app as web_app
from sinduk.vault import VaultManager, set_user_identity
from sinduk.store import SecretStore


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

    yield test_config


@pytest.fixture
def master_fernet():
    return Fernet(Fernet.generate_key())


@pytest.fixture
def user_identity(isolated_pacli_dir):
    return set_user_identity("WebUser")


@pytest.fixture
def app_client(isolated_pacli_dir, master_fernet, user_identity):
    store = SecretStore()
    store.fernet = master_fernet
    vault_manager = VaultManager()

    app = Flask(__name__)
    app.secret_key = "test-secret"
    require_auth = web_app._build_require_auth(store)
    web_app._register_csrf_same_origin_protection(app)
    web_app._register_vault_routes(app, store, vault_manager, require_auth)

    client = app.test_client()

    with client.session_transaction() as sess:
        sess["authenticated"] = True

    return client, vault_manager, store


class TestVaultWebApi:
    HEADERS = {"Origin": "http://localhost"}
    BASE_URL = "http://localhost"

    def test_list_vaults_empty(self, app_client):
        client, _, _ = app_client
        res = client.get("/api/vaults", base_url=self.BASE_URL)
        assert res.status_code == 200
        data = res.get_json()
        assert "vaults" in data
        assert len(data["vaults"]) == 0

    def test_create_and_list_vault(self, app_client, master_fernet):
        client, vm, store = app_client

        # Create vault
        res = client.post(
            "/api/vaults",
            json={"name": "frontend-team", "description": "UI secrets"},
            headers=self.HEADERS,
            base_url=self.BASE_URL,
        )
        assert res.status_code == 201
        data = res.get_json()
        assert data["success"] is True
        assert data["vault"]["name"] == "frontend-team"

        # List vaults
        res_list = client.get("/api/vaults", base_url=self.BASE_URL)
        assert res_list.status_code == 200
        vaults = res_list.get_json()["vaults"]
        assert len(vaults) == 1
        assert vaults[0]["name"] == "frontend-team"

    def test_get_vault_details(self, app_client, master_fernet):
        client, vm, store = app_client
        vm.create_vault("backend-team", description="API keys", master_fernet=master_fernet)

        res = client.get("/api/vaults/backend-team", base_url=self.BASE_URL)
        assert res.status_code == 200
        data = res.get_json()
        assert data["vault"]["name"] == "backend-team"
        assert len(data["members"]) == 1

    def test_vault_secrets_crud(self, app_client, master_fernet):
        client, vm, store = app_client
        vm.create_vault("sec-team", master_fernet=master_fernet)

        # 1. Create secret in vault
        res_create = client.post(
            "/api/vaults/sec-team/secrets",
            json={"label": "db-prod", "secret": "user:pass999", "type": "password"},
            headers=self.HEADERS,
            base_url=self.BASE_URL,
        )
        assert res_create.status_code == 201

        # 2. List secrets
        res_list = client.get("/api/vaults/sec-team/secrets", base_url=self.BASE_URL)
        assert res_list.status_code == 200
        secrets = res_list.get_json()["secrets"]
        assert len(secrets) == 1
        sec_id = secrets[0]["id"]
        assert secrets[0]["label"] == "db-prod"

        # 3. Reveal secret
        res_reveal = client.get(f"/api/vaults/sec-team/secrets/{sec_id}/reveal", base_url=self.BASE_URL)
        assert res_reveal.status_code == 200
        assert res_reveal.get_json()["secret"] == "user:pass999"

        # 4. Update secret
        res_update = client.put(
            f"/api/vaults/sec-team/secrets/{sec_id}",
            json={"secret": "user:newpass"},
            headers=self.HEADERS,
            base_url=self.BASE_URL,
        )
        assert res_update.status_code == 200

        # Verify update
        res_reveal2 = client.get(f"/api/vaults/sec-team/secrets/{sec_id}/reveal", base_url=self.BASE_URL)
        assert res_reveal2.get_json()["secret"] == "user:newpass"

        # 5. Delete secret
        res_del = client.delete(f"/api/vaults/sec-team/secrets/{sec_id}", headers=self.HEADERS, base_url=self.BASE_URL)
        assert res_del.status_code == 200

        # Verify deleted
        res_list2 = client.get("/api/vaults/sec-team/secrets", base_url=self.BASE_URL)
        assert len(res_list2.get_json()["secrets"]) == 0

    def test_vault_members_and_audit(self, app_client, master_fernet):
        client, vm, store = app_client
        vm.create_vault("mem-team", master_fernet=master_fernet)

        # 1. Add member
        res_add = client.post(
            "/api/vaults/mem-team/members",
            json={"user_id": "usr_bob123", "user_name": "Bob", "role": "editor"},
            headers=self.HEADERS,
            base_url=self.BASE_URL,
        )
        assert res_add.status_code == 201

        # 2. List members
        res_mems = client.get("/api/vaults/mem-team/members", base_url=self.BASE_URL)
        assert res_mems.status_code == 200
        mems = res_mems.get_json()["members"]
        assert len(mems) == 2

        # 3. Update member role
        res_role = client.put(
            "/api/vaults/mem-team/members/usr_bob123/role",
            json={"role": "admin"},
            headers=self.HEADERS,
            base_url=self.BASE_URL,
        )
        assert res_role.status_code == 200

        # 4. Audit log
        res_audit = client.get("/api/vaults/mem-team/audit", base_url=self.BASE_URL)
        assert res_audit.status_code == 200
        entries = res_audit.get_json()["entries"]
        assert len(entries) >= 2
        actions = {e["action"] for e in entries}
        assert "create_vault" in actions
        assert "add_member" in actions

        # 5. Remove member
        res_rem = client.delete("/api/vaults/mem-team/members/usr_bob123", headers=self.HEADERS, base_url=self.BASE_URL)
        assert res_rem.status_code == 200

        # 6. Delete vault
        res_del_vault = client.delete("/api/vaults/mem-team", headers=self.HEADERS, base_url=self.BASE_URL)
        assert res_del_vault.status_code == 200

    def test_vault_identity_endpoint(self, app_client, master_fernet):
        client, vm, store = app_client
        vm.create_vault("id-team", master_fernet=master_fernet)

        res = client.get("/api/vaults/id-team/identity", base_url=self.BASE_URL)
        assert res.status_code == 200
        data = res.get_json()
        assert data["user_name"] == "WebUser"
        assert data["role"] == "admin"
