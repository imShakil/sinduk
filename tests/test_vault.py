"""
Tests for vault management — VaultManager, key wrapping, RBAC, and audit logging.
"""

import os
import json
import pytest
from cryptography.fernet import Fernet

from sinduk.vault import (
    VaultManager,
    VaultRole,
    ROLE_PERMISSIONS,
    get_user_identity,
    set_user_identity,
)


@pytest.fixture(autouse=True)
def isolated_pacli_dir(tmp_path, monkeypatch):
    """Redirect all pacli config to a temp directory for test isolation."""
    test_config = str(tmp_path / "sinduk_config")
    os.makedirs(test_config, exist_ok=True)

    monkeypatch.setattr("sinduk.vault.PACLI_DIR", test_config)
    monkeypatch.setattr("sinduk.vault.VAULTS_DIR", os.path.join(test_config, "vaults"))
    monkeypatch.setattr("sinduk.vault.REGISTRY_PATH", os.path.join(test_config, "vaults", "vault_registry.json"))
    monkeypatch.setattr("sinduk.vault.USER_IDENTITY_PATH", os.path.join(test_config, "user_identity.json"))

    return test_config


@pytest.fixture
def master_fernet():
    """A Fernet instance simulating the user's personal master key."""
    return Fernet(Fernet.generate_key())


@pytest.fixture
def user_identity(isolated_pacli_dir, monkeypatch):
    """Set up a test user identity."""
    identity_path = os.path.join(isolated_pacli_dir, "user_identity.json")
    identity = {
        "user_id": "testuser001",
        "user_name": "Test User",
        "created_at": 1700000000,
        "updated_at": 1700000000,
    }
    os.makedirs(os.path.dirname(identity_path), exist_ok=True)
    with open(identity_path, "w") as f:
        json.dump(identity, f)
    return identity


@pytest.fixture
def vault_manager(user_identity):
    """A VaultManager instance with a test user identity."""
    return VaultManager()


@pytest.fixture
def test_vault(vault_manager, master_fernet):
    """Create a test vault and return its metadata."""
    return vault_manager.create_vault("test-vault", description="A test vault", master_fernet=master_fernet)


class TestUserIdentity:
    def test_set_user_identity(self, isolated_pacli_dir):
        identity = set_user_identity("Alice")
        assert identity["user_name"] == "Alice"
        assert len(identity["user_id"]) == 12
        assert identity["created_at"] > 0

    def test_get_user_identity_empty(self, isolated_pacli_dir):
        result = get_user_identity()
        assert result == {}

    def test_get_user_identity_persists(self, isolated_pacli_dir):
        set_user_identity("Bob")
        result = get_user_identity()
        assert result["user_name"] == "Bob"

    def test_set_user_identity_preserves_id(self, isolated_pacli_dir):
        first = set_user_identity("Alice")
        second = set_user_identity("Alice Updated")
        assert first["user_id"] == second["user_id"]
        assert second["user_name"] == "Alice Updated"


class TestVaultCreation:
    def test_create_vault(self, vault_manager, master_fernet, user_identity):
        meta = vault_manager.create_vault("my-vault", description="desc", master_fernet=master_fernet)
        assert meta["name"] == "my-vault"
        assert meta["description"] == "desc"
        assert meta["owner"] == "testuser001"
        assert len(meta["id"]) == 8

    def test_create_vault_creates_files(self, vault_manager, master_fernet, isolated_pacli_dir):
        vault_manager.create_vault("infra", master_fernet=master_fernet)
        vaults_dir = os.path.join(isolated_pacli_dir, "vaults")
        vault_dir = os.path.join(vaults_dir, "infra")
        assert os.path.exists(os.path.join(vault_dir, "vault.db"))
        assert os.path.exists(os.path.join(vault_dir, "vault_salt.bin"))
        assert os.path.exists(os.path.join(vault_dir, "vault_key.enc"))

    def test_create_duplicate_vault_fails(self, vault_manager, master_fernet):
        vault_manager.create_vault("dup", master_fernet=master_fernet)
        with pytest.raises(ValueError, match="already exists"):
            vault_manager.create_vault("dup", master_fernet=master_fernet)

    def test_create_vault_invalid_name(self, vault_manager, master_fernet):
        with pytest.raises(ValueError, match="alphanumeric"):
            vault_manager.create_vault("bad name!", master_fernet=master_fernet)

    def test_create_vault_empty_name(self, vault_manager, master_fernet):
        with pytest.raises(ValueError, match="alphanumeric"):
            vault_manager.create_vault("", master_fernet=master_fernet)

    def test_create_vault_no_identity(self, isolated_pacli_dir, master_fernet):
        vm = VaultManager()
        with pytest.raises(RuntimeError, match="User identity not set"):
            vm.create_vault("test", master_fernet=master_fernet)

    def test_create_vault_no_fernet(self, vault_manager):
        with pytest.raises(RuntimeError, match="Master Fernet key required"):
            vault_manager.create_vault("test", master_fernet=None)


class TestVaultListing:
    def test_list_vaults_empty(self, vault_manager):
        result = vault_manager.list_vaults()
        assert result == []

    def test_list_vaults_shows_owned(self, vault_manager, master_fernet):
        vault_manager.create_vault("v1", master_fernet=master_fernet)
        vault_manager.create_vault("v2", description="second", master_fernet=master_fernet)
        vaults = vault_manager.list_vaults()
        assert len(vaults) == 2
        names = {v["name"] for v in vaults}
        assert names == {"v1", "v2"}

    def test_list_vaults_includes_role(self, vault_manager, master_fernet):
        vault_manager.create_vault("v1", master_fernet=master_fernet)
        vaults = vault_manager.list_vaults()
        assert vaults[0]["role"] == "admin"

    def test_list_vaults_includes_secret_count(self, vault_manager, master_fernet):
        vault_manager.create_vault("v1", master_fernet=master_fernet)
        vault_manager.save_secret("v1", "key1", "val1", "token", master_fernet)
        vault_manager.save_secret("v1", "key2", "val2", "token", master_fernet)
        vaults = vault_manager.list_vaults()
        assert vaults[0]["secret_count"] == 2


class TestVaultDeletion:
    def test_delete_vault(self, vault_manager, master_fernet, isolated_pacli_dir):
        vault_manager.create_vault("del-me", master_fernet=master_fernet)
        vault_dir = os.path.join(isolated_pacli_dir, "vaults", "del-me")
        assert os.path.exists(vault_dir)

        vault_manager.delete_vault("del-me")
        assert not os.path.exists(vault_dir)
        assert vault_manager.get_vault("del-me") is None

    def test_delete_nonexistent_vault(self, vault_manager):
        with pytest.raises(ValueError, match="not found"):
            vault_manager.delete_vault("nope")


class TestVaultKeyManagement:
    def test_unlock_vault(self, vault_manager, master_fernet):
        vault_manager.create_vault("lock-test", master_fernet=master_fernet)
        vault_fernet = vault_manager.unlock_vault("lock-test", master_fernet)
        assert vault_fernet is not None
        # Verify it can encrypt/decrypt
        encrypted = vault_fernet.encrypt(b"hello")
        assert vault_fernet.decrypt(encrypted) == b"hello"

    def test_unlock_vault_caches(self, vault_manager, master_fernet):
        vault_manager.create_vault("cache-test", master_fernet=master_fernet)
        f1 = vault_manager.unlock_vault("cache-test", master_fernet)
        f2 = vault_manager.unlock_vault("cache-test", master_fernet)
        assert f1 is f2

    def test_unlock_nonexistent_vault(self, vault_manager, master_fernet):
        with pytest.raises(ValueError, match="not found"):
            vault_manager.unlock_vault("nope", master_fernet)

    def test_unlock_vault_wrong_key(self, vault_manager, master_fernet):
        vault_manager.create_vault("wrong-key", master_fernet=master_fernet)
        wrong_fernet = Fernet(Fernet.generate_key())
        with pytest.raises(Exception):
            vault_manager.unlock_vault("wrong-key", wrong_fernet)


class TestVaultSecrets:
    def test_save_and_get_secret(self, vault_manager, master_fernet):
        vault_manager.create_vault("sec-test", master_fernet=master_fernet)
        vault_manager.save_secret("sec-test", "api-key", "sk-12345", "token", master_fernet)

        secrets = vault_manager.list_secrets("sec-test")
        assert len(secrets) == 1
        assert secrets[0][1] == "api-key"
        assert secrets[0][2] == "token"

    def test_get_secret_by_id(self, vault_manager, master_fernet):
        vault_manager.create_vault("id-test", master_fernet=master_fernet)
        vault_manager.save_secret("id-test", "db-pass", "p@ssw0rd", "password", master_fernet)

        secrets = vault_manager.list_secrets("id-test")
        secret_id = secrets[0][0]
        result = vault_manager.get_secret("id-test", secret_id, master_fernet)
        assert result is not None
        assert result["label"] == "db-pass"
        assert result["secret"] == "p@ssw0rd"
        assert result["type"] == "password"

    def test_get_secrets_by_label(self, vault_manager, master_fernet):
        vault_manager.create_vault("label-test", master_fernet=master_fernet)
        vault_manager.save_secret("label-test", "shared-key", "value1", "token", master_fernet)
        vault_manager.save_secret("label-test", "shared-key", "value2", "token", master_fernet)

        results = vault_manager.get_secrets_by_label("label-test", "shared-key", master_fernet)
        assert len(results) == 2
        values = {r["secret"] for r in results}
        assert values == {"value1", "value2"}

    def test_update_secret(self, vault_manager, master_fernet):
        vault_manager.create_vault("upd-test", master_fernet=master_fernet)
        vault_manager.save_secret("upd-test", "key", "old", "token", master_fernet)

        secrets = vault_manager.list_secrets("upd-test")
        secret_id = secrets[0][0]
        vault_manager.update_secret("upd-test", secret_id, "new", master_fernet)

        result = vault_manager.get_secret("upd-test", secret_id, master_fernet)
        assert result["secret"] == "new"

    def test_delete_secret(self, vault_manager, master_fernet):
        vault_manager.create_vault("del-sec", master_fernet=master_fernet)
        vault_manager.save_secret("del-sec", "temp", "val", "token", master_fernet)

        secrets = vault_manager.list_secrets("del-sec")
        assert len(secrets) == 1

        vault_manager.delete_secret("del-sec", secrets[0][0])
        secrets = vault_manager.list_secrets("del-sec")
        assert len(secrets) == 0

    def test_secret_encrypted_differently_per_vault(self, vault_manager, master_fernet):
        vault_manager.create_vault("v1", master_fernet=master_fernet)
        vault_manager.create_vault("v2", master_fernet=master_fernet)

        vault_manager.save_secret("v1", "key", "same-value", "token", master_fernet)
        vault_manager.save_secret("v2", "key", "same-value", "token", master_fernet)

        f1 = vault_manager.unlock_vault("v1", master_fernet)
        f2 = vault_manager.unlock_vault("v2", master_fernet)
        # Different Fernet instances mean different encryption keys
        assert f1 is not f2

    def test_secret_includes_created_by(self, vault_manager, master_fernet, user_identity):
        vault_manager.create_vault("by-test", master_fernet=master_fernet)
        vault_manager.save_secret("by-test", "key", "val", "token", master_fernet)

        result = vault_manager.get_secret("by-test", vault_manager.list_secrets("by-test")[0][0], master_fernet)
        assert result["created_by"] == "testuser001"


class TestMemberManagement:
    def test_creator_is_admin(self, vault_manager, master_fernet, user_identity):
        vault_manager.create_vault("members", master_fernet=master_fernet)
        members = vault_manager.list_members("members")
        assert len(members) == 1
        assert members[0]["user_id"] == "testuser001"
        assert members[0]["role"] == "admin"

    def test_add_member(self, vault_manager, master_fernet):
        vault_manager.create_vault("add-mem", master_fernet=master_fernet)
        vault_manager.add_member("add-mem", "user2", "User Two", "editor", master_fernet)

        members = vault_manager.list_members("add-mem")
        assert len(members) == 2
        user2 = [m for m in members if m["user_id"] == "user2"][0]
        assert user2["role"] == "editor"
        assert user2["user_name"] == "User Two"

    def test_add_duplicate_member(self, vault_manager, master_fernet):
        vault_manager.create_vault("dup-mem", master_fernet=master_fernet)
        vault_manager.add_member("dup-mem", "user2", "User Two", "viewer", master_fernet)
        with pytest.raises(ValueError, match="already a member"):
            vault_manager.add_member("dup-mem", "user2", "User Two", "editor", master_fernet)

    def test_add_member_invalid_role(self, vault_manager, master_fernet):
        vault_manager.create_vault("inv-role", master_fernet=master_fernet)
        with pytest.raises(ValueError, match="Invalid role"):
            vault_manager.add_member("inv-role", "user2", "User Two", "superadmin", master_fernet)

    def test_remove_member(self, vault_manager, master_fernet):
        vault_manager.create_vault("rem-mem", master_fernet=master_fernet)
        vault_manager.add_member("rem-mem", "user2", "User Two", "viewer", master_fernet)
        vault_manager.remove_member("rem-mem", "user2")

        members = vault_manager.list_members("rem-mem")
        assert len(members) == 1

    def test_remove_self_fails(self, vault_manager, master_fernet, user_identity):
        vault_manager.create_vault("rem-self", master_fernet=master_fernet)
        with pytest.raises(ValueError, match="Cannot remove yourself"):
            vault_manager.remove_member("rem-self", "testuser001")

    def test_set_member_role(self, vault_manager, master_fernet):
        vault_manager.create_vault("role-test", master_fernet=master_fernet)
        vault_manager.add_member("role-test", "user2", "User Two", "viewer", master_fernet)
        vault_manager.set_member_role("role-test", "user2", "admin")

        members = vault_manager.list_members("role-test")
        user2 = [m for m in members if m["user_id"] == "user2"][0]
        assert user2["role"] == "admin"


class TestRBAC:
    def test_viewer_permissions(self):
        perms = ROLE_PERMISSIONS[VaultRole.VIEWER]
        assert "list_secrets" in perms
        assert "get_secret" in perms
        assert "create_secret" not in perms
        assert "delete_secret" not in perms

    def test_editor_permissions(self):
        perms = ROLE_PERMISSIONS[VaultRole.EDITOR]
        assert "list_secrets" in perms
        assert "create_secret" in perms
        assert "update_secret" in perms
        assert "add_member" not in perms

    def test_admin_permissions(self):
        perms = ROLE_PERMISSIONS[VaultRole.ADMIN]
        assert "add_member" in perms
        assert "remove_member" in perms
        assert "delete_vault" in perms

    def test_viewer_cannot_create_secret(self, vault_manager, master_fernet, user_identity, isolated_pacli_dir):
        vault_manager.create_vault("rbac-test", master_fernet=master_fernet)

        # Change current user's role to viewer
        import sqlite3

        vault_dir = os.path.join(isolated_pacli_dir, "vaults", "rbac-test")
        db_path = os.path.join(vault_dir, "vault.db")
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE members SET role = 'viewer' WHERE user_id = ?", (user_identity["user_id"],))
        conn.commit()
        conn.close()

        # Recreate vault manager to clear cache
        vm = VaultManager()
        with pytest.raises(PermissionError, match="does not have permission"):
            vm.save_secret("rbac-test", "key", "val", "token", master_fernet)


class TestAuditLog:
    def test_vault_creation_logged(self, vault_manager, master_fernet):
        vault_manager.create_vault("audit-test", master_fernet=master_fernet)
        log = vault_manager.get_audit_log("audit-test")
        assert len(log) >= 1
        assert any(e["action"] == "create_vault" for e in log)

    def test_secret_operations_logged(self, vault_manager, master_fernet):
        vault_manager.create_vault("audit-sec", master_fernet=master_fernet)
        vault_manager.save_secret("audit-sec", "key", "val", "token", master_fernet)

        log = vault_manager.get_audit_log("audit-sec")
        actions = {e["action"] for e in log}
        assert "create" in actions

    def test_member_operations_logged(self, vault_manager, master_fernet):
        vault_manager.create_vault("audit-mem", master_fernet=master_fernet)
        vault_manager.add_member("audit-mem", "user2", "User Two", "editor", master_fernet)

        log = vault_manager.get_audit_log("audit-mem")
        actions = {e["action"] for e in log}
        assert "add_member" in actions

    def test_audit_log_limit(self, vault_manager, master_fernet):
        vault_manager.create_vault("limit-test", master_fernet=master_fernet)
        for i in range(10):
            vault_manager.save_secret("limit-test", f"key-{i}", f"val-{i}", "token", master_fernet)

        log = vault_manager.get_audit_log("limit-test", limit=5)
        assert len(log) == 5

    def test_audit_log_includes_user(self, vault_manager, master_fernet, user_identity):
        vault_manager.create_vault("user-log", master_fernet=master_fernet)
        log = vault_manager.get_audit_log("user-log")
        assert all(e["user_id"] == "testuser001" for e in log)
