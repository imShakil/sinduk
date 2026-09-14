"""
Tests for vault sync and vault backup export/import (Phase 2).
"""

import os
import pytest
from click.testing import CliRunner
from cryptography.fernet import Fernet

from sinduk.cli import cli
from sinduk.vault import VaultManager, set_user_identity


@pytest.fixture(autouse=True)
def isolated_pacli_dir(tmp_path, monkeypatch):
    """Redirect all pacli config to a temp directory for test isolation."""
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
    return set_user_identity("SyncTester")


@pytest.fixture
def runner():
    return CliRunner()


class TestVaultBackupExportImport:
    def test_export_import_vault_backup(self, isolated_pacli_dir, master_fernet, user_identity):
        vm = VaultManager()
        vm.create_vault("sync-vault", description="for sync testing", master_fernet=master_fernet)
        vm.save_secret("sync-vault", "api-key", "secret-token-val", "token", master_fernet)
        vm.save_secret("sync-vault", "db-pass", "user:pass123", "password", master_fernet)

        backup_blob = vm.export_vault_backup("sync-vault", "sync-pass-123", master_fernet)
        assert len(backup_blob) > 0

        # Now test importing into a new or existing vault
        # 1. Test wrong password
        with pytest.raises(ValueError, match="Wrong backup password"):
            vm.import_vault_backup("sync-vault-2", backup_blob, "wrong-password", master_fernet)

        # 2. Import into a new vault name
        stats = vm.import_vault_backup("sync-vault-2", backup_blob, "sync-pass-123", master_fernet)
        assert stats["imported"] == 2
        assert stats["skipped"] == 0
        assert stats["errors"] == 0

        # Verify secrets in new vault
        secrets = vm.list_secrets("sync-vault-2")
        assert len(secrets) == 2
        sec1 = vm.get_secret("sync-vault-2", secrets[0][0], master_fernet)
        assert sec1["secret"] in ["secret-token-val", "user:pass123"]

        # 3. Test duplicate import with merge=True (default: skip duplicates)
        stats2 = vm.import_vault_backup("sync-vault-2", backup_blob, "sync-pass-123", master_fernet, merge=True)
        assert stats2["imported"] == 0
        assert stats2["skipped"] == 2


class TestSyncCliCommands:
    def test_sync_push_and_pull(self, runner, isolated_pacli_dir, master_fernet, user_identity, tmp_path, monkeypatch):
        vm = VaultManager()
        vm.create_vault("team-dev", description="dev team", master_fernet=master_fernet)
        vm.save_secret("team-dev", "staging-db", "root:secret", "password", master_fernet)

        # Monkeypatch store master password requirement
        monkeypatch.setattr("sinduk.store.SecretStore.is_master_set", lambda self: True)
        monkeypatch.setattr(
            "sinduk.store.SecretStore.require_fernet",
            lambda self, *args, **kwargs: setattr(self, "fernet", master_fernet),
        )

        shared_dir = str(tmp_path / "shared_cloud")

        # Test Push
        push_res = runner.invoke(cli, ["sync", "push", "team-dev", "--to", shared_dir, "--password", "testpassword"])
        assert push_res.exit_code == 0
        assert "Pushed vault 'team-dev'" in push_res.output
        assert os.path.exists(os.path.join(shared_dir, "team-dev.sinduk"))

        # Test Status
        status_res = runner.invoke(cli, ["sync", "status", "team-dev", "--path", shared_dir])
        assert status_res.exit_code == 0
        assert "Sync file for vault 'team-dev'" in status_res.output

        # Test Status for non-existent
        status_empty = runner.invoke(cli, ["sync", "status", "nonexistent", "--path", shared_dir])
        assert status_empty.exit_code == 0
        assert "No sync file found" in status_empty.output

        # Test Pull into target
        pull_res = runner.invoke(
            cli, ["sync", "pull", "team-dev", "--from", shared_dir, "--password", "testpassword", "--overwrite"]
        )
        assert pull_res.exit_code == 0
        assert "Pulled vault 'team-dev'" in pull_res.output

    def test_sync_pull_file_not_found(
        self, runner, isolated_pacli_dir, master_fernet, user_identity, tmp_path, monkeypatch
    ):
        monkeypatch.setattr("sinduk.store.SecretStore.is_master_set", lambda self: True)
        monkeypatch.setattr(
            "sinduk.store.SecretStore.require_fernet",
            lambda self, *args, **kwargs: setattr(self, "fernet", master_fernet),
        )

        shared_dir = str(tmp_path / "empty_cloud")
        res = runner.invoke(cli, ["sync", "pull", "team-missing", "--from", shared_dir, "--password", "testpass"])
        assert res.exit_code == 0
        assert "File not found" in res.output
