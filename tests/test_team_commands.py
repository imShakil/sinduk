"""
Tests for the `pacli team` CLI commands.
"""

import os
import json
import pytest
from click.testing import CliRunner

from sinduk.cli import cli


@pytest.fixture(autouse=True)
def isolated_pacli_dir(tmp_path, monkeypatch):
    """Redirect all pacli config to a temp directory for test isolation."""
    test_config = str(tmp_path / "sinduk_config")
    os.makedirs(test_config, exist_ok=True)

    monkeypatch.setattr("sinduk.vault.PACLI_DIR", test_config)
    monkeypatch.setattr("sinduk.vault.VAULTS_DIR", os.path.join(test_config, "vaults"))
    monkeypatch.setattr("sinduk.vault.REGISTRY_PATH", os.path.join(test_config, "vaults", "vault_registry.json"))
    monkeypatch.setattr("sinduk.vault.USER_IDENTITY_PATH", os.path.join(test_config, "user_identity.json"))

    # Also patch the store paths so they don't conflict with real data
    store_salt_path = os.path.join(test_config, "salt.bin")
    store_hash_path = os.path.join(test_config, "password_hash.bin")
    monkeypatch.setattr("sinduk.store.SALT_PATH", store_salt_path)
    monkeypatch.setattr("sinduk.store.PASSWORD_HASH_PATH", store_hash_path)

    return test_config


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def user_identity(isolated_pacli_dir):
    """Set up a test user identity."""
    identity_path = os.path.join(isolated_pacli_dir, "user_identity.json")
    identity = {
        "user_id": "clitest001",
        "user_name": "CLI Test User",
        "created_at": 1700000000,
        "updated_at": 1700000000,
    }
    with open(identity_path, "w") as f:
        json.dump(identity, f)
    return identity


class TestTeamInit:
    def test_init_sets_identity(self, runner, isolated_pacli_dir):
        result = runner.invoke(cli, ["team", "init"], input="Alice\n")
        assert result.exit_code == 0
        assert "Identity set" in result.output
        assert "Alice" in result.output

    def test_init_shows_existing(self, runner, user_identity):
        result = runner.invoke(cli, ["team", "init"], input="n\n")
        assert result.exit_code == 0
        assert "CLI Test User" in result.output


class TestTeamWhoami:
    def test_whoami_no_identity(self, runner, isolated_pacli_dir):
        result = runner.invoke(cli, ["team", "whoami"])
        assert result.exit_code == 0
        assert "No identity set" in result.output

    def test_whoami_shows_identity(self, runner, user_identity):
        result = runner.invoke(cli, ["team", "whoami"])
        assert result.exit_code == 0
        assert "clitest001" in result.output
        assert "CLI Test User" in result.output


class TestTeamCreateVault:
    def test_create_vault_no_identity(self, runner, isolated_pacli_dir):
        """Without identity, create-vault should fail."""
        result = runner.invoke(cli, ["team", "create-vault", "test"], input="password123\n")
        assert result.exit_code == 0
        assert "No identity set" in result.output or "not set" in result.output.lower()


class TestTeamListVaults:
    def test_list_vaults_empty(self, runner, user_identity):
        result = runner.invoke(cli, ["team", "list-vaults"])
        assert result.exit_code == 0
        assert "No vaults found" in result.output


class TestTeamVaultInfo:
    def test_vault_info_not_found(self, runner, user_identity):
        result = runner.invoke(cli, ["team", "vault-info", "nonexistent"])
        assert result.exit_code == 0
        assert "not found" in result.output


class TestTeamAuditLog:
    def test_audit_log_no_identity(self, runner, isolated_pacli_dir):
        result = runner.invoke(cli, ["team", "audit-log", "test"])
        assert result.exit_code == 0
        assert "No identity set" in result.output or "not set" in result.output.lower()
