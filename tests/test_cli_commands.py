import pytest
from click.testing import CliRunner
from sinduk.cli import cli
import sinduk.store as store_mod


@pytest.fixture
def initialized_store(tmp_path, monkeypatch):
    """Fixture providing an initialized store in an isolated config dir."""
    config_dir = tmp_path / "sinduk"
    config_dir.mkdir(parents=True)
    db_file = str(config_dir / "sqlite3.db")
    salt_file = str(config_dir / "salt.bin")
    hash_file = str(config_dir / "password_hash.bin")

    monkeypatch.setattr(store_mod, "CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(store_mod, "SALT_PATH", salt_file)
    monkeypatch.setattr(store_mod, "PASSWORD_HASH_PATH", hash_file)

    monkeypatch.setenv("SINDUK_MASTER_PASSWORD", "MasterPass123!")
    monkeypatch.setattr("sinduk.store.getpass", lambda prompt="": "MasterPass123!")
    monkeypatch.setattr("sinduk.commands.admin.getpass", lambda prompt="": "MasterPass123!")

    store = store_mod.SecretStore(db_path=db_file)
    store.set_master_password()
    return store


def test_get_by_label_and_by_id(initialized_store, monkeypatch):
    runner = CliRunner()
    # Add a secret
    initialized_store.save_secret("api_token", "secret-token-123", "token")
    secrets = initialized_store.list_secrets()
    assert len(secrets) == 1
    sec_id = str(secrets[0][0])

    # 1. Get by label
    res1 = runner.invoke(cli, ["get", "api_token"])
    assert res1.exit_code == 0
    assert "secret-token-123" in res1.output

    # 2. Get by positional ID
    res2 = runner.invoke(cli, ["get", sec_id])
    assert res2.exit_code == 0
    assert "secret-token-123" in res2.output

    # 3. Get with --id flag
    res3 = runner.invoke(cli, ["get", "--id", sec_id])
    assert res3.exit_code == 0
    assert "secret-token-123" in res3.output

    # 4. Hidden legacy get-by-id command
    res4 = runner.invoke(cli, ["get-by-id", sec_id])
    assert res4.exit_code == 0
    assert "secret-token-123" in res4.output


def test_update_by_label_and_id(initialized_store, monkeypatch):
    runner = CliRunner()
    initialized_store.save_secret("github_token", "old-token-val", "token")
    secrets = initialized_store.list_secrets()
    sec_id = str(secrets[0][0])

    # Mock getpass for entering new secret
    monkeypatch.setattr("sinduk.commands.secrets.getpass", lambda prompt="": "new-token-val")

    # Update with --id flag
    res = runner.invoke(cli, ["update", "--id", sec_id])
    assert res.exit_code == 0
    assert "Updated secret successfully" in res.output

    # Verify updated value
    sec = initialized_store.get_secret_by_id(sec_id)
    assert sec["secret"] == "new-token-val"


def test_delete_by_label_and_id(initialized_store, monkeypatch):
    runner = CliRunner()
    initialized_store.save_secret("delete_me_1", "tok1", "token")
    initialized_store.save_secret("delete_me_2", "tok2", "token")

    secrets = initialized_store.list_secrets()
    id1 = str(secrets[0][0])
    id2 = str(secrets[1][0])

    # Delete by label with --yes
    res1 = runner.invoke(cli, ["delete", "delete_me_1", "--yes"])
    assert res1.exit_code == 0
    assert "Deleted from the list" in res1.output
    assert initialized_store.get_secret_by_id(id1) is None

    # Delete by --id with --yes
    res2 = runner.invoke(cli, ["delete", "--id", id2, "--yes"])
    assert res2.exit_code == 0
    assert "deleted successfully" in res2.output
    assert initialized_store.get_secret_by_id(id2) is None


def test_passwd_command(initialized_store, monkeypatch):
    runner = CliRunner()

    passwords = iter(["NewMasterPass456!", "NewMasterPass456!"])
    monkeypatch.setattr("sinduk.commands.admin.getpass", lambda prompt="": next(passwords))

    res = runner.invoke(cli, ["passwd"])
    assert res.exit_code == 0
    assert "Master password changed" in res.output
