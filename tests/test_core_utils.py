def test_choice_one_retries_until_valid(monkeypatch):
    from sinduk import helpers

    prompts = iter([0, 2])
    monkeypatch.setattr(helpers.click, "prompt", lambda *args, **kwargs: next(prompts))

    selected = helpers.choice_one(
        "db",
        [
            {"id": "a", "type": "token", "creation_time": 1, "update_time": 1},
            {"id": "b", "type": "password", "creation_time": 2, "update_time": 2},
        ],
    )

    assert selected["id"] == "b"


def test_copy_to_clipboard_success(monkeypatch):
    from sinduk import helpers

    captured = {"value": None}

    def fake_copy(value):
        captured["value"] = value

    monkeypatch.setattr(helpers.pyperclip, "copy", fake_copy)
    helpers.copy_to_clipboard("hello")

    assert captured["value"] == "hello"


def test_copy_to_clipboard_failure(monkeypatch, capsys):
    from sinduk import helpers

    def _raise_runtime(value):
        raise RuntimeError("boom")

    monkeypatch.setattr(helpers.pyperclip, "copy", _raise_runtime)

    helpers.copy_to_clipboard("x")
    out = capsys.readouterr().out
    assert "Failed to copy" in out


def test_master_password_required_allows_and_blocks(monkeypatch):
    import sinduk.decorators as decorators

    class StoreNotSet:
        def is_master_set(self):
            return False

    class StoreSet:
        def is_master_set(self):
            return True

    monkeypatch.setattr(decorators, "SecretStore", StoreNotSet)

    called = {"count": 0}

    @decorators.master_password_required
    def command_one():
        called["count"] += 1
        return "ok"

    assert command_one() is None
    assert called["count"] == 0

    monkeypatch.setattr(decorators, "SecretStore", StoreSet)

    @decorators.master_password_required
    def command_two():
        called["count"] += 1
        return "ok"

    assert command_two() == "ok"
    assert called["count"] == 1


def test_parse_and_suggest_ssh_hosts(monkeypatch, tmp_path):
    from sinduk import ssh_utils

    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir(parents=True)
    config_path = ssh_dir / "config"
    config_path.write_text(
        """
Host prod
  HostName 10.0.0.1
  User ubuntu
  Port 2222

Host test-box
  HostName 10.0.0.2
  User root
""".strip() + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(ssh_utils.Path, "home", lambda: tmp_path)

    all_hosts = ssh_utils.parse_ssh_config()
    assert set(all_hosts.keys()) == {"prod", "test-box"}

    filtered = ssh_utils.parse_ssh_config("prod")
    assert set(filtered.keys()) == {"prod"}

    assert ssh_utils.suggest_ssh_hosts("test") == ["test-box"]


def test_get_ssh_connection_string():
    from sinduk import ssh_utils

    assert ssh_utils.get_ssh_connection_string({"hostname": "1.1.1.1", "user": "root", "port": "22"}) == "root@1.1.1.1"
    assert ssh_utils.get_ssh_connection_string({"hostname": "", "user": "root"}) is None


def test_cli_registers_expected_commands():
    from sinduk.cli import cli

    expected = {
        "init",
        "change-master-key",
        "version",
        "add",
        "get",
        "get-by-id",
        "list",
        "update",
        "update-by-id",
        "delete",
        "delete-by-id",
        "ssh",
        "export",
        "cc",
        "backup",
        "web",
    }

    assert expected.issubset(set(cli.commands.keys()))


def test_package_version_symbol_exists():
    import sinduk

    assert hasattr(sinduk, "__version__")
    assert isinstance(sinduk.__version__, str)


def test_get_logger_returns_named_logger(monkeypatch, tmp_path):
    import sinduk.log as log_module

    monkeypatch.setattr(log_module.os.path, "expanduser", lambda p: str(tmp_path / "sinduk.log"))
    logger = log_module.get_logger("demo.logger")

    assert logger.name == "demo.logger"


def test_get_logger_permission_error(monkeypatch, tmp_path):
    import sinduk.log as log_module
    import pytest

    monkeypatch.setattr(log_module.os.path, "expanduser", lambda p: str(tmp_path / "sinduk.log"))
    monkeypatch.setattr(log_module.os, "access", lambda *args, **kwargs: False)

    with pytest.raises(PermissionError):
        log_module.get_logger("blocked.logger")


def test_cli_pacli_alias_deprecation_warning(monkeypatch):
    import sys
    from click.testing import CliRunner
    from sinduk.cli import cli

    runner = CliRunner()
    monkeypatch.setattr(sys, "argv", ["pacli", "--help"])
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "deprecated" in result.output.lower() or "sinduk" in result.output.lower()
