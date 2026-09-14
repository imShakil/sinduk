def test_ssh_helper_extract_and_build_command(monkeypatch):
    from sinduk.commands import ssh as ssh_cmd

    selected = {"secret": "ubuntu:10.0.0.1|port:2200|key:/tmp/id_rsa|opts:-o StrictHostKeyChecking=no"}
    cmd_parts, user, ip = ssh_cmd._build_ssh_command(selected)

    assert user == "ubuntu"
    assert ip == "10.0.0.1"
    assert cmd_parts[-1] == "ubuntu@10.0.0.1"
    assert "-p" in cmd_parts
    assert "2200" in cmd_parts


def test_ssh_helpers_invalid_cases(capsys):
    from sinduk.commands import ssh as ssh_cmd

    user, ip, parts = ssh_cmd._extract_user_host("invalid-format")
    assert (user, ip, parts) == (None, None, None)

    out = capsys.readouterr().out
    assert "Invalid SSH format" in out

    assert ssh_cmd._is_valid_username("valid.user-1") is True
    assert ssh_cmd._is_valid_username("bad user") is False


def test_ssh_option_handlers():
    from sinduk.commands import ssh as ssh_cmd

    cmd = ["ssh"]
    assert ssh_cmd._handle_port_option(cmd, "port:22") is True
    assert ssh_cmd._handle_key_option(cmd, "key:/tmp/key") is True
    assert ssh_cmd._handle_opts_option(cmd, "opts:-o StrictHostKeyChecking=no") is True

    assert ssh_cmd._handle_port_option(["ssh"], "port:99999") is False
    assert ssh_cmd._handle_key_option(["ssh"], "key:../bad") is False
    assert ssh_cmd._handle_opts_option(["ssh"], "opts:-F /tmp/unsafe") is False


def test_secrets_helper_type_and_ssh_formatting(monkeypatch):
    from sinduk.commands import secrets

    assert secrets._detect_secret_type(None, None, None) == "token"
    assert secrets._detect_secret_type(None, "user", "pass") == "password"
    assert secrets._detect_secret_type(None, "root@1.2.3.4", None) == "ssh"

    built = secrets._append_ssh_parts("root:1.1.1.1", "/tmp/key", "2200", "-o StrictHostKeyChecking=no")
    assert built == "root:1.1.1.1|key:/tmp/key|port:2200|opts:-o StrictHostKeyChecking=no"

    display = secrets._get_ssh_display(
        {"secret": built, "type": "ssh"},
        "SSH: ",
    )
    assert "SSH: root:1.1.1.1" in display
    assert "Key: /tmp/key" in display
    assert "Port: 2200" in display


def test_secrets_prompt_updated_ssh_secret(monkeypatch):
    from sinduk.commands import secrets

    prompts = iter(["ubuntu", "10.0.0.1", "key:/tmp/id_rsa"])
    monkeypatch.setattr(secrets.click, "prompt", lambda *args, **kwargs: next(prompts))

    updated = secrets._prompt_updated_ssh_secret("old:host|key:/old")
    assert updated == "ubuntu:10.0.0.1|key:/tmp/id_rsa"


def test_secrets_copy_and_print_paths(monkeypatch, capsys):
    from sinduk.commands import secrets

    copied = {"value": None}
    monkeypatch.setattr(secrets, "copy_to_clipboard", lambda s: copied.__setitem__("value", s))

    ssh_secret = {"secret": "root:1.2.3.4|port:22", "type": "ssh"}
    token_secret = {"secret": "abc", "type": "token"}

    secrets._copy_secret(ssh_secret)
    assert copied["value"] == "root:1.2.3.4"

    secrets._print_secret(token_secret, "prefix")
    out = capsys.readouterr().out
    assert "Secret: abc" in out
