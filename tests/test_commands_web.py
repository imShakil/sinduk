def test_state_file_save_load_and_clear(monkeypatch, tmp_path):
    from sinduk.commands import web as web_cmd

    monkeypatch.setattr(web_cmd, "WEB_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(web_cmd, "WEB_PID_PATH", str(tmp_path / "webui.pid"))
    monkeypatch.setattr(web_cmd, "WEB_STATE_PATH", str(tmp_path / "webui_state.json"))

    web_cmd._save_state(1234, "127.0.0.1", 58371, str(tmp_path / "webui.log"))
    assert web_cmd._get_pid_from_file() == 1234

    state = web_cmd._load_state()
    assert state["pid"] == 1234
    assert state["host"] == "127.0.0.1"

    web_cmd._clear_state_files()
    assert web_cmd._get_pid_from_file() is None
    assert web_cmd._load_state() == {}


def test_get_pid_from_file_invalid_values(monkeypatch, tmp_path):
    from sinduk.commands import web as web_cmd

    monkeypatch.setattr(web_cmd, "WEB_PID_PATH", str(tmp_path / "webui.pid"))

    assert web_cmd._get_pid_from_file() is None

    (tmp_path / "webui.pid").write_text("abc", encoding="utf-8")
    assert web_cmd._get_pid_from_file() is None

    (tmp_path / "webui.pid").write_text("1", encoding="utf-8")
    assert web_cmd._get_pid_from_file() is None


def test_load_state_invalid_json(monkeypatch, tmp_path):
    from sinduk.commands import web as web_cmd

    monkeypatch.setattr(web_cmd, "WEB_STATE_PATH", str(tmp_path / "webui_state.json"))
    (tmp_path / "webui_state.json").write_text("{broken", encoding="utf-8")

    assert web_cmd._load_state() == {}


def test_pid_owned_by_current_user(monkeypatch):
    from sinduk.commands import web as web_cmd

    monkeypatch.setattr(web_cmd.os.path, "exists", lambda p: True)

    class StatObj:
        st_uid = 1000

    monkeypatch.setattr(web_cmd.os, "stat", lambda p: StatObj())
    monkeypatch.setattr(web_cmd.os, "getuid", lambda: 1000)
    assert web_cmd._is_pid_owned_by_current_user(5) is True

    monkeypatch.setattr(web_cmd.os, "getuid", lambda: 1001)
    assert web_cmd._is_pid_owned_by_current_user(5) is False


def test_is_expected_web_process(monkeypatch, tmp_path):
    from sinduk.commands import web as web_cmd

    cmdline_file = tmp_path / "cmdline"
    cmdline_file.write_bytes(b"python\x00-m\x00pacli.commands.web\x00_run_server\x00")

    def fake_open(path, mode="r", *args, **kwargs):
        if path.endswith("/cmdline") and "b" in mode:
            return cmdline_file.open("rb")
        raise OSError("missing")

    monkeypatch.setattr(web_cmd, "open", fake_open, raising=False)
    assert web_cmd._is_expected_web_process(999) is True

    cmdline_file.write_bytes(b"python\x00other.module\x00")
    assert web_cmd._is_expected_web_process(999) is False


def test_start_already_running_uses_state(monkeypatch, tmp_path, capsys):
    from sinduk.commands import web as web_cmd

    pid_file = tmp_path / "webui.pid"
    pid_file.write_text("777", encoding="utf-8")

    monkeypatch.setattr(web_cmd, "WEB_PID_PATH", str(pid_file))
    monkeypatch.setattr(web_cmd, "_is_pid_running", lambda pid: True)
    monkeypatch.setattr(web_cmd, "_load_state", lambda: {"host": "0.0.0.0", "port": 8000})

    web_cmd.start.callback(host="127.0.0.1", port=58371, no_browser=True)
    out = capsys.readouterr().out
    assert "already running" in out
    assert "0.0.0.0:8000" in out


def test_start_process_exits_immediately(monkeypatch, tmp_path):
    from sinduk.commands import web as web_cmd
    import pytest

    class FakeProcess:
        pid = 4242

        def poll(self):
            return 1

    monkeypatch.setattr(web_cmd, "WEB_PID_PATH", str(tmp_path / "webui.pid"))
    monkeypatch.setattr(web_cmd, "WEB_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(web_cmd, "WEB_LOG_PATH", str(tmp_path / "webui.log"))
    monkeypatch.setattr(web_cmd, "_clear_state_files", lambda: None)
    monkeypatch.setattr(web_cmd.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())

    with pytest.raises(web_cmd.click.Abort):
        web_cmd.start.callback(host="127.0.0.1", port=58371, no_browser=True)


def test_status_paths(monkeypatch, tmp_path, capsys):
    from sinduk.commands import web as web_cmd

    monkeypatch.setattr(web_cmd, "WEB_PID_PATH", str(tmp_path / "webui.pid"))

    web_cmd.status.callback()
    out = capsys.readouterr().out
    assert "not running" in out

    (tmp_path / "webui.pid").write_text("999", encoding="utf-8")
    monkeypatch.setattr(web_cmd, "_get_pid_from_file", lambda: 999)
    monkeypatch.setattr(web_cmd, "_load_state", lambda: {"host": "127.0.0.1", "port": 58371, "log": "x.log"})
    monkeypatch.setattr(web_cmd, "_is_pid_running", lambda pid: True)

    web_cmd.status.callback()
    out = capsys.readouterr().out
    assert "running" in out
    assert "x.log" in out


def test_stop_rejects_non_owned_process(monkeypatch, tmp_path, capsys):
    from sinduk.commands import web as web_cmd

    pid_file = tmp_path / "webui.pid"
    pid_file.write_text("123", encoding="utf-8")
    monkeypatch.setattr(web_cmd, "WEB_PID_PATH", str(pid_file))
    monkeypatch.setattr(web_cmd, "_get_pid_from_file", lambda: 123)
    monkeypatch.setattr(web_cmd, "_is_pid_running", lambda pid: True)
    monkeypatch.setattr(web_cmd, "_is_pid_owned_by_current_user", lambda pid: False)

    web_cmd.stop.callback()
    out = capsys.readouterr().out
    assert "not owned by current user" in out


def test_run_server_no_browser(monkeypatch, capsys):
    from sinduk.commands import web as web_cmd

    class FakeSocket:
        def run(self, app, host, port, debug, allow_unsafe_werkzeug):
            assert host == "127.0.0.1"
            assert port == 58371
            assert debug is False
            assert allow_unsafe_werkzeug is True

    monkeypatch.setattr(web_cmd, "create_app", lambda: (object(), FakeSocket()))
    web_cmd._run_server("127.0.0.1", 58371, True)
    out = capsys.readouterr().out
    assert "starting" in out.lower()
