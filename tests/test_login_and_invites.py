import os
import pytest
from click.testing import CliRunner
from sinduk.cli import cli
from sinduk.invite import generate_invite_url, parse_invite_token
from sinduk.server import SyncServerDB, create_sync_server_app
from sinduk.sync_client import get_sync_config, set_sync_config


@pytest.fixture
def runner():
    return CliRunner()


class TestInviteHelpers:
    def test_generate_and_parse_invite_url(self):
        url = generate_invite_url(
            server_url="https://secrets.company.com:58380",
            vault_name="backend-infra",
            vault_key_b64="c2VjcmV0LWtleS0xMjM=",
            role="editor",
            expires_in_hours=24,
            invited_by="Alice",
        )
        assert url.startswith("https://secrets.company.com:58380/join?token=")
        assert "#key=c2VjcmV0LWtleS0xMjM=" in url

        # Extract token param
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(url)
        token_b64 = parse_qs(parsed.query)["token"][0]

        payload = parse_invite_token(token_b64)
        assert payload is not None
        assert payload["vault"] == "backend-infra"
        assert payload["role"] == "editor"
        assert payload["invited_by"] == "Alice"

    def test_parse_invalid_token(self):
        assert parse_invite_token("invalid_garbage_token") is None


class TestLoginCliCommands:
    def test_logout_command(self, runner, tmp_path, monkeypatch):
        test_cfg = str(tmp_path / "sync_cfg.json")
        monkeypatch.setattr("sinduk.sync_client.SYNC_CONFIG_PATH", test_cfg)

        set_sync_config(server_url="http://127.0.0.1:58380", token="sample_tok")
        assert get_sync_config().get("token") == "sample_tok"

        res = runner.invoke(cli, ["logout"])
        assert res.exit_code == 0
        assert "Successfully logged out" in res.output
        assert get_sync_config().get("token") is None

    def test_login_headless(self, runner, tmp_path, monkeypatch):
        db_file = os.path.join(str(tmp_path), "login_test.db")
        db = SyncServerDB(db_file)
        db.register_user("charlie@company.com", "charliePass123", "Charlie")

        test_cfg = str(tmp_path / "sync_cfg.json")
        monkeypatch.setattr("sinduk.sync_client.SYNC_CONFIG_PATH", test_cfg)

        from unittest.mock import patch
        from urllib.parse import urlparse

        app = create_sync_server_app(db)
        client = app.test_client()

        class MockResponse:
            def __init__(self, flask_res):
                self.status_code = flask_res.status_code
                self._data = flask_res.get_json(silent=True) or {}

            def json(self):
                return self._data

        def mock_post(url, *args, **kwargs):
            parsed = urlparse(url)
            path = parsed.path or "/"
            json_data = kwargs.get("json", {})
            return MockResponse(client.post(path, json=json_data))

        def mock_get(url, *args, **kwargs):
            parsed = urlparse(url)
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
            return MockResponse(client.get(path))

        with patch("requests.post", side_effect=mock_post), patch("requests.get", side_effect=mock_get):
            res = runner.invoke(
                cli,
                ["login", "http://127.0.0.1:58380", "--no-browser"],
                input="charlie@company.com\ncharliePass123\n",
            )
            assert res.exit_code == 0
            assert "Successfully authenticated" in res.output
            assert get_sync_config().get("token") is not None
