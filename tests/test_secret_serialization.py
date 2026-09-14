import json
from sinduk.helpers import (
    generate_secure_password,
    parse_secret_payload,
    serialize_password_secret,
    serialize_ssh_secret,
    serialize_token_secret,
)


def test_generate_secure_password():
    pwd20 = generate_secure_password(20)
    assert len(pwd20) == 20
    assert any(c.isupper() for c in pwd20)
    assert any(c.islower() for c in pwd20)
    assert any(c.isdigit() for c in pwd20)
    assert any(c in "!@#$%^&*()-_=+[]{}<>?" for c in pwd20)

    pwd_min = generate_secure_password(4)  # should clamp to min 8
    assert len(pwd_min) == 8


def test_parse_and_serialize_password_json():
    serialized = serialize_password_secret("alice", "sample_password_val_1", "example.com")
    parsed = parse_secret_payload(serialized, "password")

    assert parsed["username"] == "alice"
    assert parsed["password"] == "sample_password_val_1"
    assert parsed["domain"] == "example.com"


def test_parse_password_legacy_formats():
    # Standard user:pass
    parsed1 = parse_secret_payload("bob:test_pass_sample", "password")
    assert parsed1["username"] == "bob"
    assert parsed1["password"] == "test_pass_sample"
    assert parsed1["domain"] == ""

    # Legacy with |domain:
    parsed2 = parse_secret_payload("charlie:sample_password_val|domain:console.example.com", "password")
    assert parsed2["username"] == "charlie"
    assert parsed2["password"] == "sample_password_val"
    assert parsed2["domain"] == "console.example.com"

    # Password with colons in legacy format
    parsed3 = parse_secret_payload("dave:my:sample:password:val", "password")
    assert parsed3["username"] == "dave"
    assert parsed3["password"] == "my:sample:password:val"


def test_parse_and_serialize_ssh_json():
    serialized = serialize_ssh_secret(
        user="ubuntu",
        host="192.168.1.100",
        port=2222,
        key_path="~/.ssh/id_ed25519",
        opts="-o StrictHostKeyChecking=no",
        password="test_ssh_pass_val",
    )
    parsed = parse_secret_payload(serialized, "ssh")

    assert parsed["user"] == "ubuntu"
    assert parsed["host"] == "192.168.1.100"
    assert parsed["port"] == 2222
    assert parsed["key_path"] == "~/.ssh/id_ed25519"
    assert parsed["opts"] == "-o StrictHostKeyChecking=no"
    assert parsed["password"] == "test_ssh_pass_val"


def test_parse_ssh_legacy_formats():
    legacy1 = "root:10.0.0.1|port:2200|key:/path/to/key|opts:-o ConnectTimeout=5"
    parsed1 = parse_secret_payload(legacy1, "ssh")
    assert parsed1["user"] == "root"
    assert parsed1["host"] == "10.0.0.1"
    assert parsed1["port"] == 2200
    assert parsed1["key_path"] == "/path/to/key"
    assert parsed1["opts"] == "-o ConnectTimeout=5"

    legacy2 = "admin@prod.example.com|pass:test_legacy_pass_str"
    parsed2 = parse_secret_payload(legacy2, "ssh")
    assert parsed2["user"] == "admin"
    assert parsed2["host"] == "prod.example.com"
    assert parsed2["password"] == "test_legacy_pass_str"


def test_parse_and_serialize_token_secret():
    # Single token serialization
    tok_simple = serialize_token_secret("sample_mock_token_string_123")
    assert tok_simple == "sample_mock_token_string_123"
    parsed1 = parse_secret_payload(tok_simple, "token")
    assert parsed1["token"] == "sample_mock_token_string_123"

    # Token ID + Secret Pair serialization
    tok_pair = serialize_token_secret("mock_api_secret_key_sample_456", token_id="mock_api_key_id_sample_123")
    parsed_pair = parse_secret_payload(tok_pair, "token")
    assert parsed_pair["token_id"] == "mock_api_key_id_sample_123"
    assert parsed_pair["token"] == "mock_api_secret_key_sample_456"

    # Direct JSON dictionary with custom client_id
    token_json = json.dumps({"client_id": "oauth_client_1", "client_secret": "oauth_secret_2"})
    parsed3 = parse_secret_payload(token_json, "token")
    assert parsed3["client_id"] == "oauth_client_1"
    assert parsed3["client_secret"] == "oauth_secret_2"


def test_web_api_generate_password(monkeypatch):
    import sinduk.web.app as web_app
    from flask import Flask

    class MockStore:
        def __init__(self):
            self.fernet = object()

        def is_master_set(self):
            return True

    store = MockStore()
    app = Flask(__name__)
    app.secret_key = "test-secret"
    app.config["TESTING"] = True

    require_auth = web_app._build_require_auth(store)
    web_app._register_generate_password_route(app, require_auth)

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["authenticated"] = True

        res = client.get("/api/tools/generate-password?length=24")
        assert res.status_code == 200
        data = res.get_json()
        assert "password" in data
        assert len(data["password"]) == 24
