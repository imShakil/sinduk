"""Tests for pacli.validators module."""

import pytest

from sinduk.validators import (
    MAX_LABEL_LENGTH,
    MAX_PASSWORD_LENGTH,
    MAX_SECRET_BYTES,
    ValidationError,
    sanitise_search_query,
    validate_backup_password,
    validate_label,
    validate_master_password,
    validate_secret,
    validate_secret_type,
    validate_ssh_parts,
)


class TestValidationError:
    """Test ValidationError exception."""

    def test_creation(self):
        """ValidationError should store field and message."""
        exc = ValidationError("label", "Too short")
        assert exc.field == "label"
        assert exc.message == "Too short"

    def test_string_representation(self):
        """ValidationError should format as 'field: message'."""
        exc = ValidationError("secret", "Invalid value")
        assert str(exc) == "secret: Invalid value"


class TestValidateLabel:
    """Test validate_label function."""

    def test_valid_label(self):
        """Valid labels should pass."""
        assert validate_label("github") == "github"
        assert validate_label("my-secret") == "my-secret"
        assert validate_label("api_key_1") == "api_key_1"

    def test_label_stripping(self):
        """Labels should be stripped of whitespace."""
        assert validate_label("  github  ") == "github"
        assert validate_label("\tapi-key\n") == "api-key"

    def test_label_too_short(self):
        """Empty or too-short labels should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_label("")
        assert exc.value.field == "label"

    def test_label_too_long(self):
        """Labels exceeding max length should fail."""
        long_label = "a" * (MAX_LABEL_LENGTH + 1)
        with pytest.raises(ValidationError) as exc:
            validate_label(long_label)
        assert exc.value.field == "label"
        assert "too long" in exc.value.message.lower()

    def test_label_invalid_chars(self):
        """Labels with invalid characters should fail."""
        with pytest.raises(ValidationError):
            validate_label("secret@#$")
        with pytest.raises(ValidationError):
            validate_label("secret with spaces")

    def test_label_allowed_chars(self):
        """Labels with allowed special chars should pass."""
        assert validate_label("my.secret") == "my.secret"
        assert validate_label("my/secret") == "my/secret"
        assert validate_label("secret@host") == "secret@host"
        assert validate_label("secret-123") == "secret-123"


class TestValidateSecret:
    """Test validate_secret function."""

    def test_valid_password(self):
        """Valid passwords should pass."""
        result = validate_secret("MyPassword123", secret_type="password")
        assert result == "MyPassword123"

    def test_valid_token(self):
        """Valid tokens should pass."""
        result = validate_secret("abc123def456", secret_type="token")
        assert result == "abc123def456"

    def test_secret_empty(self):
        """Empty secrets should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_secret("")
        assert exc.value.field == "secret"

    def test_secret_too_large(self):
        """Secrets exceeding max bytes should fail."""
        large_secret = "a" * (MAX_SECRET_BYTES + 1)
        with pytest.raises(ValidationError) as exc:
            validate_secret(large_secret)
        assert exc.value.field == "secret"
        assert "too large" in exc.value.message.lower()

    def test_password_max_length(self):
        """Passwords exceeding max length should fail."""
        long_password = "a" * (MAX_PASSWORD_LENGTH + 1)
        with pytest.raises(ValidationError):
            validate_secret(long_password, secret_type="password")

    def test_token_multiline_handling(self):
        """Multi-line tokens should be trimmed to first line."""
        token = "abc123\ndef456"
        result = validate_secret(token, secret_type="token")
        assert result == "abc123"

    def test_token_empty_after_strip(self):
        """Tokens empty after stripping should fail."""
        with pytest.raises(ValidationError):
            validate_secret("\n\n", secret_type="token")

    def test_secret_stripped(self):
        """Secrets should be stripped."""
        result = validate_secret("  mytoken  ", secret_type="token")
        assert result == "mytoken"

    def test_invalid_secret_type(self):
        """Invalid secret type should raise error."""
        with pytest.raises(ValidationError):
            validate_secret("test", secret_type="invalid")


class TestValidateSecretType:
    """Test validate_secret_type function."""

    def test_valid_types(self):
        """Valid types should pass."""
        assert validate_secret_type("password") == "password"
        assert validate_secret_type("token") == "token"
        assert validate_secret_type("ssh") == "ssh"

    def test_invalid_type(self):
        """Invalid types should raise error."""
        with pytest.raises(ValidationError) as exc:
            validate_secret_type("invalid_type")
        assert exc.value.field == "type"
        assert "unknown" in exc.value.message.lower()


class TestValidateSshParts:
    """Test validate_ssh_parts function."""

    def test_valid_ssh_parts(self):
        """Valid SSH parts should return tuple."""
        user, host, port, key = validate_ssh_parts("ubuntu", "example.com", 22)
        assert user == "ubuntu"
        assert host == "example.com"
        assert port == 22
        assert key == ""

    def test_ssh_default_port(self):
        """SSH should default to port 22."""
        _, _, port, _ = validate_ssh_parts("ubuntu", "example.com")
        assert port == 22

    def test_ssh_custom_port(self):
        """SSH should accept custom port."""
        _, _, port, _ = validate_ssh_parts("ubuntu", "example.com", 2222)
        assert port == 2222

    def test_ssh_port_as_string(self):
        """SSH port can be provided as string."""
        _, _, port, _ = validate_ssh_parts("ubuntu", "example.com", "2222")
        assert port == 2222

    def test_ssh_port_invalid(self):
        """Invalid SSH port should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_ssh_parts("ubuntu", "example.com", "not_a_port")
        assert exc.value.field == "port"

    def test_ssh_port_out_of_range(self):
        """SSH port out of range should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_ssh_parts("ubuntu", "example.com", 99999)
        assert exc.value.field == "port"

    def test_ssh_empty_username(self):
        """Empty SSH username should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_ssh_parts("", "example.com")
        assert exc.value.field == "username"

    def test_ssh_username_too_long(self):
        """SSH username over 64 chars should fail."""
        long_user = "a" * 65
        with pytest.raises(ValidationError) as exc:
            validate_ssh_parts(long_user, "example.com")
        assert exc.value.field == "username"

    def test_ssh_username_invalid_chars(self):
        """SSH username with invalid chars should fail."""
        with pytest.raises(ValidationError):
            validate_ssh_parts("bad user!", "example.com")

    def test_ssh_empty_hostname(self):
        """Empty hostname should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_ssh_parts("ubuntu", "")
        assert exc.value.field == "hostname"

    def test_ssh_hostname_too_long(self):
        """Hostname over 253 chars should fail."""
        long_host = "a" * 254
        with pytest.raises(ValidationError) as exc:
            validate_ssh_parts("ubuntu", long_host)
        assert exc.value.field == "hostname"

    def test_ssh_hostname_ip_address(self):
        """SSH should accept IP addresses."""
        _, host, _, _ = validate_ssh_parts("ubuntu", "192.168.1.1")
        assert host == "192.168.1.1"

    def test_ssh_hostname_ipv6(self):
        """SSH should accept IPv6 addresses."""
        _, host, _, _ = validate_ssh_parts("ubuntu", "[::1]")
        assert host == "[::1]"

    def test_ssh_key_path_optional(self):
        """SSH key_path should be optional."""
        _, _, _, key = validate_ssh_parts("ubuntu", "example.com", key_path="")
        assert key == ""

    def test_ssh_key_path_expansion(self):
        """SSH key_path should expand ~."""
        _, _, _, key = validate_ssh_parts("ubuntu", "example.com", key_path="~/.ssh/id_rsa")
        assert "/.ssh/id_rsa" in key

    def test_ssh_key_path_traversal_blocked(self):
        """SSH key_path with .. should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_ssh_parts("ubuntu", "example.com", key_path="../../../etc/passwd")
        assert exc.value.field == "key_path"

    def test_ssh_hostname_strips_trailing_dot(self):
        """Hostname should strip trailing dot."""
        _, host, _, _ = validate_ssh_parts("ubuntu", "example.com.")
        assert host == "example.com"


class TestValidateMasterPassword:
    """Test validate_master_password function."""

    def test_valid_master_password(self):
        """Valid master password should pass."""
        result = validate_master_password("MySecurePassword123")
        assert result == "MySecurePassword123"

    def test_password_too_short(self):
        """Password below min length should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_master_password("short")
        assert exc.value.field == "password"
        assert "at least" in exc.value.message.lower()

    def test_password_too_long(self):
        """Password over max length should fail."""
        long_pass = "a" * (MAX_PASSWORD_LENGTH + 1)
        with pytest.raises(ValidationError) as exc:
            validate_master_password(long_pass)
        assert exc.value.field == "password"

    def test_password_confirmation_match(self):
        """Matching confirmation should pass."""
        result = validate_master_password("MyPassword123", "MyPassword123")
        assert result == "MyPassword123"

    def test_password_confirmation_mismatch(self):
        """Mismatching confirmation should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_master_password("Password1", "Password2")
        assert exc.value.field == "password"
        assert "do not match" in exc.value.message.lower()

    def test_password_preserves_spaces(self):
        """Master password should preserve spaces."""
        p_ass = "My Secure Pass 123"
        result = validate_master_password(p_ass)
        assert result == p_ass


class TestValidateBackupPassword:
    """Test validate_backup_password function."""

    def test_backup_password_same_rules_as_master(self):
        """Backup password should use same rules as master."""
        valid = validate_backup_password("MyPassword123")
        assert valid == "MyPassword123"

    def test_backup_password_with_confirmation(self):
        """Backup password should support confirmation."""
        result = validate_backup_password("MyPassword123", "MyPassword123")
        assert result == "MyPassword123"

    def test_backup_password_too_short(self):
        """Backup password too short should fail."""
        with pytest.raises(ValidationError):
            validate_backup_password("short")


class TestSanitiseSearchQuery:
    """Test sanitise_search_query function."""

    def test_valid_query(self):
        """Valid queries should pass through."""
        assert sanitise_search_query("github") == "github"
        assert sanitise_search_query("api-key-prod") == "api-key-prod"

    def test_query_stripped(self):
        """Queries should be stripped."""
        assert sanitise_search_query("  github  ") == "github"

    def test_query_truncated(self):
        """Queries should be truncated to max length."""
        long_query = "a" * 300
        result = sanitise_search_query(long_query)
        assert len(result) <= 200

    def test_query_custom_max_length(self):
        """Query max length should be customizable."""
        long_query = "a" * 100
        result = sanitise_search_query(long_query, max_length=50)
        assert len(result) == 50

    def test_query_control_chars_removed(self):
        """Control characters should be removed."""
        query = "github\x00\x1f\x7ftest"
        result = sanitise_search_query(query)
        assert "\x00" not in result
        assert "\x1f" not in result
        assert "\x7f" not in result

    def test_query_never_raises(self):
        """sanitise_search_query should handle typical inputs."""
        # Try various valid inputs
        sanitise_search_query("")
        sanitise_search_query("valid query")
        sanitise_search_query("\x00\x01\x02")
        sanitise_search_query(" spaces ")
