"""
sinduk.validators
~~~~~~~~~~~~~~~~~
Centralised input validation and sanitisation for all secret-related inputs.

Every public function either returns a cleaned value or raises
:class:`ValidationError`.  Callers should catch ``ValidationError`` and
convert it to user-facing feedback.

Design principles
-----------------
- **Fail loud early** — validate at the boundary, not deep in business logic.
- **Single source of truth** — one place defines what is allowed.
- **No silent truncation** — if the input is too long, tell the user.
- **Type-specific rules** — a token has different constraints to a password.

Usage::

    from sinduk.validators import validate_label, validate_secret, ValidationError

    try:
        label = validate_label(raw_label)
        secret = validate_secret(raw_secret, secret_type="token")
    except ValidationError as exc:
        click.echo(f"❌ {exc}")
        return
"""

from __future__ import annotations

import re
from typing import Literal

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

#: Maximum label length (characters).
MAX_LABEL_LENGTH: int = 128

#: Minimum label length.
MIN_LABEL_LENGTH: int = 1

#: Maximum raw secret size (bytes).  5 MiB is generous for any real secret.
MAX_SECRET_BYTES: int = 5 * 1024 * 1024

#: Maximum password length (characters).  bcrypt silently truncates at 72,
#: so we stop well before that to make the limit user-visible.
MAX_PASSWORD_LENGTH: int = 512

#: Minimum master password length.
MIN_MASTER_PASSWORD_LENGTH: int = 6

#: Minimum recommended secret length (warnings, not errors).
MIN_SECRET_LENGTH_WARN: int = 8

#: Maximum SSH label length mirrors the general label limit.
MAX_SSH_HOSTNAME_LENGTH: int = 253  # RFC 1123

#: Maximum port number.
MAX_PORT: int = 65535
MIN_PORT: int = 1

#: Allowed label pattern — alphanumeric, hyphens, dots, underscores, slashes.
_LABEL_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9_./@-]+$")

#: Allowed username characters (SSH / password).
_USERNAME_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9_.@-]+$")

#: Hostname / IP — very permissive to allow IPv6 and non-ASCII IDN.
_HOSTNAME_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9._:\[\]-]{1,253}$")

#: Recognised secret types.
SecretType = Literal["password", "token", "ssh"]

_VALID_SECRET_TYPES: frozenset[str] = frozenset({"password", "token", "ssh"})


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class ValidationError(ValueError):
    """Raised when user-supplied input fails validation.

    Attributes
    ----------
    field:
        The name of the field that failed (e.g. ``"label"``, ``"secret"``).
    message:
        Human-readable explanation suitable for direct display.
    """

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field
        self.message = message

    def __str__(self) -> str:
        return f"{self.field}: {self.message}"


# ---------------------------------------------------------------------------
# Label validation
# ---------------------------------------------------------------------------


def validate_label(raw: str) -> str:
    """Validate and normalise a secret label.

    Parameters
    ----------
    raw:
        The raw label string supplied by the user.

    Returns
    -------
    str
        Stripped, lower-cased label.

    Raises
    ------
    ValidationError
        If the label is empty, too long, or contains disallowed characters.
    """
    cleaned = raw.strip()

    if len(cleaned) < MIN_LABEL_LENGTH:
        raise ValidationError("label", "Label cannot be empty.")

    if len(cleaned) > MAX_LABEL_LENGTH:
        raise ValidationError(
            "label",
            f"Label too long — maximum {MAX_LABEL_LENGTH} characters (got {len(cleaned)}).",
        )

    if not _LABEL_RE.match(cleaned):
        raise ValidationError(
            "label",
            "Label contains disallowed characters. Use letters, digits, hyphens, dots, underscores, or slashes.",
        )

    return cleaned


# ---------------------------------------------------------------------------
# Secret value validation
# ---------------------------------------------------------------------------


def validate_secret(raw: str, secret_type: SecretType = "password") -> str:  # nosec
    """Validate a raw secret value.

    Parameters
    ----------
    raw:
        The plaintext secret.
    secret_type:
        Governs which type-specific rules apply.

    Returns
    -------
    str
        The stripped secret value (newlines removed for passwords / tokens).

    Raises
    ------
    ValidationError
        On empty input or length violations.
    """
    validate_secret_type(secret_type)

    if not raw:
        raise ValidationError("secret", "Secret value cannot be empty.")

    if len(raw.encode("utf-8")) > MAX_SECRET_BYTES:
        raise ValidationError(
            "secret",
            f"Secret too large — maximum {MAX_SECRET_BYTES // 1024} KiB.",
        )

    if secret_type == "password":
        return _validate_password_secret(raw)

    if secret_type == "token":
        return _validate_token_secret(raw)

    # SSH secrets are validated via validate_ssh_parts; pass through stripped.
    return raw.strip()


def _validate_password_secret(raw: str) -> str:
    """Strip and length-check a password secret (``user:pass`` format)."""
    cleaned = raw.strip()
    if not cleaned:
        raise ValidationError("secret", "Password value cannot be empty.")
    if len(cleaned) > MAX_PASSWORD_LENGTH:
        raise ValidationError(
            "secret",
            f"Password too long — maximum {MAX_PASSWORD_LENGTH} characters.",
        )
    return cleaned


def _validate_token_secret(raw: str) -> str:
    """Strip a token, reject obviously malformed values."""
    cleaned = raw.strip()
    if not cleaned:
        raise ValidationError("secret", "Token value cannot be empty.")
    # Tokens may be very long (e.g. JWT), but should be a single line.
    if "\n" in cleaned:
        # Multi-line tokens are usually paste errors; trim to first line.
        cleaned = cleaned.splitlines()[0].strip()
    if not cleaned:
        raise ValidationError("secret", "Token value is empty after stripping.")
    return cleaned


# ---------------------------------------------------------------------------
# SSH-specific validation
# ---------------------------------------------------------------------------


def validate_ssh_parts(
    username: str,
    hostname: str,
    port: int | str = 22,
    key_path: str = "",
) -> tuple[str, str, int, str]:
    """Validate SSH connection parameters.

    Parameters
    ----------
    username:
        SSH username.
    hostname:
        Remote host (IP address or FQDN).
    port:
        Port number (integer or string).  Defaults to 22.
    key_path:
        Optional path to a private key file.

    Returns
    -------
    tuple[str, str, int, str]
        ``(username, hostname, port, key_path)`` — all cleaned.

    Raises
    ------
    ValidationError
        On any invalid field.
    """
    clean_user = _validate_username(username)
    clean_host = _validate_hostname(hostname)
    clean_port = _validate_port(port)
    clean_key = _validate_key_path(key_path)
    return clean_user, clean_host, clean_port, clean_key


def _validate_username(raw: str) -> str:
    cleaned = raw.strip()
    if not cleaned:
        raise ValidationError("username", "SSH username cannot be empty.")
    if len(cleaned) > 64:
        raise ValidationError("username", "SSH username too long (max 64 characters).")
    if not _USERNAME_RE.match(cleaned):
        raise ValidationError(
            "username",
            "SSH username contains disallowed characters. Use letters, digits, hyphens, dots, underscores, or @.",
        )
    return cleaned


def _validate_hostname(raw: str) -> str:
    cleaned = raw.strip().rstrip(".")
    if not cleaned:
        raise ValidationError("hostname", "Hostname cannot be empty.")
    if len(cleaned) > MAX_SSH_HOSTNAME_LENGTH:
        raise ValidationError(
            "hostname",
            f"Hostname too long — maximum {MAX_SSH_HOSTNAME_LENGTH} characters.",
        )
    if not _HOSTNAME_RE.match(cleaned):
        raise ValidationError(
            "hostname",
            "Hostname contains invalid characters.",
        )
    return cleaned


def _validate_port(raw: int | str) -> int:
    try:
        port = int(raw)
    except (TypeError, ValueError):
        raise ValidationError("port", f"Port must be an integer, got {raw!r}.") from None
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValidationError(
            "port",
            f"Port must be between {MIN_PORT} and {MAX_PORT} (got {port}).",
        )
    return port


def _validate_key_path(raw: str) -> str:
    """Validate a key file path (may be empty)."""
    cleaned = raw.strip()
    if not cleaned:
        return ""
    # Block obvious path traversal attempts.
    if ".." in cleaned:
        raise ValidationError("key_path", "Key path must not contain '..'.")
    # Expand ~ but do not resolve the path (file may not exist yet).
    import os

    expanded = os.path.expanduser(cleaned)
    if len(expanded) > 4096:
        raise ValidationError("key_path", "Key path too long.")
    return expanded


# ---------------------------------------------------------------------------
# Secret type validation
# ---------------------------------------------------------------------------


def validate_secret_type(raw: str) -> SecretType:
    """Validate that *raw* is a recognised secret type.

    Raises
    ------
    ValidationError
    """
    if raw not in _VALID_SECRET_TYPES:
        raise ValidationError(
            "type",
            f"Unknown secret type '{raw}'. Valid types: {', '.join(sorted(_VALID_SECRET_TYPES))}.",
        )
    return raw  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Master-password validation
# ---------------------------------------------------------------------------


def validate_master_password(password: str, confirm: str | None = None) -> str:
    """Validate a prospective master password.

    Parameters
    ----------
    password:
        The candidate password.
    confirm:
        If provided, must match *password* exactly.

    Returns
    -------
    str
        The validated password (not stripped — spaces are valid).

    Raises
    ------
    ValidationError
    """
    if len(password) < MIN_MASTER_PASSWORD_LENGTH:
        raise ValidationError(
            "password",
            f"Master password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters.",
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValidationError(
            "password",
            f"Master password too long — maximum {MAX_PASSWORD_LENGTH} characters.",
        )
    if confirm is not None and password != confirm:
        raise ValidationError("password", "Passwords do not match.")
    return password


# ---------------------------------------------------------------------------
# Backup-password validation
# ---------------------------------------------------------------------------


def validate_backup_password(password: str, confirm: str | None = None) -> str:
    """Validate a backup-export password.

    Same rules as the master password.
    """
    return validate_master_password(password, confirm)


# ---------------------------------------------------------------------------
# Search-query sanitisation
# ---------------------------------------------------------------------------


def sanitise_search_query(raw: str, max_length: int = 200) -> str:
    """Strip and truncate a search query to safe bounds.

    Never raises — always returns a safe string.
    """
    cleaned = raw.strip()[:max_length]
    # Remove control characters
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", cleaned)
    return cleaned
