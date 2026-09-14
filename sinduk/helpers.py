import click
import datetime
import json
import secrets
import string
import pyperclip
from .log import get_logger

logger = get_logger("sinduk.helpers")


def choice_one(label, matches):
    """Helper function to select one secret from multiple matches."""
    click.echo(f"Multiple secrets found for label '{label}':")
    for idx, s in enumerate(matches, 1):
        cstr = (
            datetime.datetime.fromtimestamp(s["creation_time"]).strftime("%Y-%m-%d %H:%M:%S")
            if s["creation_time"]
            else ""
        )
        ustr = (
            datetime.datetime.fromtimestamp(s["update_time"]).strftime("%Y-%m-%d %H:%M:%S") if s["update_time"] else ""
        )
        click.echo(f"[{idx}] ID: {s['id']}  Type: {s['type']}  Created: {cstr}  Updated: {ustr}")
    while True:
        choice = click.prompt("Select which secret to retrieve (number)", type=int)
        if 1 <= choice <= len(matches):
            selected = matches[choice - 1]
            break
        click.echo("Invalid selection. Try again.")
    return selected


def copy_to_clipboard(secret):
    """Copy text to clipboard."""
    try:
        pyperclip.copy(secret)
        click.echo("📋 Secret copied to clipboard.")
    except ImportError:
        click.echo("❌ pyperclip is not installed. Run 'pip install pyperclip' to enable clipboard support.")
    except Exception as e:
        click.echo(f"❌ Failed to copy to clipboard: {e}")


def generate_secure_password(length: int = 20) -> str:
    """Generate a cryptographically secure random password with mixed characters."""
    if length < 8:
        length = 8
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}<>?"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_sym = any(c in "!@#$%^&*()-_=+[]{}<>?" for c in pwd)
        if has_lower and has_upper and has_digit and has_sym:
            return pwd


def _parse_legacy_password(raw_str: str) -> dict:
    """Parse legacy password format: username:password or username:password|domain:example.com."""
    domain = ""
    user_pass = raw_str
    if "|domain:" in raw_str:
        parts = raw_str.split("|domain:", 1)
        user_pass = parts[0]
        domain = parts[1].strip()

    if ":" in user_pass:
        parts = user_pass.split(":", 1)
        return {
            "username": parts[0],
            "password": parts[1],
            "domain": domain,
        }
    return {
        "username": "",
        "password": user_pass,
        "domain": domain,
    }


def _parse_legacy_ssh(raw_str: str) -> dict:
    """Parse legacy SSH format: user:host|key:path|port:22|opts:-o..."""
    parts = raw_str.split("|")
    user_host = parts[0]
    user, host = "", user_host
    if ":" in user_host:
        u_parts = user_host.split(":", 1)
        user, host = u_parts[0], u_parts[1]
    elif "@" in user_host:
        u_parts = user_host.split("@", 1)
        user, host = u_parts[0], u_parts[1]

    port = 22
    key_path = ""
    opts = ""
    password = ""

    for part in parts[1:]:
        if part.startswith("key:"):
            key_path = part[4:]
        elif part.startswith("port:"):
            try:
                port = int(part[5:])
            except ValueError:
                port = 22
        elif part.startswith("opts:"):
            opts = part[5:]
        elif part.startswith("pass:"):
            password = part[5:]

    return {
        "user": user,
        "host": host,
        "port": port,
        "key_path": key_path,
        "opts": opts,
        "password": password,
    }


def parse_secret_payload(raw: str, secret_type: str = "password") -> dict:  # nosec B107
    """
    Parse a raw secret payload into a structured dictionary.
    Handles both modern JSON serialization and legacy delimited formats.
    """
    if not raw:
        return {}

    raw_str = raw.strip()

    # Try JSON parsing first
    if raw_str.startswith("{") and raw_str.endswith("}"):
        try:
            data = json.loads(raw_str)
            if isinstance(data, dict):
                return data
        except (ValueError, TypeError):
            pass  # nosec B110

    if secret_type == "password":
        return _parse_legacy_password(raw_str)

    if secret_type == "ssh":
        return _parse_legacy_ssh(raw_str)

    # Default / token type
    return {"token": raw_str}


def serialize_password_secret(username: str, password: str, domain: str = "") -> str:
    """Serialize password credentials into a structured JSON string."""
    return json.dumps(
        {
            "username": username.strip() if username else "",
            "password": password,
            "domain": domain.strip() if domain else "",
        }
    )


def serialize_ssh_secret(
    user: str,
    host: str,
    port: int = 22,
    key_path: str = "",
    opts: str = "",
    password: str = "",  # nosec B107
) -> str:
    """Serialize SSH connection information into a structured JSON string."""
    return json.dumps(
        {
            "user": user.strip() if user else "",
            "host": host.strip() if host else "",
            "port": port,
            "key_path": key_path.strip() if key_path else "",
            "opts": opts.strip() if opts else "",
            "password": password if password else "",
        }
    )
