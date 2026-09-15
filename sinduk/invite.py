"""
Zero-knowledge invite and onboarding link helper for Sinduk team vaults.

Invite links embed cryptographic key material in URL fragments (#key=...)
so plaintext key derivation material is never sent across HTTP to the server.
"""

import json
import base64
import time
import secrets
from urllib.parse import urlparse
from .log import get_logger

logger = get_logger("sinduk.invite")


def generate_invite_url(
    server_url: str,
    vault_name: str,
    vault_key_b64: str,
    role: str = "editor",
    expires_in_hours: int = 48,
    invited_by: str = "",
) -> str:
    """
    Generate an invite onboarding link.

    Format:
        https://<server>/join?token=<payload_b64>#key=<vault_key_b64>

    The #key fragment is handled client-side and never transmitted in the HTTP request.
    """
    now = int(time.time())
    expires_at = now + (expires_in_hours * 3600)
    invite_id = secrets.token_urlsafe(16)

    payload = {
        "invite_id": invite_id,
        "vault": vault_name.strip().lower(),
        "role": role,
        "invited_by": invited_by,
        "created_at": now,
        "expires_at": expires_at,
    }
    payload_json = json.dumps(payload, separators=(",", ":"))
    token_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("ascii").rstrip("=")

    parsed = urlparse(server_url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
    return f"{base}/join?token={token_b64}#key={vault_key_b64}"


def parse_invite_token(token_b64: str) -> dict | None:
    """Parse and validate an invite token payload."""
    try:
        # Add padding back if necessary
        padded = token_b64 + "=" * (-len(token_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
        payload = json.loads(payload_bytes.decode("utf-8"))

        now = int(time.time())
        if payload.get("expires_at", 0) < now:
            logger.warning(f"Invite token expired at {payload.get('expires_at')} (now {now})")
            return None

        return payload
    except Exception as e:
        logger.warning(f"Failed to parse invite token: {e}")
        return None
