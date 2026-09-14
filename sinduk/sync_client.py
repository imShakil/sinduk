"""
Client helper functions for syncing with a self-hosted sinduk server.
"""

import os
import json
import urllib.parse
import requests  # type: ignore
from .log import get_logger

logger = get_logger("sinduk.sync_client")

SYNC_CONFIG_PATH = os.path.expanduser("~/.config/sinduk/sync_config.json")


def get_sync_config() -> dict:
    """Read local sync configuration (default server URL and token)."""
    if os.path.exists(SYNC_CONFIG_PATH):
        try:
            with open(SYNC_CONFIG_PATH, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.debug(f"Failed to read sync config: {e}")
    return {}


def set_sync_config(server_url: str | None = None, token: str | None = None) -> dict:
    """Save local sync configuration."""
    config = get_sync_config()
    if server_url is not None:
        config["server_url"] = server_url.rstrip("/")
    if token is not None:
        config["token"] = token

    os.makedirs(os.path.dirname(SYNC_CONFIG_PATH), exist_ok=True)
    with open(SYNC_CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)
    return config


def resolve_server_params(server_url: str | None = None, token: str | None = None) -> tuple[str | None, str | None]:
    """
    Resolve server_url and token using:
    1. Explicit arguments
    2. Environment variables (SINDUK_SYNC_SERVER/PACLI_SYNC_SERVER, SINDUK_SYNC_TOKEN/PACLI_SYNC_TOKEN)
    3. Saved config (~/.config/sinduk/sync_config.json)
    """
    config = get_sync_config()

    res_server: str | None = server_url
    res_token: str | None = token

    if not res_server:
        server_env = os.environ.get("SINDUK_SYNC_SERVER") or os.environ.get("PACLI_SYNC_SERVER")
        res_server = server_env or config.get("server_url")
    if not res_token:
        token_env = os.environ.get("SINDUK_SYNC_TOKEN") or os.environ.get("PACLI_SYNC_TOKEN")
        res_token = token_env or config.get("token")

    if res_server:
        res_server = res_server.rstrip("/")

    return res_server, res_token


def _build_api_url(server_url: str, endpoint: str, vault_name: str) -> str:
    """Validate server URL and safely construct API endpoint."""
    parsed = urllib.parse.urlparse(server_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Invalid server URL: '{server_url}'. Must start with http:// or https://")
    clean_vault = urllib.parse.quote(vault_name, safe="")
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
    return f"{base}/api/v1/sync/{endpoint}/{clean_vault}"


def push_to_server(vault_name: str, blob_bytes: bytes, server_url: str, token: str, user_name: str = "") -> dict:
    """
    Push encrypted vault blob to the sync server.

    Returns:
        {"version": int, "checksum": str, "updated": bool}
    """
    url = _build_api_url(server_url, "push", vault_name)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/octet-stream",
    }
    if user_name:
        headers["X-Pacli-User"] = user_name

    resp = requests.post(url, data=blob_bytes, headers=headers, timeout=30)
    if resp.status_code == 200:
        return resp.json()
    try:
        err = resp.json().get("error", resp.text)
    except Exception:
        err = resp.text
    raise RuntimeError(f"Server push failed ({resp.status_code}): {err}")


def pull_from_server(
    vault_name: str, server_url: str, token: str, if_none_match: str = ""
) -> tuple[bytes | None, dict]:
    """
    Pull latest encrypted vault blob from the sync server.

    Returns:
        (blob_bytes, headers_dict)
    """
    url = _build_api_url(server_url, "pull", vault_name)
    headers = {
        "Authorization": f"Bearer {token}",
    }
    if if_none_match:
        headers["If-None-Match"] = if_none_match

    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 200:
        meta = {
            "version": resp.headers.get("X-Vault-Version"),
            "checksum": resp.headers.get("X-Vault-Checksum"),
            "updated_by": resp.headers.get("X-Vault-Updated-By"),
            "updated_at": resp.headers.get("X-Vault-Updated-At"),
        }
        return resp.content, meta
    if resp.status_code == 304:
        return None, {"not_modified": True}

    try:
        err = resp.json().get("error", resp.text)
    except Exception:
        err = resp.text
    raise RuntimeError(f"Server pull failed ({resp.status_code}): {err}")


def get_server_status(vault_name: str, server_url: str, token: str) -> dict:
    """Check status of a vault on the sync server."""
    url = _build_api_url(server_url, "status", vault_name)
    headers = {
        "Authorization": f"Bearer {token}",
    }
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code == 200:
        return resp.json()
    try:
        err = resp.json().get("error", resp.text)
    except Exception:
        err = resp.text
    raise RuntimeError(f"Server status check failed ({resp.status_code}): {err}")
