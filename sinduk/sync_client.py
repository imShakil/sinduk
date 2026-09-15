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


def set_sync_config(
    server_url: str | None = None,
    token: str | None = None,
    clear: bool = False,
) -> dict:
    """Save local sync configuration."""
    config = {} if clear else get_sync_config()
    if server_url is not None:
        if server_url == "":
            config.pop("server_url", None)
        else:
            config["server_url"] = server_url.rstrip("/")
    if token is not None:
        if token == "":
            config.pop("token", None)
        else:
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


def _normalize_and_validate_server_url(server_url: str) -> tuple[str | None, str | None]:
    """Validate server URL format and return the normalized base URL or an error message."""
    if not server_url:
        return None, "Server URL is required."
    parsed = urllib.parse.urlparse(server_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return (
            None,
            f"Invalid URL format: '{server_url}'.Must start with http:// or https:// (e.g. http://sinduk.example.com)",
        )
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}", None


def _check_server_connectivity(base_url: str, timeout: int) -> str | None:
    """Perform health check on server. Returns error string if unsuccessful, None if connected."""
    try:
        resp = requests.get(f"{base_url}/health", timeout=timeout)
        if resp.status_code != 200:
            return f"Server responded with HTTP {resp.status_code} at {base_url}/health."
        return None
    except requests.exceptions.RequestException as e:
        return f"Could not connect to sync server at {base_url}: {e}"


def _verify_server_token(base_url: str, token: str, timeout: int) -> tuple[bool, dict | None, str | None]:
    """
    Verify bearer token validity against the server.
    Returns (token_valid, token_info, error_message).
    """
    try:
        auth_resp = requests.get(
            f"{base_url}/api/v1/auth/verify",
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )
        if auth_resp.status_code == 200:
            return True, auth_resp.json(), None
        if auth_resp.status_code in (401, 403):
            return False, None, "Server connected, but the provided token was rejected (invalid or revoked)."
        if auth_resp.status_code == 404:
            # Fallback check against a protected endpoint on older/running server versions
            ping_resp = requests.get(
                f"{base_url}/api/v1/sync/status/_ping_",
                headers={"Authorization": f"Bearer {token}"},
                timeout=timeout,
            )
            if ping_resp.status_code in (401, 403):
                return False, None, "Server connected, but the provided token was rejected (invalid or revoked)."
            return True, None, None
        return True, None, None
    except requests.exceptions.RequestException as e:
        logger.debug(f"Auth verify request failed: {e}")
        return True, None, None


def validate_sync_server(server_url: str, token: str | None = None, timeout: int = 4) -> dict:
    """
    Actively validate server connectivity and bearer token.

    Returns:
        {
            "ok": bool,
            "connected": bool,
            "token_valid": bool | None,
            "token_info": dict | None,
            "error": str | None,
        }
    """
    base, err = _normalize_and_validate_server_url(server_url)
    if err or not base:
        return {"ok": False, "connected": False, "error": err or "Server URL is required."}

    conn_err = _check_server_connectivity(base, timeout=timeout)
    if conn_err:
        return {"ok": False, "connected": False, "error": conn_err}

    token_info = None
    token_valid = None
    if token:
        token_valid, token_info, token_err = _verify_server_token(base, token, timeout=timeout)
        if token_err:
            return {
                "ok": False,
                "connected": True,
                "token_valid": False,
                "error": token_err,
            }

    return {
        "ok": True,
        "connected": True,
        "token_valid": token_valid,
        "token_info": token_info,
        "error": None,
    }


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


def auto_push_vault(vault_name: str, store_fernet) -> dict:
    """
    Attempt to push the vault to the configured sync server automatically in the background.

    Returns:
        {"synced": True, "version": int, "checksum": str, "updated": bool}
        or {"synced": False, "reason": "no_config" | "error", "error": str}
    """
    server_url, token = resolve_server_params()
    if not server_url or not token:
        return {"synced": False, "reason": "no_config"}

    try:
        import time
        from .vault import VaultManager, get_user_identity

        vm = VaultManager()
        blob = vm.export_vault_backup(vault_name, token, store_fernet)
        identity = get_user_identity()
        user_name = identity.get("user_name", "")
        res = push_to_server(vault_name, blob, server_url, token, user_name=user_name)
        vm.update_sync_status(
            vault_name,
            last_push_at=int(time.time()),
            last_push_version=res.get("version"),
            last_push_checksum=res.get("checksum"),
        )
        return {
            "synced": True,
            "version": res.get("version"),
            "checksum": res.get("checksum"),
            "updated": res.get("updated", True),
        }
    except Exception as e:
        logger.warning(f"Auto-push failed for vault '{vault_name}': {e}")
        return {"synced": False, "reason": "error", "error": str(e)}


def auto_pull_vault(vault_name: str, store_fernet, overwrite: bool = False) -> dict:
    """
    Attempt to pull latest changes for the vault from the configured sync server automatically.

    Returns:
        {"synced": True, "imported": int, "skipped": int, "version": int}
        or {"synced": False, "reason": "no_config" | "up_to_date" | "error", "error": str}
    """
    server_url, token = resolve_server_params()
    if not server_url or not token:
        return {"synced": False, "reason": "no_config"}

    try:
        import time
        from .vault import VaultManager

        vm = VaultManager()
        local_st = vm.get_sync_status(vault_name) or {}
        local_checksum = local_st.get("last_pull_checksum") or local_st.get("last_push_checksum") or ""

        blob, meta = pull_from_server(vault_name, server_url, token, if_none_match=local_checksum)
        if meta.get("not_modified") or blob is None:
            return {"synced": True, "up_to_date": True, "version": local_st.get("last_pull_version")}

        stats = vm.import_vault_backup(vault_name, blob, token, store_fernet, merge=not overwrite)
        vm.update_sync_status(
            vault_name,
            last_pull_at=int(time.time()),
            last_pull_version=meta.get("version"),
            last_pull_checksum=meta.get("checksum"),
        )
        return {
            "synced": True,
            "imported": stats.get("imported", 0),
            "skipped": stats.get("skipped", 0),
            "version": meta.get("version"),
        }
    except Exception as e:
        logger.warning(f"Auto-pull failed for vault '{vault_name}': {e}")
        return {"synced": False, "reason": "error", "error": str(e)}
