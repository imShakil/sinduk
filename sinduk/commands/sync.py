"""
CLI commands for vault sync — push/pull encrypted vault data to shared locations or a self-hosted sinduk server.
"""

import os
import time
import click
from getpass import getpass
from ..store import SecretStore
from ..vault import VaultManager, get_user_identity
from ..sync_client import (
    get_sync_config,
    set_sync_config,
    resolve_server_params,
    push_to_server,
    pull_from_server,
    get_server_status,
)
from ..log import get_logger
from ..decorators import master_password_required

logger = get_logger("sinduk.commands.sync")
NO_TOKEN_MSG = "❌ Server URL configured but no access token provided."
NO_MASTER_KEY_MSG = "❌ Master key is not loaded."


@click.group()
def sync():
    """🔄 Sync vaults — push and pull encrypted vault backups to shared paths or a self-hosted server."""
    pass


# ------------------------------------------------------------------
# Config Subgroup
# ------------------------------------------------------------------


@sync.group("config")
def config_group():
    """Configure default sync server settings."""
    pass


@config_group.command("set")
@click.option("--server", "-s", "server_url", help="Sync server URL (e.g. https://sinduk.example.com:58380).")
@click.option("--token", "-t", "token", help="Bearer token for the sync server.")
def sync_config_set(server_url, token):
    """Save default sync server URL and token."""
    if not server_url and not token:
        click.echo("❌ Please provide at least one of --server or --token.")
        return

    cfg = set_sync_config(server_url=server_url, token=token)
    click.echo("✅ Sync configuration updated.")
    if cfg.get("server_url"):
        click.echo(f"   Server: {cfg['server_url']}")
    if cfg.get("token"):
        masked = cfg["token"][:8] + "…" if len(cfg["token"]) > 8 else "…"
        click.echo(f"   Token:  {masked}")


@config_group.command("show")
def sync_config_show():
    """Display the currently saved sync configuration."""
    cfg = get_sync_config()
    if not cfg:
        click.echo("📭 No sync configuration saved. Use 'sinduk sync config set --server ... --token ...'")
        return

    click.echo("📋 Saved Sync Configuration:")
    click.echo(f"   Server: {cfg.get('server_url', '—')}")
    token = cfg.get("token", "")
    if len(token) > 16:
        masked = token[:12] + "..."
    elif token:
        masked = "(set)"
    else:
        masked = "—"
    click.echo(f"   Token:  {masked}")


# ------------------------------------------------------------------
# Push / Pull / Status Helpers
# ------------------------------------------------------------------


def _pull_from_server_handler(vault_name: str, server_url: str, token: str, store_fernet, overwrite: bool):
    """Handle pulling and importing a vault from a sync server."""
    click.echo(f"☁️ Pulling vault '{vault_name}' from {server_url}...")
    try:
        blob, meta = pull_from_server(vault_name, server_url, token)
        if meta.get("not_modified") or blob is None:
            click.echo("✅ Vault is already up-to-date (no changes on server).")
            return

        vm = VaultManager()
        stats = vm.import_vault_backup(vault_name, blob, token, store_fernet, merge=not overwrite)

        v_str = f"v{meta['version']}" if meta.get("version") else ""
        by_str = f"by {meta['updated_by']}" if meta.get("updated_by") else ""
        click.echo(
            f"✅ Pulled vault '{vault_name}' {v_str} {by_str}: "
            f"{stats['imported']} imported, {stats['skipped']} skipped."
        )
        logger.info(f"Pulled vault '{vault_name}' from server: {stats}")
    except Exception as e:
        click.echo(f"❌ Server pull failed: {e}")
        logger.error(f"Server pull error: {e}")


def _pull_from_filesystem_handler(
    vault_name: str, source_path: str, sync_password: str | None, store_fernet, overwrite: bool
):
    """Handle pulling and importing a vault from a filesystem directory."""
    source_path = os.path.expanduser(source_path)
    filename = f"{vault_name}.sinduk"
    filepath = os.path.join(source_path, filename)

    if not os.path.exists(filepath):
        legacy_filename = f"{vault_name}.pacli"
        legacy_filepath = os.path.join(source_path, legacy_filename)
        if os.path.exists(legacy_filepath):
            filename = legacy_filename
            filepath = legacy_filepath
        else:
            click.echo(f"❌ File not found: {filepath}")
            click.echo(f"   Expected a file named '{filename}' in {source_path}")
            return

    if not sync_password:
        sync_password = getpass("Sync password: ")

    try:
        with open(filepath, "rb") as f:
            blob = f.read()

        vm = VaultManager()
        stats = vm.import_vault_backup(vault_name, blob, sync_password, store_fernet, merge=not overwrite)

        click.echo(
            f"✅ Pulled vault '{vault_name}': {stats['imported']} imported, "
            f"{stats['skipped']} skipped, {stats['errors']} errors."
        )
        logger.info(f"Vault '{vault_name}' pulled from {filepath}: {stats}")
    except ValueError as e:
        click.echo(f"❌ {e}")
    except Exception as e:
        click.echo(f"❌ Pull failed: {e}")
        logger.error(f"Sync pull failed: {e}")


def _push_to_server_handler(vault_name: str, server_url: str, token: str, store_fernet):
    click.echo(f"☁️ Pushing vault '{vault_name}' to {server_url}...")
    vm = VaultManager()
    try:
        blob = vm.export_vault_backup(vault_name, token, store_fernet)
        identity = get_user_identity()
        user_name = identity.get("user_name", "")
        res = push_to_server(vault_name, blob, server_url, token, user_name=user_name)
        if res.get("updated"):
            click.echo(f"✅ Pushed vault '{vault_name}' (version {res['version']}) to server successfully!")
        else:
            click.echo(f"ℹ️ Vault '{vault_name}' is already up-to-date on server (version {res['version']}).")
        logger.info(f"Pushed vault '{vault_name}' to server: {res}")
    except Exception as e:
        click.echo(f"❌ Server push failed: {e}")
        logger.error(f"Server push error: {e}")


def _push_to_filesystem_handler(vault_name: str, target_path: str, sync_password: str | None, store_fernet):
    target_path = os.path.expanduser(target_path)
    os.makedirs(target_path, exist_ok=True)

    if not sync_password:
        sync_password = getpass("Sync password (used to encrypt the file for transit): ")
        confirm_pass = getpass("Confirm sync password: ")
        if sync_password != confirm_pass:
            click.echo("❌ Passwords do not match.")
            return

    vm = VaultManager()
    try:
        blob = vm.export_vault_backup(vault_name, sync_password, store_fernet)
        filename = f"{vault_name}.sinduk"
        filepath = os.path.join(target_path, filename)

        with open(filepath, "wb") as f:
            f.write(blob)

        click.echo(f"✅ Pushed vault '{vault_name}' to: {filepath}")
        click.echo(f"   File size: {len(blob)} bytes (encrypted)")
        logger.info(f"Vault '{vault_name}' exported to {filepath}")
    except (ValueError, PermissionError) as e:
        click.echo(f"❌ {e}")
    except Exception as e:
        click.echo(f"❌ Export failed: {e}")
        logger.error(f"Sync export failed: {e}")


def _status_server_handler(vault_name: str, server_url: str, token: str):
    try:
        status = get_server_status(vault_name, server_url, token)
        size_kb = (status.get("size") or 0) / 1024
        mod_time = (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(status["updated_at"]))
            if status.get("updated_at")
            else "—"
        )
        click.echo(f"📦 Server status for vault '{vault_name}':")
        click.echo(f"   Server:     {server_url}")
        click.echo(f"   Version:    {status.get('version', 1)}")
        click.echo(f"   Size:       {size_kb:.1f} KB")
        click.echo(f"   Updated by: {status.get('updated_by', '—')}")
        click.echo(f"   Modified:   {mod_time}")
        click.echo(f"\n   To pull: sinduk sync pull {vault_name}")
    except Exception as e:
        click.echo(f"❌ Server status check failed: {e}")


def _status_filesystem_handler(vault_name: str, sync_path: str):
    sync_path = os.path.expanduser(sync_path)
    filepath = os.path.join(sync_path, f"{vault_name}.sinduk")

    if not os.path.exists(filepath):
        legacy_filepath = os.path.join(sync_path, f"{vault_name}.pacli")
        if os.path.exists(legacy_filepath):
            filepath = legacy_filepath
        else:
            click.echo(f"📭 No sync file found for vault '{vault_name}' at {sync_path}")
            return

    stat = os.stat(filepath)
    size_kb = stat.st_size / 1024
    mod_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime))

    click.echo(f"📦 Sync file for vault '{vault_name}':")
    click.echo(f"   Path:     {filepath}")
    click.echo(f"   Size:     {size_kb:.1f} KB")
    click.echo(f"   Modified: {mod_time}")
    click.echo(f"\n   To pull: sinduk sync pull {vault_name} --from {sync_path}")


# ------------------------------------------------------------------
# Push / Pull / Status Commands
# ------------------------------------------------------------------


@sync.command("push")
@click.argument("vault_name")
@click.option("--to", "-t", "target_path", default=None, help="Destination directory path (e.g. ~/Dropbox/pacli/).")
@click.option("--server", "-s", "server_url", default=None, help="Sync server URL (overrides saved config).")
@click.option("--token", "token", default=None, help="Sync server token (overrides saved config).")
@click.option(
    "--password", "-p", "sync_password", default=None, help="Password for file export (not needed for server)."
)
@master_password_required
def sync_push(vault_name, target_path, server_url, token, sync_password):
    """
    Push an encrypted vault backup to a shared path or sync server.

    Examples:
        # Push to self-hosted server
        sinduk sync push team-infra

        # Push to specific server with token
        sinduk sync push team-infra --server http://192.168.1.50:58380 --token <tok>

        # Push to filesystem folder
        sinduk sync push team-infra --to ~/Dropbox/sinduk/
    """
    store = SecretStore()
    store.require_fernet()
    if store.fernet is None:
        click.echo(NO_MASTER_KEY_MSG)
        return
    fernet = store.fernet

    server_url, token = resolve_server_params(server_url, token)

    # Server mode
    if server_url and not target_path:
        if not token:
            click.echo(NO_TOKEN_MSG)
            click.echo("   Use --token <tok> or 'sinduk sync config set --token <tok>'.")
            return

        _push_to_server_handler(vault_name, server_url, token, fernet)
        return

    # Filesystem mode
    if not target_path:
        click.echo("❌ Please specify --to <directory_path> or configure a sync server with 'sinduk sync config set'.")
        return

    _push_to_filesystem_handler(vault_name, target_path, sync_password, fernet)


@sync.command("pull")
@click.argument("vault_name")
@click.option(
    "--from", "-f", "source_path", default=None, help="Source directory path containing the .sinduk or .pacli file."
)
@click.option("--server", "-s", "server_url", default=None, help="Sync server URL (overrides saved config).")
@click.option("--token", "token", default=None, help="Sync server token (overrides saved config).")
@click.option(
    "--password", "-p", "sync_password", default=None, help="Password for file import (not needed for server)."
)
@click.option("--overwrite", is_flag=True, default=False, help="Overwrite existing secrets (default: skip duplicates).")
@master_password_required
def sync_pull(vault_name, source_path, server_url, token, sync_password, overwrite):
    """
    Pull and import an encrypted vault backup from a shared path or sync server.

    Examples:
        # Pull from server
        sinduk sync pull team-infra

        # Pull from filesystem folder
        sinduk sync pull team-infra --from ~/Dropbox/sinduk/
    """
    store = SecretStore()
    store.require_fernet()
    if store.fernet is None:
        click.echo(NO_MASTER_KEY_MSG)
        return
    fernet = store.fernet

    server_url, token = resolve_server_params(server_url, token)

    if server_url and not source_path:
        if not token:
            click.echo(NO_TOKEN_MSG)
            return
        _pull_from_server_handler(vault_name, server_url, token, fernet, overwrite)
        return

    if not source_path:
        click.echo(
            "❌ Please specify --from <directory_path> or configure a sync server with 'sinduk sync config set'."
        )
        return

    _pull_from_filesystem_handler(vault_name, source_path, sync_password, fernet, overwrite)


@sync.command("status")
@click.argument("vault_name")
@click.option("--path", "-p", "sync_path", default=None, help="Sync directory path.")
@click.option("--server", "-s", "server_url", default=None, help="Sync server URL.")
@click.option("--token", "token", default=None, help="Sync server token.")
def sync_status(vault_name, sync_path, server_url, token):
    """Check if a vault has updates available at the sync path or server."""
    server_url, token = resolve_server_params(server_url, token)

    # Server mode
    if server_url and not sync_path:
        if not token:
            click.echo(NO_TOKEN_MSG)
            return
        _status_server_handler(vault_name, server_url, token)
        return

    # Filesystem mode
    if not sync_path:
        click.echo(
            "❌ Please specify --path <directory_path> or configure a sync server with 'sinduk sync config set'."
        )
        return

    _status_filesystem_handler(vault_name, sync_path)
