"""
CLI commands for managing the self-hosted sinduk sync server.
"""

import click
import os
import sys
import json
import signal
import subprocess  # nosec B404
import time
from ..server import create_sync_server_app, SyncServerDB, SERVER_DIR
from ..log import get_logger

logger = get_logger("sinduk.server_cli")

SERVER_PID_PATH = os.path.join(SERVER_DIR, "server.pid")
SERVER_STATE_PATH = os.path.join(SERVER_DIR, "server_state.json")
SERVER_LOG_PATH = os.path.join(SERVER_DIR, "server.log")
DEFAULT_HOST = "0.0.0.0"  # nosec B104
DEFAULT_PORT = 58380


def _is_pid_running(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _get_pid_from_file():
    if not os.path.exists(SERVER_PID_PATH):
        return None
    try:
        with open(SERVER_PID_PATH, "r") as f:
            pid_text = f.read().strip()
        if not pid_text.isdigit():
            return None
        return int(pid_text)
    except Exception:
        return None


def _clean_stale_pid():
    if os.path.exists(SERVER_PID_PATH):
        try:
            os.remove(SERVER_PID_PATH)
        except OSError:
            pass


def _format_server_url(host: str, port: int) -> str:
    scheme = "https" if port in (443, 8443) else "http"
    return f"{scheme}://{host}:{port}"


def _write_state(pid, host, port):
    os.makedirs(SERVER_DIR, exist_ok=True)
    with open(SERVER_PID_PATH, "w") as f:
        f.write(str(pid))
    state = {
        "pid": pid,
        "host": host,
        "port": port,
        "url": _format_server_url(host, port),
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(SERVER_STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)


def _read_state():
    if not os.path.exists(SERVER_STATE_PATH):
        return None
    try:
        with open(SERVER_STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return None


def _clear_state():
    _clean_stale_pid()
    if os.path.exists(SERVER_STATE_PATH):
        try:
            os.remove(SERVER_STATE_PATH)
        except OSError:
            pass


@click.group()
def server():
    """🖥️ Self-hosted zero-knowledge sync server for team collaboration."""
    pass


@server.command("start")
@click.option("--host", "-h", default=DEFAULT_HOST, show_default=True, help="Host to bind the server to.")
@click.option("--port", "-p", default=DEFAULT_PORT, show_default=True, type=int, help="Port to listen on.")
@click.option("--daemon/--no-daemon", "-d/-f", default=False, help="Run as background daemon process.")
def server_start(host, port, daemon):
    """Start the sinduk sync server."""
    pid = _get_pid_from_file()
    if pid and _is_pid_running(pid):
        state = _read_state() or {}
        url = state.get("url", _format_server_url(host, port))
        click.echo(f"⚠️ Sync server is already running (PID: {pid}) at {url}")
        return

    _clean_stale_pid()

    if daemon:
        os.makedirs(SERVER_DIR, exist_ok=True)
        log_file = open(SERVER_LOG_PATH, "a")

        cmd = [sys.executable, "-m", "sinduk.commands.server", "_internal_run", "--host", host, "--port", str(port)]
        proc = subprocess.Popen(  # nosec B603
            cmd,
            stdout=log_file,
            stderr=log_file,
            start_new_session=True,
            close_fds=True,
        )

        _write_state(proc.pid, host, port)
        time.sleep(0.5)

        if not _is_pid_running(proc.pid):
            click.echo("❌ Server failed to start. Check logs at: " + SERVER_LOG_PATH)
            _clear_state()
            return

        click.echo(f"🚀 Sync server started in background (PID: {proc.pid})")
        click.echo(f"   URL:  {_format_server_url(host, port)}")
        click.echo(f"   Logs: {SERVER_LOG_PATH}")
        click.echo("\n💡 Create a team token with: sinduk server token create --name 'DevTeam'")
    else:
        click.echo(f"🚀 Starting sinduk sync server on {_format_server_url(host, port)}")
        click.echo("   Press Ctrl+C to stop.")
        _write_state(os.getpid(), host, port)
        try:
            app = create_sync_server_app()
            app.run(host=host, port=port, debug=False)
        finally:
            _clear_state()


@server.command("_internal_run", hidden=True)
@click.option("--host", default=DEFAULT_HOST)
@click.option("--port", default=DEFAULT_PORT, type=int)
def internal_run(host, port):
    """Internal runner for daemon mode."""
    _write_state(os.getpid(), host, port)
    app = create_sync_server_app()
    app.run(host=host, port=port, debug=False)


@server.command("stop")
def server_stop():
    """Stop the background sync server."""
    pid = _get_pid_from_file()
    if not pid:
        click.echo("ℹ️ No running sync server found.")
        _clear_state()
        return

    if not _is_pid_running(pid):
        click.echo(f"ℹ️ Server process {pid} is already stopped.")
        _clear_state()
        return

    try:
        os.kill(pid, signal.SIGTERM)
        click.echo(f"🛑 Sent stop signal to server process {pid}...")
        for _ in range(20):
            time.sleep(0.2)
            if not _is_pid_running(pid):
                break
        else:
            os.kill(pid, signal.SIGKILL)
            click.echo(f"⚡ Force stopped server process {pid}.")

        _clear_state()
        click.echo("✅ Sync server stopped.")
    except Exception as e:
        click.echo(f"❌ Failed to stop server: {e}")


@server.command("status")
def server_status():
    """Check sync server status."""
    pid = _get_pid_from_file()
    if not pid or not _is_pid_running(pid):
        click.echo("⚪ Sync server: Stopped")
        return

    state = _read_state() or {}
    click.echo("🟢 Sync server: Running")
    click.echo(f"   PID:        {pid}")
    click.echo(f"   URL:        {state.get('url', 'unknown')}")
    click.echo(f"   Started:    {state.get('started_at', 'unknown')}")
    click.echo(f"   Logs:       {SERVER_LOG_PATH}")


# ------------------------------------------------------------------
# Token Management Subgroup
# ------------------------------------------------------------------


@server.group("token")
def token_group():
    """Manage sync server access tokens."""
    pass


@token_group.command("create")
@click.option("--name", "-n", required=True, help="Display name for token owner (e.g. 'Alice', 'DevOps').")
@click.option(
    "--role", "-r", type=click.Choice(["member", "admin"]), default="member", show_default=True, help="Token role."
)
def token_create(name, role):
    """Generate a new team access token."""
    db = SyncServerDB()
    token_id, raw_token = db.create_token(name, role=role)

    click.echo("\n🔑 New Sync Server Token Generated!")
    click.echo("-" * 60)
    click.echo(f"Token ID:    {token_id}")
    click.echo(f"Name:        {name}")
    click.echo(f"Role:        {role}")
    click.echo(f"Secret Token:\n\n  {raw_token}\n")
    click.echo("⚠️  Save this token now! It will not be shown again.")
    click.echo("   Team members can configure it with:")
    click.echo(f"   sinduk sync config set --server <server_url> --token {raw_token}")


@token_group.command("list")
def token_list():
    """List all server access tokens."""
    db = SyncServerDB()
    tokens = db.list_tokens()
    if not tokens:
        click.echo("📭 No tokens found.")
        return

    click.echo(f"{'ID':10}  {'Name':20}  {'Role':10}  {'Active':8}  {'Created'}")
    click.echo("-" * 65)
    for t in tokens:
        created = time.strftime("%Y-%m-%d %H:%M", time.localtime(t["created_at"]))
        active_str = "✅ Yes" if t["active"] else "❌ Revoked"
        click.echo(f"{t['id']:10}  {t['name'][:20]:20}  {t['role']:10}  {active_str:8}  {created}")


@token_group.command("revoke")
@click.argument("token_id")
@click.confirmation_option(prompt="Are you sure you want to revoke this token?")
def token_revoke(token_id):
    """Revoke an access token."""
    db = SyncServerDB()
    success = db.revoke_token(token_id)
    if success:
        click.echo(f"✅ Token '{token_id}' has been revoked.")
    else:
        click.echo(f"❌ Token '{token_id}' not found.")


if __name__ == "__main__":
    server()
