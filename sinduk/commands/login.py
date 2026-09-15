"""
Login and logout commands for pairing the CLI with a self-hosted Sinduk server.
"""

import sys
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import click
import requests
from ..log import get_logger
from ..sync_client import (
    get_sync_config,
    set_sync_config,
    resolve_server_params,
    validate_sync_server,
)

logger = get_logger("sinduk.login")


class _AuthCallbackHandler(BaseHTTPRequestHandler):
    """Temporary local HTTP handler for browser OAuth/device callback."""

    received_token: str | None = None

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        token = qs.get("token", [""])[0]

        if token:
            _AuthCallbackHandler.received_token = token
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"<html><body style='font-family:sans-serif;text-align:center;padding:50px;"
                b"background:#0f172a;color:#fff;'>"
                b"<h1 style='color:#38bdf8;'>&#x2714; Authenticated!</h1>"
                b"<p>You can close this tab and return to your terminal.</p>"
                b"</body></html>"
            )
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing token in authorization callback.")

    def log_message(self, format, *args):
        pass  # Suppress noisy HTTP logs in console


def _start_loopback_server(port: int = 58390) -> tuple[HTTPServer | None, int]:
    """Start local loopback server on an available port."""
    for p in range(port, port + 10):
        try:
            httpd = HTTPServer(("127.0.0.1", p), _AuthCallbackHandler)
            return httpd, p
        except OSError:
            continue
    return None, 0


def _request_device_code(server_url: str) -> dict | None:
    """Request a new device pairing code from the server."""
    try:
        res = requests.post(f"{server_url}/api/v1/auth/device/code", timeout=5)
        if res.status_code != 200:
            click.secho(f"Server error: HTTP {res.status_code} requesting device code.", fg="red")
            return None
        return res.json()
    except Exception as e:
        click.secho(f"Could not connect to server at {server_url}: {e}", fg="red")
        return None


def _poll_device_session(server_url: str, session_id: str, expires_in: int) -> str | None:
    """Poll the server until the device session is authorized or expires."""
    start_time = time.time()
    while time.time() - start_time < expires_in:
        # Check loopback result first
        if _AuthCallbackHandler.received_token:
            return _AuthCallbackHandler.received_token

        # Poll server endpoint
        try:
            poll_res = requests.get(
                f"{server_url}/api/v1/auth/device/poll",
                params={"session_id": session_id},
                timeout=5,
            )
            if poll_res.status_code == 200:
                data = poll_res.json()
                if data.get("status") == "authorized" and data.get("token"):
                    return data.get("token")
                if data.get("status") == "expired":
                    click.secho("Authorization request expired.", fg="red")
                    return None
        except Exception:  # nosec B110
            pass

        time.sleep(1.5)

    click.secho("Authentication timed out.", fg="red")
    return None


def _login_with_browser(server_url: str) -> str | None:
    """Execute interactive browser-based device login."""
    code_data = _request_device_code(server_url)
    if not code_data:
        return None

    device_code = code_data.get("device_code")
    session_id = code_data.get("session_id")
    expires_in = code_data.get("expires_in", 600)

    if not device_code or not session_id:
        click.secho("Invalid device code payload from server.", fg="red")
        return None

    # Setup loopback receiver
    httpd, port = _start_loopback_server()
    if httpd:
        server_thread = threading.Thread(target=httpd.handle_request, daemon=True)
        server_thread.start()

    auth_url = f"{server_url}/auth/device?code={device_code}&session_id={session_id}"
    if port > 0:
        auth_url += f"&callback=http://127.0.0.1:{port}/auth"

    click.echo("\n🔑 Authenticating with Sinduk Server...")
    click.secho(f"👉 Opening browser: {auth_url}", fg="cyan")
    click.echo(f"   Device Code: {click.style(device_code, bold=True, fg='yellow')}")
    click.echo("   Waiting for authorization...")

    try:
        webbrowser.open(auth_url)
    except Exception:  # nosec B110
        pass

    return _poll_device_session(server_url, session_id, expires_in)


def _login_headless(server_url: str) -> str | None:
    """Authenticate directly using username/email and password in terminal."""
    email = click.prompt("Email / Username", type=str).strip()
    password = click.prompt("Password", hide_input=True)

    try:
        res = requests.post(
            f"{server_url}/api/v1/auth/login",
            json={"email": email, "password": password},
            timeout=5,
        )
        if res.status_code == 200:
            data = res.json()
            return data.get("token")
        if res.status_code == 401:
            click.secho("Invalid email or password.", fg="red")
            return None
        click.secho(f"Login failed: HTTP {res.status_code}", fg="red")
        return None
    except Exception as e:
        click.secho(f"Connection error: {e}", fg="red")
        return None


@click.command(name="login")
@click.argument("server_url", required=False)
@click.option("--no-browser", is_flag=True, help="Authenticate directly in the terminal without opening a browser.")
def login_cmd(server_url: str | None, no_browser: bool):
    """
    Log in to a self-hosted Sinduk team server and pair this terminal.

    Examples:
        sinduk login https://secrets.mycompany.com
        sinduk login http://192.168.1.50:58380 --no-browser
    """
    target_server = server_url
    if not target_server:
        configured_server, _ = resolve_server_params()
        if configured_server:
            target_server = click.prompt("Sinduk Server URL", default=configured_server)
        else:
            target_server = click.prompt("Sinduk Server URL (e.g. http://127.0.0.1:58380)")

    if not target_server:
        click.secho("✖ Server URL is required.", fg="red")
        sys.exit(1)

    target_server = target_server.strip().rstrip("/")
    if not target_server.startswith(("http://", "https://")):
        if target_server.startswith(("localhost", "127.0.0.1", "0.0.0.0")):  # nosec B104
            target_server = f"http://{target_server}"  # NOSONAR - python:S5332: Local development fallback
        else:
            target_server = f"https://{target_server}"

    # Verify server connectivity
    validation = validate_sync_server(target_server)
    if not validation.get("connected"):
        click.secho(f"✖ Could not reach server at '{target_server}': {validation.get('error')}", fg="red")
        sys.exit(1)

    if no_browser:
        token = _login_headless(target_server)
    else:
        token = _login_with_browser(target_server)

    if not token:
        click.secho("✖ Authentication failed.", fg="red")
        sys.exit(1)

    # Save sync config
    set_sync_config(server_url=target_server, token=token)
    click.secho("\n✔ Successfully authenticated and paired with Sinduk Server!", fg="green", bold=True)
    click.echo(f"  Server: {target_server}")
    click.echo("  You can now access and synchronize team vaults automatically.")


@click.command(name="logout")
def logout_cmd():
    """Log out and remove stored sync server credentials from this machine."""
    cfg = get_sync_config()
    server_url = cfg.get("server_url")
    if not server_url and not cfg.get("token"):
        click.echo("No active sync server session found.")
        return

    set_sync_config(clear=True)
    click.secho("✔ Successfully logged out from Sinduk Sync Server.", fg="green")
