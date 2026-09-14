import click
import webbrowser
import os
import json
import signal
import subprocess  # nosec B404
import sys
from ..web.app import create_app
from ..log import get_logger

logger = get_logger("sinduk.web")

WEB_STATE_DIR = os.path.expanduser("~/.config/sinduk")
WEB_PID_PATH = os.path.join(WEB_STATE_DIR, "webui.pid")
WEB_STATE_PATH = os.path.join(WEB_STATE_DIR, "webui_state.json")
WEB_LOG_PATH = os.path.join(WEB_STATE_DIR, "webui.log")
WEB_DEFAULT_PORT = 58371


def _run_server(host, port, no_browser):
    app, socketio = create_app()

    os.environ["FLASK_ENV"] = "production"
    url = f"http://{host}:{port}"

    if not no_browser:
        import threading
        import time

        def open_browser():
            time.sleep(1)
            try:
                webbrowser.open(url)
            except Exception as e:
                logger.warning(f"Could not open browser: {e}")

        thread = threading.Thread(target=open_browser, daemon=True)
        thread.start()

    click.echo(f"🔐 Sinduk Web UI starting at {url}")
    click.echo("Press Ctrl+C to stop the server")
    socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)


def _is_pid_running(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _get_pid_from_file():
    if not os.path.exists(WEB_PID_PATH):
        return None
    with open(WEB_PID_PATH, "r") as f:
        pid_text = f.read().strip()
    if not pid_text.isdigit():
        return None
    pid = int(pid_text)
    if pid <= 1:
        return None
    return pid


def _is_pid_owned_by_current_user(pid):
    proc_path = f"/proc/{pid}"
    if not os.path.exists(proc_path):
        return False
    try:
        return os.stat(proc_path).st_uid == os.getuid()
    except OSError:
        return False


def _is_expected_web_process(pid):
    cmdline_path = f"/proc/{pid}/cmdline"
    try:
        with open(cmdline_path, "rb") as f:
            cmdline = f.read().decode("utf-8", errors="ignore")
    except OSError:
        return False
    return ("sinduk.commands.web" in cmdline or "pacli.commands.web" in cmdline) and "_run_server" in cmdline


def _load_state():
    if not os.path.exists(WEB_STATE_PATH):
        return {}
    try:
        with open(WEB_STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _clear_state_files():
    for path in (WEB_PID_PATH, WEB_STATE_PATH):
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


def _save_state(pid, host, port, log_file):
    os.makedirs(WEB_STATE_DIR, exist_ok=True)
    with open(WEB_PID_PATH, "w") as f:
        f.write(str(pid))
    with open(WEB_STATE_PATH, "w") as f:
        json.dump({"pid": pid, "host": host, "port": port, "log": log_file}, f)


@click.group(invoke_without_command=True)
@click.option(
    "--host",
    default="127.0.0.1",
    help="Host to bind to (default: 127.0.0.1)",
)
@click.option(
    "--port",
    default=WEB_DEFAULT_PORT,
    type=int,
    help=f"Port to bind to (default: {WEB_DEFAULT_PORT})",
)
@click.option(
    "--no-browser",
    is_flag=True,
    help="Don't open browser automatically",
)
@click.pass_context
def web(ctx, host, port, no_browser):
    """Launch and manage the Web UI for sinduk."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(serve, host=host, port=port, no_browser=no_browser)


@web.command("serve")
@click.option(
    "--host",
    default="127.0.0.1",
    help="Host to bind to (default: 127.0.0.1)",
)
@click.option(
    "--port",
    default=WEB_DEFAULT_PORT,
    type=int,
    help=f"Port to bind to (default: {WEB_DEFAULT_PORT})",
)
@click.option(
    "--no-browser",
    is_flag=True,
    help="Don't open browser automatically",
)
def serve(host, port, no_browser):
    """Run Web UI in the current terminal (foreground)."""
    try:
        _run_server(host, port, no_browser)
    except Exception as e:
        logger.error(f"Failed to start web UI: {e}")
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()


@web.command("start")
@click.option(
    "--host",
    default="127.0.0.1",
    help="Host to bind to (default: 127.0.0.1)",
)
@click.option(
    "--port",
    default=WEB_DEFAULT_PORT,
    type=int,
    help=f"Port to bind to (default: {WEB_DEFAULT_PORT})",
)
@click.option(
    "--no-browser",
    is_flag=True,
    help="Don't open browser automatically",
)
def start(host, port, no_browser):
    """Run Web UI in the background."""
    try:
        if os.path.exists(WEB_PID_PATH):
            with open(WEB_PID_PATH, "r") as f:
                pid_text = f.read().strip()
            if pid_text.isdigit() and _is_pid_running(int(pid_text)):
                state = _load_state()
                running_host = state.get("host", host)
                running_port = state.get("port", port)
                click.echo(f"Web UI already running (pid {pid_text}) at http://{running_host}:{running_port}")
                return
            _clear_state_files()

        os.makedirs(WEB_STATE_DIR, exist_ok=True)
        log_file = WEB_LOG_PATH
        runner = (
            "from sinduk.commands.web import _run_server; " f"_run_server({host!r}, {int(port)}, {bool(no_browser)})"
        )
        with open(log_file, "a") as lf:
            # Inputs are local CLI args and this runs under the same user account.
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    runner,
                ],
                stdout=lf,
                stderr=lf,
                stdin=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
            )  # nosec B603

        if process.poll() is not None:
            raise RuntimeError("Web UI process exited immediately. Check log file for details.")

        _save_state(process.pid, host, port, log_file)
        click.echo(f"Started Web UI in background (pid {process.pid}) at http://{host}:{port}")
        click.echo(f"Logs: {log_file}")
    except Exception as e:
        logger.error(f"Failed to start web UI in background: {e}")
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()


@web.command("stop")
def stop():
    """Stop background Web UI process."""
    if not os.path.exists(WEB_PID_PATH):
        click.echo("Web UI is not running.")
        return

    try:
        pid = _get_pid_from_file()
        if pid is None:
            _clear_state_files()
            click.echo("Web UI pid file was invalid and has been cleaned up.")
            return

        if not _is_pid_running(pid):
            _clear_state_files()
            click.echo("Web UI was not running; cleaned up stale pid/state files.")
            return

        if not _is_pid_owned_by_current_user(pid):
            click.echo("Refusing to stop process: pid is not owned by current user.")
            return

        if not _is_expected_web_process(pid):
            click.echo("Refusing to stop process: pid does not look like Sinduk Web UI.")
            return

        os.kill(pid, signal.SIGTERM)
        click.echo(f"Stopped Web UI (pid {pid}).")
        _clear_state_files()
    except Exception as e:
        logger.error(f"Failed to stop web UI: {e}")
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()


@web.command("status")
def status():
    """Show background Web UI status."""
    if not os.path.exists(WEB_PID_PATH):
        click.echo("Web UI is not running.")
        return

    try:
        pid = _get_pid_from_file()
        if pid is None:
            click.echo("Web UI status unknown (invalid pid file).")
            return

        state = _load_state()
        host = state.get("host", "127.0.0.1")
        port = state.get("port", WEB_DEFAULT_PORT)
        if _is_pid_running(pid):
            click.echo(f"Web UI is running (pid {pid}) at http://{host}:{port}")
            if state.get("log"):
                click.echo(f"Logs: {state['log']}")
        else:
            click.echo("Web UI is not running (stale pid file present).")
    except Exception as e:
        logger.error(f"Failed to get web UI status: {e}")
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()
