import click
import subprocess  # nosec 604
from ..store import SecretStore
from ..log import get_logger
from ..decorators import master_password_required
from ..helpers import choice_one

logger = get_logger("sinduk.commands.ssh")
SAFE_SSH_OPTS = {"-o", "StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null", "ConnectTimeout=10"}


def _get_selected_secret(label, store):
    matches = store.get_secrets_by_label(label)
    if not matches:
        logger.warning(f"SSH connection not found for label: {label}")
        click.echo("❌ SSH connection not found.")
        return None

    ssh_secrets = [m for m in matches if m["type"] == "ssh"]
    if not ssh_secrets:
        click.echo("❌ No SSH connections found for this label.")
        return None

    if len(ssh_secrets) == 1:
        return ssh_secrets[0]

    selected = choice_one(label, ssh_secrets)
    if not selected:
        click.echo("❌ No valid selection made. Aborting.")
    return selected


def _extract_user_host(ssh_data):
    parts = ssh_data.split("|")
    user_ip = parts[0]
    if ":" not in user_ip:
        click.echo("❌ Invalid SSH format. Expected user:host")
        return None, None, None

    user, ip = user_ip.split(":", 1)
    return user, ip, parts


def _is_valid_username(user):
    return user.replace("-", "").replace("_", "").replace(".", "").isalnum()


def _handle_key_option(cmd_parts, part):
    key_path = part[4:]
    if not key_path or ".." in key_path:
        click.echo("❌ Invalid key path")
        return False
    cmd_parts.extend(["-i", key_path])
    return True


def _handle_port_option(cmd_parts, part):
    port = part[5:]
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        click.echo("❌ Invalid port number")
        return False
    cmd_parts.extend(["-p", port])
    return True


def _handle_opts_option(cmd_parts, part):
    opts = part[5:].split()
    if not all(opt in SAFE_SSH_OPTS or opt.startswith("-o") for opt in opts):
        click.echo("❌ Unsafe SSH options detected")
        return False
    cmd_parts.extend(opts)
    return True


def _option_handler_for_part(part):
    if part.startswith("key:"):
        return _handle_key_option
    if part.startswith("port:"):
        return _handle_port_option
    if part.startswith("opts:"):
        return _handle_opts_option
    return None


def _append_option_parts(cmd_parts, parts):
    for part in parts[1:]:
        handler = _option_handler_for_part(part)
        if handler and not handler(cmd_parts, part):
            return False

    return True


def _build_ssh_command(selected_secret):
    user, ip, parts = _extract_user_host(selected_secret["secret"])
    if not user:
        return None, None, None

    if not _is_valid_username(user):
        click.echo("❌ Invalid username format")
        return None, None, None

    cmd_parts = ["ssh"]
    if not _append_option_parts(cmd_parts, parts):
        return None, None, None

    cmd_parts.append(f"{user}@{ip}")
    return cmd_parts, user, ip


@click.command()
@click.argument("label", required=True)
@master_password_required
def ssh(label):
    """Connect to SSH server using saved SSH credentials."""
    store = SecretStore()
    selected = _get_selected_secret(label, store)
    if not selected:
        return

    cmd_parts, user, ip = _build_ssh_command(selected)
    if not cmd_parts:
        return

    logger.info(f"Connecting to SSH: {user}@{ip}")
    click.echo(f"🔗 Connecting to {user}@{ip}...")
    try:
        subprocess.run(cmd_parts, check=False)  # nosec B603
    except FileNotFoundError:
        click.echo("❌ SSH command not found. Please install OpenSSH client.")
    except Exception as e:
        click.echo(f"❌ SSH connection failed: {e}")
