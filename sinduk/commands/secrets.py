import click
import datetime
from getpass import getpass
from ..store import SecretStore
from ..vault import VaultManager
from ..log import get_logger
from ..decorators import master_password_required
from ..helpers import choice_one, copy_to_clipboard
from ..ssh_utils import suggest_ssh_hosts

logger = get_logger("sinduk.commands.secrets")
NO_SELECTION_MSG = "❌ No valid selection made. Aborting."
SECRET_UPDATED_MSG = "✅ Updated secret successfully!"
SECRET_NOT_FOUND_MSG = "❌ Secret not found or may already be deleted."
NO_SECRET_MSG = "❌ Secret not found."
NO_MASTER_KEY_MSG = "❌ Master key is not loaded."


def _detect_secret_type(secret_type, arg1, arg2):
    if secret_type:
        return secret_type
    if arg1 and ("@" in arg1 or (":" in arg1 and arg1.count(":") <= 1)):
        return "ssh"
    if arg1 and arg2:
        return "password"
    return "token"


def _echo_suggested_ssh_hosts():
    suggested_hosts = suggest_ssh_hosts()
    if not suggested_hosts:
        return
    click.echo("Available SSH hosts from config:")
    for i, host in enumerate(suggested_hosts[:5], 1):
        click.echo(f"  {i}. {host}")
    click.echo("")


def _build_ssh_user_ip(arg1, arg2):
    if arg1:
        if "@" in arg1:
            return arg1.replace("@", ":")
        if ":" in arg1:
            return arg1
        ip = arg2 if arg2 else click.prompt("Enter SSH IP/hostname")
        return f"{arg1}:{ip}"

    _echo_suggested_ssh_hosts()
    user = click.prompt("Enter SSH username")
    ip = click.prompt("Enter SSH IP/hostname")
    return f"{user}:{ip}"


def _append_ssh_parts(user_ip, key_path, ssh_port, ssh_opts):
    ssh_data = user_ip
    if key_path:
        ssh_data += f"|key:{key_path}"
    if ssh_port:
        ssh_data += f"|port:{ssh_port}"
    if ssh_opts:
        ssh_data += f"|opts:{ssh_opts}"
    return ssh_data


def _save_token_secret(store, label, arg1):
    secret = arg1 if arg1 else getpass("🔐 Enter token: ")
    store.save_secret(label, secret, "token")
    logger.info(f"Token saved for label: {label}")
    click.echo("✅ Token saved.")


def _save_password_secret(store, label, arg1, arg2):
    username = arg1 if arg1 else click.prompt("Enter username")
    password = arg2 if arg2 else getpass("🔐 Enter password: ")
    store.save_secret(label, f"{username}:{password}", "password")
    logger.info(f"Username and password saved for label: {label}")
    click.echo(f"✅ {label} credentials saved.")


def _save_ssh_secret(store, label, arg1, arg2, key_path, ssh_port, ssh_opts):
    user_ip = _build_ssh_user_ip(arg1, arg2)
    ssh_data = _append_ssh_parts(user_ip, key_path, ssh_port, ssh_opts)
    store.save_secret(label, ssh_data, "ssh")
    logger.info(f"SSH connection saved for label: {label}")
    click.echo(f"✅ SSH connection {label} saved.")


def _select_secret(label, matches):
    if len(matches) == 1:
        return matches[0]
    selected = choice_one(label, matches)
    if not selected:
        click.echo(NO_SELECTION_MSG)
    return selected


def _get_ssh_display(secret, prefix):
    parts = secret["secret"].split("|")
    user_ip = parts[0]
    extras = []
    for part in parts[1:]:
        if part.startswith("key:"):
            extras.append(f"Key: {part[4:]}")
        elif part.startswith("port:"):
            extras.append(f"Port: {part[5:]}")
        elif part.startswith("opts:"):
            extras.append(f"Opts: {part[5:]}")

    display = f"{prefix}{user_ip}"
    if extras:
        display += f" ({', '.join(extras)})"
    return display


def _print_secret(secret, prefix):
    if secret["type"] == "ssh":
        click.echo(_get_ssh_display(secret, prefix))
        return
    click.echo(f"🔐 Secret: {secret['secret']}")


def _copy_secret(secret):
    if secret["type"] == "ssh":
        copy_to_clipboard(secret["secret"].split("|")[0])
        return
    copy_to_clipboard(secret["secret"])


def _prompt_updated_ssh_secret(current_ssh):
    if "|" in current_ssh:
        user_ip, key_path = current_ssh.split("|", 1)
        click.echo(f"Current SSH: {user_ip} (Key: {key_path})")
    else:
        click.echo(f"Current SSH: {current_ssh}")

    new_user = click.prompt("Enter new SSH username", default="")
    new_ip = click.prompt("Enter new SSH IP/hostname", default="")
    new_key = click.prompt("Enter new SSH key path (optional)", default="")

    if not new_user or not new_ip:
        click.echo("❌ Username and IP are required for SSH connections.")
        return None

    new_secret = f"{new_user}:{new_ip}"
    if new_key:
        new_secret += f"|{new_key}"
    return new_secret


def _resolve_secret_payload(secret_type, arg1, arg2, key_path, ssh_port, ssh_opts):
    if secret_type == "token":  # nosec B105
        return arg1 if arg1 else getpass("🔐 Enter token: ")
    if secret_type == "password":  # nosec B105
        username = arg1 if arg1 else click.prompt("Enter username")
        password = arg2 if arg2 else getpass("🔐 Enter password: ")
        return f"{username}:{password}"
    user_ip = _build_ssh_user_ip(arg1, arg2)
    return _append_ssh_parts(user_ip, key_path, ssh_port, ssh_opts)


def _save_vault_secret(store, vault_name, label, secret_type, arg1, arg2, key_path, ssh_port, ssh_opts):
    store.require_fernet()
    if store.fernet is None:
        click.echo(NO_MASTER_KEY_MSG)
        return
    fernet = store.fernet
    payload = _resolve_secret_payload(secret_type, arg1, arg2, key_path, ssh_port, ssh_opts)
    vm = VaultManager()
    try:
        vm.save_secret(vault_name, label, payload, secret_type, fernet)
        click.echo(f"✅ Secret saved to vault '{vault_name}'.")
    except (ValueError, PermissionError, RuntimeError) as e:
        click.echo(f"❌ {e}")


@click.command()
@click.option(
    "--type",
    "-t",
    "secret_type",
    type=click.Choice(["token", "password", "ssh"]),
    help="Type of secret to store (token, password, ssh).",
)
@click.option("--key", "-k", "key_path", help="Path to SSH private key file.")
@click.option("--port", "-p", "ssh_port", help="SSH port (default: 22).")
@click.option("--opts", "-o", "ssh_opts", help="Additional SSH options.")
@click.option("--vault", "-v", "vault_name", default=None, help="Save to a team vault instead of personal store.")
@click.argument("label", required=True)
@click.argument("arg1", required=False)
@click.argument("arg2", required=False)
@click.pass_context
@master_password_required
def add(ctx, secret_type, key_path, ssh_port, ssh_opts, vault_name, label, arg1, arg2):
    """Add a secret with LABEL. Use --type to specify token, password, or ssh."""
    store = SecretStore()
    del ctx
    secret_type = _detect_secret_type(secret_type, arg1, arg2)

    # If targeting a vault, route through VaultManager
    if vault_name:
        _save_vault_secret(store, vault_name, label, secret_type, arg1, arg2, key_path, ssh_port, ssh_opts)
        return

    if secret_type == "token":  # nosec B105
        _save_token_secret(store, label, arg1)
        return
    if secret_type == "password":  # nosec B105
        _save_password_secret(store, label, arg1, arg2)
        return
    _save_ssh_secret(store, label, arg1, arg2, key_path, ssh_port, ssh_opts)


def _get_vault_secret(vault_name, label, clip, store):
    store.require_fernet()
    if store.fernet is None:
        click.echo(NO_MASTER_KEY_MSG)
        return
    fernet = store.fernet
    vm = VaultManager()
    try:
        matches = vm.get_secrets_by_label(vault_name, label, fernet)
    except (PermissionError, ValueError, RuntimeError) as e:
        click.echo(f"❌ {e}")
        return
    if not matches:
        click.echo(NO_SECRET_MSG)
        return
    selected = _select_secret(label, matches)
    if not selected:
        return
    if clip:
        _copy_secret(selected)
        return
    _print_secret(selected, "🔐 SSH: ")


def _get_personal_secret(label, clip, store):
    matches = store.get_secrets_by_label(label)
    if not matches:
        logger.warning(f"Secret not found for label: {label}")
        click.echo(NO_SECRET_MSG)
        return
    selected = _select_secret(label, matches)
    if not selected:
        return

    logger.info(f"Secret retrieved for label: {label}, id: {selected['id']}")
    if clip:
        _copy_secret(selected)
        return
    _print_secret(selected, "🔐 SSH: ")


@click.command()
@click.argument("label", required=True)
@click.option("--clip", is_flag=True, help="Copy the secret to clipboard instead of printing.")
@click.option("--vault", "-v", "vault_name", default=None, help="Retrieve from a team vault.")
@master_password_required
def get(label, clip, vault_name):
    """Retrieve secrets by LABEL. Use --clip to copy to clipboard."""
    store = SecretStore()
    if vault_name:
        _get_vault_secret(vault_name, label, clip, store)
    else:
        _get_personal_secret(label, clip, store)


@click.command()
@click.argument("secret_id", required=True)
@click.option("--clip", is_flag=True, help="Copy the secret to clipboard instead of printing.")
@master_password_required
def get_by_id(secret_id, clip):
    """Retrieve a secret by its ID."""
    store = SecretStore()
    try:
        secret = store.get_secret_by_id(secret_id)
        if not secret:
            click.echo(f"❌ No secret found with ID: {secret_id}")
            return
        if clip:
            _copy_secret(secret)
            return
        if secret["type"] == "ssh":
            click.echo(_get_ssh_display(secret, f"🔐 SSH for ID {secret_id}: "))
        else:
            click.echo(f"🔐 Secret for ID {secret_id}: {secret['secret']}")
    except Exception as e:
        logger.error(f"Error retrieving secret by ID {secret_id}: {e}")
        click.echo("❌ An error occurred while retrieving the secret.")


def _list_vault_secrets(vault_name):
    vm = VaultManager()
    try:
        secrets = vm.list_secrets(vault_name)
    except (PermissionError, ValueError, RuntimeError) as e:
        click.echo(f"❌ {e}")
        return
    if not secrets:
        click.echo(f"(No secrets in vault '{vault_name}')")
        return
    click.echo(f"📜 Secrets in vault '{vault_name}':")
    click.echo(f"{'ID':10}  {'Label':33}  {'Type':10}  {'By':14}  {'Created':20}  {'Updated':20}")
    click.echo("-" * 115)
    for sid, label, stype, created_by, ctime, utime in secrets:
        cstr = datetime.datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M:%S") if ctime else ""
        ustr = datetime.datetime.fromtimestamp(utime).strftime("%Y-%m-%d %H:%M:%S") if utime else ""
        click.echo(f"{sid:10}  {label:33}  {stype:10}  {(created_by or ''):14}  {cstr:20}  {ustr:20}")


def _list_personal_secrets(store):
    secrets = store.list_secrets()
    if not secrets:
        logger.info("No secrets found.")
        click.echo("(No secrets found)")
        return

    logger.info("Listing all saved secrets.")
    click.echo("📜 List of saved secrets:")
    click.echo(f"{'ID':10}  {'Label':33}  {'Type':10}  {'Created':20}  {'Updated':20}")
    click.echo("-" * 100)
    for sid, label, stype, ctime, utime in secrets:
        cstr = datetime.datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M:%S") if ctime else ""
        ustr = datetime.datetime.fromtimestamp(utime).strftime("%Y-%m-%d %H:%M:%S") if utime else ""
        click.echo(f"{sid:10}  {label:33}  {stype:10}  {cstr:20}  {ustr:20}")


@click.command()
@click.option("--vault", "-v", "vault_name", default=None, help="List secrets from a team vault.")
@master_password_required
def list(vault_name):
    """List all saved secrets."""
    if vault_name:
        _list_vault_secrets(vault_name)
    else:
        _list_personal_secrets(SecretStore())


def _update_vault_secret(vault_name, label, store):
    store.require_fernet()
    if store.fernet is None:
        click.echo(NO_MASTER_KEY_MSG)
        return
    fernet = store.fernet
    vm = VaultManager()
    try:
        matches = vm.get_secrets_by_label(vault_name, label, fernet)
    except (PermissionError, ValueError, RuntimeError) as e:
        click.echo(f"❌ {e}")
        return
    if not matches:
        click.echo(SECRET_NOT_FOUND_MSG)
        return
    selected = _select_secret(label, matches)
    if not selected:
        return
    if selected["type"] == "ssh":
        new_secret = _prompt_updated_ssh_secret(selected["secret"])
        if not new_secret:
            return
    else:
        new_secret = getpass(f"Enter updated secret for {label}:")
    try:
        vm.update_secret(vault_name, selected["id"], new_secret, fernet)
        click.echo(SECRET_UPDATED_MSG)
    except (PermissionError, ValueError) as e:
        click.echo(f"❌ {e}")


def _update_personal_secret(label, store):
    matches = store.get_secrets_by_label(label)
    if not matches:
        logger.warning(f"Attempted to update non-existent secret: {label}")
        click.echo(SECRET_NOT_FOUND_MSG)
        return
    logger.info(f"Updating secret for label: {label}")
    selected = _select_secret(label, matches)
    if not selected:
        return
    secret_id = selected["id"]

    if selected["type"] == "ssh":
        new_secret = _prompt_updated_ssh_secret(selected["secret"])
        if not new_secret:
            return
    else:
        new_secret = getpass(f"Enter updated secret for {label} with {secret_id}:")
    try:
        store.update_secret(secret_id, new_secret)
        click.echo(SECRET_UPDATED_MSG)
        logger.info(f"Secreted update for {label} with ID: {secret_id}")
    except Exception as e:
        click.echo(f"❌ couldn't able to update due to {e}")


@click.command()
@click.argument("label", required=True)
@click.option("--vault", "-v", "vault_name", default=None, help="Update secret in a team vault.")
@master_password_required
def update(label, vault_name):
    """Update a secret by LABEL."""
    store = SecretStore()
    if vault_name:
        _update_vault_secret(vault_name, label, store)
    else:
        _update_personal_secret(label, store)


@click.command()
@click.argument("secret_id", required=True)
@master_password_required
def update_by_id(secret_id):
    """Update secret with ID"""
    store = SecretStore()
    secret = store.get_secret_by_id(secret_id)
    if not secret:
        click.echo(f"❌ No secret found with ID: {secret_id}")
        return
    if secret["type"] == "ssh":
        new_secret = _prompt_updated_ssh_secret(secret["secret"])
        if not new_secret:
            return
    else:
        new_secret = getpass("Enter updated secret: ")
    try:
        store.update_secret(secret_id, new_secret)
        click.echo(SECRET_UPDATED_MSG)
        logger.info(f"Secreted update with ID: {secret_id}")
    except Exception as e:
        click.echo(f"❌ couldn't able to update due to {e}")


def _delete_vault_secret(vault_name, label, store):
    store.require_fernet()
    if store.fernet is None:
        click.echo(NO_MASTER_KEY_MSG)
        return
    fernet = store.fernet
    vm = VaultManager()
    try:
        matches = vm.get_secrets_by_label(vault_name, label, fernet)
    except (PermissionError, ValueError, RuntimeError) as e:
        click.echo(f"❌ {e}")
        return
    if not matches:
        click.echo(SECRET_NOT_FOUND_MSG)
        return
    selected = _select_secret(label, matches)
    if not selected:
        return
    if not click.confirm("Are you sure you want to delete this secret?"):
        click.echo("❌ Deletion cancelled.")
        return
    try:
        vm.delete_secret(vault_name, selected["id"])
        click.echo("🗑️ Deleted from the vault.")
    except (PermissionError, ValueError) as e:
        click.echo(f"❌ {e}")


def _delete_personal_secret(label, store):
    matches = store.get_secrets_by_label(label)
    if not matches:
        logger.warning(f"Attempted to delete non-existent secret: {label}")
        click.echo(SECRET_NOT_FOUND_MSG)
        return
    logger.info(f"Deleting secret for label: {label}")
    selected = _select_secret(label, matches)
    if not selected:
        return

    if not click.confirm("Are you sure you want to delete this secret?"):
        click.echo("❌ Deletion cancelled.")
        return

    logger.info(f"Deleting secret with ID: {selected['id']} and label: {label}")
    click.echo(f"🔐 Deleting secret with ID: {selected['id']} and label: {label}")
    store.delete_secret(selected["id"])
    logger.info(f"Secret deleted for label: {label} with ID: {selected['id']}")
    click.echo("🗑️ Deleted from the list.")


@click.command()
@click.argument("label", required=True)
@click.option("--vault", "-v", "vault_name", default=None, help="Delete secret from a team vault.")
@master_password_required
def delete(label, vault_name):
    """Delete a secret by LABEL."""
    store = SecretStore()
    if vault_name:
        _delete_vault_secret(vault_name, label, store)
    else:
        _delete_personal_secret(label, store)


@click.command()
@click.argument("secret_id", required=True)
@click.confirmation_option(prompt="Are you sure you want to delete this secret?")
@master_password_required
def delete_by_id(secret_id):
    """Delete a secret by its ID."""
    store = SecretStore()
    try:
        store.delete_secret(secret_id)
        click.echo(f"🗑️ Secret with ID {secret_id} deleted successfully.")
    except Exception as e:
        logger.error(f"Error deleting secret by ID {secret_id}: {e}")
        click.echo("❌ An error occurred while deleting the secret.")
