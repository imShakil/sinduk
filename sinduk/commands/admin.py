import os
import click
from getpass import getpass
from ..decorators import master_password_required
from ..store import SecretStore
from ..log import get_logger
from .. import __version__, __metadata__

logger = get_logger("sinduk.commands.admin")


@click.command()
def init():
    """
    (Optional) Explicitly set the master password.

    sinduk sets up your master password automatically the first time you run
    any command — you don't need to run this manually. Use it only if you
    want to reset or pre-configure sinduk before your first secret.
    """
    config_dir = os.path.expanduser("~/.config/sinduk")
    os.makedirs(config_dir, exist_ok=True)
    try:
        os.chmod(config_dir, 0o700)
    except Exception as e:
        logger.warning(f"Could not set permissions on {config_dir}: {e}")

    store = SecretStore()
    if store.is_master_set():
        click.echo(
            "✅ Master password is already set.\n"
            "   To reset, delete ~/.config/sinduk/salt.bin and run this command again.\n"
            "   To change it without losing secrets, use: sinduk passwd"
        )
        return
    store.set_master_password()
    click.echo("✅ Master password set. You can now add secrets.")


def _execute_change_master_password():
    store = SecretStore()
    store.require_fernet()
    if store.fernet is None:
        click.echo("❌ Master key is not loaded. Aborting.")
        return
    fernet = store.fernet

    all_secrets = []
    for row in store.conn.execute("SELECT id, value_encrypted FROM secrets"):
        try:
            decrypted = fernet.decrypt(row[1].encode()).decode()
            all_secrets.append((row[0], decrypted))
        except Exception as e:
            logger.error(f"Failed to decrypt secret {row[0]}: {e}")
            click.echo("❌ Failed to decrypt a secret. Aborting master key change.")
            return

    new_password = getpass("🔐 Enter new master password: ")
    confirm_password = getpass("🔐 Confirm new master password: ")
    if new_password != confirm_password or not new_password:
        click.echo("❌ Passwords do not match or are empty. Aborting.")
        return

    store.update_master_password(new_password)
    # Re-derive fernet with new password so re-encryption works
    from ..store import get_salt

    salt = get_salt()
    new_fernet = store._derive_fernet(new_password, salt)
    store.fernet = new_fernet

    for sid, plain in all_secrets:
        encrypted = new_fernet.encrypt(plain.encode()).decode()
        store.conn.execute("UPDATE secrets SET value_encrypted = ? WHERE id = ?", (encrypted, sid))
    store.conn.commit()
    logger.info("Master password changed and all secrets re-encrypted.")
    click.echo("✅ Master password changed and all secrets re-encrypted.")


@click.command()
@master_password_required
def passwd():
    """Change the master password without losing secrets."""
    _execute_change_master_password()


@click.command(hidden=True)
@master_password_required
def change_master_key():
    """Change the master password without losing secrets (alias for passwd)."""
    _execute_change_master_password()


@click.command()
def version(**kwargs):
    """Show the current version of sinduk."""
    AUTHOR = "Unknown"
    HOMEPAGE = "Unknown"

    if __metadata__:
        AUTHOR = __metadata__["Author-email"]
        HOMEPAGE = __metadata__["Project-URL"].split(",")[1].strip()

    click.echo("🔐 sinduk - Secrets Management CLI")
    click.echo("-" * 33)
    click.echo(f"Version: {__version__}")
    click.echo(f"Author: {AUTHOR}")
    click.echo(f"GitHub: {HOMEPAGE}")
