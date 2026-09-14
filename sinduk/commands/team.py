"""
CLI commands for team vault management.

Provides the `sinduk team` command group for managing shared vaults,
members, and permissions.
"""

import click
import datetime
from ..vault import VaultManager, set_user_identity, get_user_identity
from ..store import SecretStore
from ..decorators import master_password_required
from ..log import get_logger

logger = get_logger("sinduk.commands.team")
NO_IDENTITY_MSG = "❌ No identity set. Run 'sinduk team init' first."
NO_MASTER_KEY_MSG = "❌ Master key is not loaded."


@click.group()
def team():
    """👥 Team vault management — create and share encrypted vaults."""
    pass


@team.command("init")
def team_init():
    """Initialize team features and set your user identity."""
    existing = get_user_identity()
    if existing:
        click.echo(f"📋 Current identity: {existing['user_name']} ({existing['user_id']})")
        if not click.confirm("Do you want to update your identity?"):
            return

    user_name = click.prompt("Enter your display name (e.g., 'John Doe')")
    identity = set_user_identity(user_name)
    click.echo("\n✅ Identity set!")
    click.echo(f"   User ID:   {identity['user_id']}")
    click.echo(f"   Name:      {identity['user_name']}")
    click.echo("\n💡 Share your User ID with team members so they can add you to vaults.")


@team.command("whoami")
def team_whoami():
    """Show your current team identity."""
    identity = get_user_identity()
    if not identity:
        click.echo(NO_IDENTITY_MSG)
        return
    click.echo(f"👤 User ID:   {identity['user_id']}")
    click.echo(f"   Name:      {identity['user_name']}")
    cstr = datetime.datetime.fromtimestamp(identity.get("created_at", 0)).strftime("%Y-%m-%d %H:%M:%S")
    click.echo(f"   Created:   {cstr}")


@team.command("create-vault")
@click.argument("name")
@click.option("--description", "-d", default="", help="Optional description for the vault.")
@master_password_required
def create_vault(name, description):
    """Create a new shared vault.

    NAME should be alphanumeric with hyphens (e.g., 'team-infra', 'prod-keys').
    """
    identity = get_user_identity()
    if not identity:
        click.echo(NO_IDENTITY_MSG)
        return

    store = SecretStore()
    store.require_fernet()
    if store.fernet is None:
        click.echo(NO_MASTER_KEY_MSG)
        return
    fernet = store.fernet

    vm = VaultManager()
    try:
        meta = vm.create_vault(name, description=description, master_fernet=fernet)
        click.echo(f"\n✅ Vault '{name}' created!")
        click.echo(f"   Vault ID:     {meta['id']}")
        click.echo(f"   Owner:        {identity['user_name']} ({identity['user_id']})")
        click.echo("   Your role:    admin")
        if description:
            click.echo(f"   Description:  {description}")
        click.echo(f"\n💡 Use 'sinduk add --vault {name} ...' to add secrets to this vault.")
        click.echo(f"   Use 'sinduk team add-member {name} <user-id>' to invite team members.")
    except (ValueError, RuntimeError) as e:
        click.echo(f"❌ {e}")


@team.command("list-vaults")
def list_vaults():
    """List all vaults you have access to."""
    identity = get_user_identity()
    if not identity:
        click.echo(NO_IDENTITY_MSG)
        return

    vm = VaultManager()
    vaults = vm.list_vaults()

    if not vaults:
        click.echo("📭 No vaults found. Create one with 'sinduk team create-vault <name>'.")
        return

    click.echo("🗄️  Your vaults:\n")
    click.echo(f"{'Name':20}  {'Role':8}  {'Secrets':8}  {'Description':30}  {'Created':20}")
    click.echo("-" * 90)
    for v in vaults:
        cstr = (
            datetime.datetime.fromtimestamp(v.get("created_at", 0)).strftime("%Y-%m-%d %H:%M")
            if v.get("created_at")
            else ""
        )
        click.echo(
            f"{v['name']:20}  {v['role']:8}  {v.get('secret_count', 0):<8}  "
            f"{v.get('description', '')[:30]:30}  {cstr:20}"
        )


@team.command("vault-info")
@click.argument("name")
def vault_info(name):
    """Show detailed information about a vault."""
    vm = VaultManager()
    meta = vm.get_vault(name)
    if not meta:
        click.echo(f"❌ Vault '{name}' not found.")
        return

    click.echo(f"\n🗄️  Vault: {name}")
    click.echo(f"   ID:           {meta['id']}")
    click.echo(f"   Description:  {meta.get('description', '—')}")
    click.echo(f"   Owner:        {meta['owner']}")
    cstr = datetime.datetime.fromtimestamp(meta.get("created_at", 0)).strftime("%Y-%m-%d %H:%M:%S")
    click.echo(f"   Created:      {cstr}")

    members = vm.list_members(name)
    click.echo(f"\n👥 Members ({len(members)}):")
    for m in members:
        astr = datetime.datetime.fromtimestamp(m.get("added_at", 0)).strftime("%Y-%m-%d") if m.get("added_at") else ""
        click.echo(f"   • {m['user_name']} ({m['user_id']})  —  {m['role']}  (since {astr})")


@team.command("add-member")
@click.argument("vault_name")
@click.argument("user_id")
@click.option("--name", "-n", "user_name", required=True, help="Display name for the new member.")
@click.option(
    "--role",
    "-r",
    type=click.Choice(["viewer", "editor", "admin"]),
    default="viewer",
    show_default=True,
    help="Role for the new member.",
)
@master_password_required
def add_member(vault_name, user_id, user_name, role):
    """Add a member to a vault.

    VAULT_NAME is the name of the vault. USER_ID is the member's user ID
    (they can find it with 'sinduk team whoami').
    """
    store = SecretStore()
    store.require_fernet()
    if store.fernet is None:
        click.echo(NO_MASTER_KEY_MSG)
        return
    fernet = store.fernet

    vm = VaultManager()
    try:
        vm.add_member(vault_name, user_id, user_name, role, fernet)
        click.echo(f"✅ Added {user_name} ({user_id}) to vault '{vault_name}' as {role}.")
    except (ValueError, PermissionError, RuntimeError) as e:
        click.echo(f"❌ {e}")


@team.command("remove-member")
@click.argument("vault_name")
@click.argument("user_id")
@master_password_required
def remove_member(vault_name, user_id):
    """Remove a member from a vault."""
    store = SecretStore()
    store.require_fernet()

    vm = VaultManager()
    try:
        if not click.confirm(f"Remove user '{user_id}' from vault '{vault_name}'?"):
            click.echo("Cancelled.")
            return
        vm.remove_member(vault_name, user_id)
        click.echo(f"✅ Removed {user_id} from vault '{vault_name}'.")
    except (ValueError, PermissionError) as e:
        click.echo(f"❌ {e}")


@team.command("set-role")
@click.argument("vault_name")
@click.argument("user_id")
@click.argument("role", type=click.Choice(["viewer", "editor", "admin"]))
@master_password_required
def set_role(vault_name, user_id, role):
    """Change a member's role in a vault."""
    store = SecretStore()
    store.require_fernet()

    vm = VaultManager()
    try:
        vm.set_member_role(vault_name, user_id, role)
        click.echo(f"✅ Updated {user_id}'s role to '{role}' in vault '{vault_name}'.")
    except (ValueError, PermissionError) as e:
        click.echo(f"❌ {e}")


@team.command("audit-log")
@click.argument("vault_name")
@click.option("--limit", "-l", default=20, show_default=True, help="Number of log entries to show.")
def audit_log(vault_name, limit):
    """View the audit trail for a vault."""
    identity = get_user_identity()
    if not identity:
        click.echo(NO_IDENTITY_MSG)
        return

    vm = VaultManager()
    try:
        entries = vm.get_audit_log(vault_name, limit=limit)
    except (PermissionError, ValueError) as e:
        click.echo(f"❌ {e}")
        return

    if not entries:
        click.echo(f"📋 No audit log entries for vault '{vault_name}'.")
        return

    click.echo(f"\n📋 Audit log for vault '{vault_name}' (last {limit}):\n")
    click.echo(f"{'Timestamp':20}  {'User':14}  {'Action':15}  {'Details'}")
    click.echo("-" * 80)
    for entry in entries:
        tstr = datetime.datetime.fromtimestamp(entry["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        click.echo(f"{tstr:20}  {entry['user_id']:14}  {entry['action']:15}  {entry.get('details', '')}")


@team.command("delete-vault")
@click.argument("name")
@click.confirmation_option(prompt="Are you sure you want to permanently delete this vault and all its secrets?")
@master_password_required
def delete_vault_cmd(name):
    """Permanently delete a vault and all its secrets."""
    store = SecretStore()
    store.require_fernet()

    vm = VaultManager()
    try:
        vm.delete_vault(name)
        click.echo(f"🗑️  Vault '{name}' has been permanently deleted.")
    except (ValueError, PermissionError) as e:
        click.echo(f"❌ {e}")
