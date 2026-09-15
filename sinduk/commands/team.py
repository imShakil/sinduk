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

    store = SecretStore()
    fernet = store.fernet if store.is_master_set() and hasattr(store, "fernet") else None

    user_name = click.prompt("Enter your display name (e.g., 'John Doe')")
    identity = set_user_identity(user_name, master_fernet=fernet)
    click.echo("\n✅ Identity set!")
    click.echo(f"   User ID:     {identity['user_id']}")
    click.echo(f"   Name:        {identity['user_name']}")
    if identity.get("public_key"):
        click.echo(f"   Public Key:  x25519_pk_{identity['public_key']}")
        click.echo(f"   Fingerprint: {identity.get('fingerprint', '—')}")
    click.echo("\n💡 Run 'sinduk team whoami' or 'sinduk team id' to view your identity.")
    click.echo("   Teammates can invite you using 'sinduk team invite' or 'sinduk team add-member'.")


@team.command("whoami")
def team_whoami():
    """Show your current team identity."""
    identity = get_user_identity()
    if not identity:
        click.echo(NO_IDENTITY_MSG)
        return
    click.echo(f"👤 User ID:     {identity['user_id']}")
    click.echo(f"   Name:        {identity['user_name']}")
    if identity.get("public_key"):
        click.echo(f"   Public Key:  x25519_pk_{identity['public_key']}")
        click.echo(f"   Fingerprint: {identity.get('fingerprint', '—')}")
    cstr = datetime.datetime.fromtimestamp(identity.get("created_at", 0)).strftime("%Y-%m-%d %H:%M:%S")
    click.echo(f"   Created:     {cstr}")


@team.command("id")
@click.option("--copy", "-c", is_flag=True, default=False, help="Copy public key to clipboard.")
def team_id(copy):
    """Show your public identity for team onboarding."""
    identity = get_user_identity()
    if not identity:
        click.echo(NO_IDENTITY_MSG)
        return
    pub = identity.get("public_key", "")
    full_pub = f"x25519_pk_{pub}" if pub else ""
    click.echo(f"📋 User ID:    {identity['user_id']}")
    click.echo(f"   Name:       {identity['user_name']}")
    click.echo(f"   Public Key: {full_pub or '—'}")
    if identity.get("fingerprint"):
        click.echo(f"   Fingerprint:{identity['fingerprint']}")
    if copy and full_pub:
        try:
            import pyperclip

            pyperclip.copy(full_pub)
            click.echo("\n📋 Public key copied to clipboard!")
        except Exception:
            logger.info("Failed to copy public key to clipboard.")


def _try_auto_push(vault_name: str, fernet) -> None:
    """Helper to auto-push vault changes to sync server if configured."""
    try:
        from ..sync_client import auto_push_vault

        res = auto_push_vault(vault_name, fernet)
        if res.get("synced"):
            v_str = f" (v{res['version']})" if res.get("version") else ""
            click.echo(f"☁️ Auto-synced vault '{vault_name}'{v_str} to server.")
        elif res.get("reason") == "error":
            click.echo("⚠️ Sync note: Saved locally (sync server unreachable).")
    except Exception as e:
        logger.debug(f"Auto-push error ignored: {e}")


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
        _try_auto_push(name, fernet)
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


def _display_sync_status(sync_st: dict) -> None:
    """Print vault sync status details if available."""
    if not sync_st:
        return
    click.echo("\n🔄 Sync Status:")
    if sync_st.get("last_push_at"):
        pstr = datetime.datetime.fromtimestamp(sync_st["last_push_at"]).strftime("%Y-%m-%d %H:%M:%S")
        vstr = f" (v{sync_st['last_push_version']})" if sync_st.get("last_push_version") else ""
        click.echo(f"   Last Pushed:  {pstr}{vstr}")
    if sync_st.get("last_pull_at"):
        plstr = datetime.datetime.fromtimestamp(sync_st["last_pull_at"]).strftime("%Y-%m-%d %H:%M:%S")
        vstr = f" (v{sync_st['last_pull_version']})" if sync_st.get("last_pull_version") else ""
        click.echo(f"   Last Pulled:  {plstr}{vstr}")


def _display_members(members: list) -> None:
    """Print member list for a vault."""
    click.echo(f"\n👥 Members ({len(members)}):")
    for m in members:
        astr = datetime.datetime.fromtimestamp(m.get("added_at", 0)).strftime("%Y-%m-%d") if m.get("added_at") else ""
        pub_info = " [PK]" if m.get("public_key") else ""
        click.echo(f"   • {m['user_name']} ({m['user_id']}){pub_info}  —  {m['role']}  (since {astr})")


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

    _display_sync_status(meta.get("sync_status", {}))
    _display_members(vm.list_members(name))


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
@click.option("--pubkey", "-k", "public_key", default=None, help="Member's X25519 public key.")
@master_password_required
def add_member(vault_name, user_id, user_name, role, public_key):
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
        vm.add_member(vault_name, user_id, user_name, role, fernet, target_public_key=public_key)
        click.echo(f"✅ Added {user_name} ({user_id}) to vault '{vault_name}' as {role}.")
        _try_auto_push(vault_name, fernet)
    except (ValueError, PermissionError, RuntimeError) as e:
        click.echo(f"❌ {e}")


@team.command("remove-member")
@click.argument("vault_name")
@click.argument("user_id")
@click.option("--rotate-key/--no-rotate-key", default=True, help="Rotate vault key upon removal.")
@master_password_required
def remove_member(vault_name, user_id, rotate_key):
    """Remove a member from a vault and optionally rotate the vault key."""
    store = SecretStore()
    fernet = store.require_fernet()

    vm = VaultManager()
    try:
        if not click.confirm(f"Remove user '{user_id}' from vault '{vault_name}'?"):
            click.echo("Cancelled.")
            return
        vm.remove_member(vault_name, user_id, master_fernet=fernet, rotate_key=rotate_key)
        click.echo(f"✅ Removed {user_id} from vault '{vault_name}'.")
        if rotate_key:
            click.echo("🔄 Vault encryption key was automatically rotated to revoke removed member's access.")
        _try_auto_push(vault_name, fernet)
    except (ValueError, PermissionError) as e:
        click.echo(f"❌ {e}")


@team.command("rotate-key")
@click.argument("vault_name")
@master_password_required
def rotate_key_cmd(vault_name):
    """Rotate the symmetric encryption key for a vault.

    Re-encrypts all secrets in the vault with a fresh key and
    re-wraps the new key for all remaining active members.
    Requires admin role.
    """
    store = SecretStore()
    fernet = store.require_fernet()

    vm = VaultManager()
    try:
        if not click.confirm(f"Rotate encryption key for vault '{vault_name}'? This will re-encrypt all secrets."):
            click.echo("Cancelled.")
            return
        res = vm.rotate_vault_key(vault_name, fernet)
        click.echo(f"✅ Key rotated successfully for vault '{vault_name}'!")
        click.echo(f"   Secrets re-encrypted: {res['secrets_reencrypted']}")
        click.echo(f"   Members re-wrapped:   {res['members_rewrapped']}")
        _try_auto_push(vault_name, fernet)
    except (ValueError, PermissionError) as e:
        click.echo(f"❌ {e}")


@team.command("invite")
@click.argument("vault_name")
@click.option(
    "--role",
    "-r",
    type=click.Choice(["viewer", "editor", "admin"]),
    default="viewer",
    show_default=True,
    help="Role to grant via this invite.",
)
@click.option(
    "--expires",
    "-e",
    "expires_hours",
    type=int,
    default=24,
    show_default=True,
    help="Expiration time in hours.",
)
@master_password_required
def invite_cmd(vault_name, role, expires_hours):
    """Generate a one-time cryptographic invite token to onboard a member."""
    store = SecretStore()
    fernet = store.require_fernet()

    vm = VaultManager()
    try:
        token = vm.create_vault_invite(vault_name, role, fernet, expires_in_hours=expires_hours)
        click.echo(f"\n📨 Invite token created for vault '{vault_name}' (Role: {role}, Expires in {expires_hours}h):")
        click.echo(f"\n{token}\n")
        click.echo("💡 Share this token with your teammate via Slack, email, or chat.")
        click.echo("   They can accept it by running:")
        click.echo("   sinduk team accept <token>")
    except (ValueError, PermissionError) as e:
        click.echo(f"❌ {e}")


@team.command("accept")
@click.argument("invite_token")
@master_password_required
def accept_cmd(invite_token):
    """Accept an invite token to join a shared team vault."""
    store = SecretStore()
    fernet = store.require_fernet()

    vm = VaultManager()
    try:
        res = vm.accept_vault_invite(invite_token, fernet)
        click.echo(f"\n🎉 Successfully joined vault '{res['vault_name']}'!")
        click.echo(f"   Your Role:   {res['role']}")
        click.echo(f"   Vault ID:    {res['vault_id']}")
        if res.get("description"):
            click.echo(f"   Description: {res['description']}")
        click.echo(f"\n💡 Use 'sinduk list --vault {res['vault_name']}' to view secrets.")
        click.echo(f"   Use 'sinduk sync pull {res['vault_name']}' to sync latest changes.")
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
    fernet = store.fernet

    vm = VaultManager()
    try:
        vm.set_member_role(vault_name, user_id, role)
        click.echo(f"✅ Updated {user_id}'s role to '{role}' in vault '{vault_name}'.")
        if fernet:
            _try_auto_push(vault_name, fernet)
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
