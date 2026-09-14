"""
Vault management for team secrets sharing.

Each vault is an isolated secrets store with its own:
- SQLite database (vault.db)
- Encryption salt (vault_salt.bin)
- Symmetric key wrapped per-member (vault_key.enc)

Vaults allow secrets to be grouped and shared independently while
preserving sinduk's local-first, zero-knowledge philosophy.
"""

import json
import os
import time
import uuid
import sqlite3
import base64
import threading
from enum import Enum
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from .log import get_logger

logger = get_logger("sinduk.vault")

VAULTS_KEY = "vaults"
VAULT_DB_NAME = "vault.db"
SINDUK_DIR = os.path.expanduser("~/.config/sinduk")
PACLI_DIR = SINDUK_DIR  # Backwards-compatibility alias
VAULTS_DIR = os.path.join(SINDUK_DIR, VAULTS_KEY)
REGISTRY_PATH = os.path.join(VAULTS_DIR, "vault_registry.json")
USER_IDENTITY_PATH = os.path.join(SINDUK_DIR, "user_identity.json")


class VaultRole(str, Enum):
    """Roles for vault access control."""

    VIEWER = "viewer"
    EDITOR = "editor"
    ADMIN = "admin"


# Permission matrix: what each role can do
ROLE_PERMISSIONS = {
    VaultRole.VIEWER: {"list_secrets", "get_secret", "audit_log"},
    VaultRole.EDITOR: {"list_secrets", "get_secret", "audit_log", "create_secret", "update_secret", "delete_secret"},
    VaultRole.ADMIN: {
        "list_secrets",
        "get_secret",
        "audit_log",
        "create_secret",
        "update_secret",
        "delete_secret",
        "add_member",
        "remove_member",
        "set_role",
        "delete_vault",
        "rotate_key",
    },
}


def get_user_identity() -> dict:
    """
    Get or create a local user identity.

    Returns:
        dict with 'user_id' and 'user_name'
    """
    if os.path.exists(USER_IDENTITY_PATH):
        with open(USER_IDENTITY_PATH, "r") as f:
            return json.load(f)
    return {}


def set_user_identity(user_name: str) -> dict:
    """
    Create or update local user identity.

    Args:
        user_name: Human-readable name for this user

    Returns:
        dict with 'user_id' and 'user_name'
    """
    existing = get_user_identity()
    user_id = existing.get("user_id", uuid.uuid4().hex[:12])
    identity = {
        "user_id": user_id,
        "user_name": user_name,
        "created_at": existing.get("created_at", int(time.time())),
        "updated_at": int(time.time()),
    }
    os.makedirs(os.path.dirname(USER_IDENTITY_PATH), exist_ok=True)
    with open(USER_IDENTITY_PATH, "w") as f:
        json.dump(identity, f, indent=2)
    logger.info(f"User identity set: {user_id} ({user_name})")
    return identity


class VaultManager:
    """
    Manages vault lifecycle, membership, and encryption.

    Each vault has:
    - Its own SQLite DB for secrets
    - A unique salt for key derivation
    - A symmetric vault key, wrapped (encrypted) with each member's master key
    - An audit log tracking all operations
    """

    def __init__(self):
        os.makedirs(VAULTS_DIR, exist_ok=True)
        self._registry = self._load_registry()
        self._vault_fernets: dict[str, Fernet] = {}
        self._local = threading.local()

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------

    def _load_registry(self) -> dict:
        """Load the vault registry from disk."""
        if os.path.exists(REGISTRY_PATH):
            with open(REGISTRY_PATH, "r") as f:
                return json.load(f)
        return {VAULTS_KEY: {}}

    def _save_registry(self):
        """Persist the vault registry to disk."""
        with open(REGISTRY_PATH, "w") as f:
            json.dump(self._registry, f, indent=2)

    def _validate_vault_name(self, name: str) -> str:
        """Validate vault name format and prevent directory traversal."""
        clean = os.path.basename(name.strip())
        if not clean or clean != name.strip():
            raise ValueError(f"Invalid vault name: '{name}'. Cannot contain path separators.")
        return clean

    def _get_vault_dir(self, vault_name: str) -> str:
        """Securely get absolute path to vault directory."""
        clean = self._validate_vault_name(vault_name)
        base = os.path.abspath(VAULTS_DIR)
        path = os.path.abspath(os.path.join(base, clean))
        if not path.startswith(base):
            raise ValueError("Path traversal attempt detected.")
        return path

    # ------------------------------------------------------------------
    # Vault CRUD
    # ------------------------------------------------------------------

    def create_vault(self, name: str, description: str = "", master_fernet: Fernet | None = None) -> dict:
        """
        Create a new vault with its own encryption key.

        Args:
            name: Unique vault name (alphanumeric + hyphens)
            description: Optional description
            master_fernet: The creator's personal Fernet instance (to wrap the vault key)

        Returns:
            Vault metadata dict

        Raises:
            ValueError: If name is invalid or already exists
        """
        name = name.strip().lower()
        if not name or not all(c.isalnum() or c in "-_" for c in name):
            raise ValueError("Vault name must be alphanumeric with hyphens/underscores only")
        if name in self._registry[VAULTS_KEY]:
            raise ValueError(f"Vault '{name}' already exists")

        identity = get_user_identity()
        if not identity:
            raise RuntimeError("User identity not set. Run 'sinduk team init' first.")

        user_id = identity["user_id"]
        vault_id = uuid.uuid4().hex[:8]
        vault_dir = self._get_vault_dir(name)
        os.makedirs(vault_dir, mode=0o700, exist_ok=True)

        # Generate unique salt for this vault
        vault_salt = os.urandom(16)
        salt_path = os.path.join(vault_dir, "vault_salt.bin")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        with open(os.open(salt_path, flags, 0o600), "wb") as f:
            f.write(vault_salt)

        # Generate a random vault key (32 bytes, base64-encoded for Fernet)
        vault_key = Fernet.generate_key()

        # Wrap (encrypt) the vault key with the creator's master Fernet
        if master_fernet is None:
            raise RuntimeError("Master Fernet key required to create vault")
        wrapped_key = master_fernet.encrypt(vault_key)

        # Store the wrapped key
        key_path = os.path.join(vault_dir, "vault_key.enc")
        with open(os.open(key_path, flags, 0o600), "wb") as f:
            f.write(wrapped_key)

        # Initialize vault database
        db_path = os.path.join(vault_dir, VAULT_DB_NAME)
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                label TEXT,
                value_encrypted TEXT,
                type TEXT,
                created_by TEXT,
                creation_time INTEGER,
                update_time INTEGER
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS members (
                user_id TEXT PRIMARY KEY,
                user_name TEXT,
                role TEXT NOT NULL DEFAULT 'viewer',
                wrapped_key BLOB,
                added_at INTEGER
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                action TEXT,
                target_id TEXT,
                details TEXT,
                timestamp INTEGER
            )
        """)
        # Add creator as admin
        conn.execute(
            "INSERT INTO members (user_id, user_name, role, wrapped_key, added_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, identity["user_name"], VaultRole.ADMIN.value, wrapped_key, int(time.time())),
        )
        conn.commit()
        conn.close()

        # Update registry
        now = int(time.time())
        vault_meta = {
            "id": vault_id,
            "name": name,
            "description": description,
            "owner": user_id,
            "role_default": VaultRole.VIEWER.value,
            "created_at": now,
            "updated_at": now,
        }
        self._registry[VAULTS_KEY][name] = vault_meta
        self._save_registry()

        # Log creation
        self._log_audit(name, user_id, "create_vault", vault_id, f"Vault '{name}' created")

        logger.info("Vault created by %s", user_id)
        return vault_meta

    def list_vaults(self) -> list[dict]:
        """
        List all vaults the current user has access to.

        Returns:
            List of vault metadata dicts with the user's role
        """
        identity = get_user_identity()
        if not identity:
            return []

        user_id = identity["user_id"]
        result = []

        for name, meta in self._registry[VAULTS_KEY].items():
            vault_dir = os.path.join(VAULTS_DIR, name)
            db_path = os.path.join(vault_dir, VAULT_DB_NAME)
            if not os.path.exists(db_path):
                continue

            conn = sqlite3.connect(db_path)
            row = conn.execute("SELECT role FROM members WHERE user_id = ?", (user_id,)).fetchone()
            conn.close()

            if row:
                vault_info = {**meta, "role": row[0]}
                # Count secrets
                conn = sqlite3.connect(db_path)
                count = conn.execute("SELECT COUNT(*) FROM secrets").fetchone()[0]
                conn.close()
                vault_info["secret_count"] = count
                result.append(vault_info)

        return result

    def get_vault(self, name: str) -> dict | None:
        """Get vault metadata by name."""
        return self._registry[VAULTS_KEY].get(name)

    def delete_vault(self, name: str):
        """
        Delete a vault and all its data.

        Args:
            name: Vault name

        Raises:
            ValueError: If vault doesn't exist
            PermissionError: If caller is not admin
        """
        if name not in self._registry[VAULTS_KEY]:
            raise ValueError(f"Vault '{name}' not found")

        self._check_permission(name, "delete_vault")

        vault_dir = self._get_vault_dir(name)
        import shutil

        if os.path.exists(vault_dir):
            shutil.rmtree(vault_dir)

        del self._registry[VAULTS_KEY][name]
        self._save_registry()

        # Clear cached fernet
        self._vault_fernets.pop(name, None)

        logger.info("Vault deleted")

    # ------------------------------------------------------------------
    # Vault Key Management
    # ------------------------------------------------------------------

    def unlock_vault(self, name: str, master_fernet: Fernet) -> Fernet:
        """
        Unlock a vault by unwrapping its key with the user's master Fernet.

        Args:
            name: Vault name
            master_fernet: The user's personal Fernet instance

        Returns:
            The vault's symmetric Fernet instance

        Raises:
            ValueError: If vault doesn't exist
            PermissionError: If user is not a member of this vault
        """
        if name in self._vault_fernets:
            return self._vault_fernets[name]

        if name not in self._registry[VAULTS_KEY]:
            raise ValueError(f"Vault '{name}' not found")

        identity = get_user_identity()
        if not identity:
            raise PermissionError("No user identity configured. Run 'sinduk team init' first.")

        user_id = identity["user_id"]
        vault_dir = self._get_vault_dir(name)
        db_path = os.path.join(vault_dir, VAULT_DB_NAME)

        if not os.path.exists(db_path):
            raise ValueError(f"Vault database for '{name}' not found")

        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT wrapped_key FROM members WHERE user_id = ?", (user_id,)).fetchone()
        conn.close()

        if not row:
            raise PermissionError(f"You are not a member of vault '{name}'")

        wrapped_key = row[0]
        if isinstance(wrapped_key, str):
            wrapped_key_bytes = wrapped_key.encode()
        else:
            wrapped_key_bytes = bytes(wrapped_key)

        try:
            raw_vault_key = master_fernet.decrypt(wrapped_key_bytes)
        except Exception:
            raise PermissionError("Failed to unwrap vault key. Incorrect master password.")

        vault_fernet = Fernet(raw_vault_key)
        self._vault_fernets[name] = vault_fernet
        return vault_fernet

    def get_raw_vault_key(self, name: str, master_fernet: Fernet) -> bytes:
        """Get the raw 32-byte symmetric key for a vault."""
        identity = get_user_identity()
        if not identity:
            raise PermissionError("No user identity configured")
        user_id = identity["user_id"]
        vault_dir = self._get_vault_dir(name)
        db_path = os.path.join(vault_dir, VAULT_DB_NAME)

        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT wrapped_key FROM members WHERE user_id = ?", (user_id,)).fetchone()
        conn.close()

        if not row:
            raise PermissionError(f"You are not a member of vault '{name}'")

        wrapped_key = row[0]
        if isinstance(wrapped_key, str):
            wrapped_key_bytes = wrapped_key.encode()
        else:
            wrapped_key_bytes = bytes(wrapped_key)

        return master_fernet.decrypt(wrapped_key_bytes)

    # ------------------------------------------------------------------
    # Membership & RBAC
    # ------------------------------------------------------------------

    def _check_permission(self, vault_name: str, action: str):
        """Verify the current user has permission to perform an action."""
        identity = get_user_identity()
        if not identity:
            raise PermissionError("No user identity configured. Run 'sinduk team init' first.")

        user_id = identity["user_id"]
        vault_dir = self._get_vault_dir(vault_name)
        db_path = os.path.join(vault_dir, VAULT_DB_NAME)

        if not os.path.exists(db_path):
            raise ValueError(f"Vault '{vault_name}' not found")

        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT role FROM members WHERE user_id = ?", (user_id,)).fetchone()
        conn.close()

        if not row:
            raise PermissionError(f"You are not a member of vault '{vault_name}'")

        role = VaultRole(row[0])
        if action not in ROLE_PERMISSIONS.get(role, set()):
            raise PermissionError(f"Role '{role.value}' does not have permission to '{action}'")

    def add_member(
        self,
        vault_name: str,
        target_user_id: str,
        target_user_name: str,
        role: str,
        master_fernet: Fernet,
    ):
        """
        Add a new member to a vault, wrapping the vault key for them.

        Args:
            vault_name: Vault name
            target_user_id: The member's user ID
            target_user_name: Display name for the member
            role: 'viewer', 'editor', or 'admin'
            master_fernet: Adder's master Fernet to unlock the vault key
        """
        self._check_permission(vault_name, "add_member")

        if role not in [r.value for r in VaultRole]:
            raise ValueError(f"Invalid role: {role}. Must be one of: viewer, editor, admin")

        self.unlock_vault(vault_name, master_fernet)

        # Get the raw vault key from adder's wrapped copy
        vault_dir = self._get_vault_dir(vault_name)
        identity = get_user_identity()
        db_path = os.path.join(vault_dir, VAULT_DB_NAME)
        conn = sqlite3.connect(db_path)

        # Check if already a member
        existing = conn.execute("SELECT user_id FROM members WHERE user_id = ?", (target_user_id,)).fetchone()
        if existing:
            conn.close()
            raise ValueError(f"User '{target_user_id}' is already a member of vault '{vault_name}'")

        raw_vault_key = self.get_raw_vault_key(vault_name, master_fernet)

        # Wrap the key for the new member (for now, using same key since we don't have their master pass)
        wrapped_for_member = master_fernet.encrypt(raw_vault_key)

        now = int(time.time())
        conn.execute(
            "INSERT INTO members (user_id, user_name, role, wrapped_key, added_at) VALUES (?, ?, ?, ?, ?)",
            (target_user_id, target_user_name, role, wrapped_for_member, now),
        )
        conn.commit()
        conn.close()

        self._log_audit(
            vault_name,
            identity["user_id"],
            "add_member",
            target_user_id,
            f"Added {target_user_name} as {role}",
        )
        logger.info(f"Added member {target_user_name} ({target_user_id}) to vault '{vault_name}' as {role}")

    def remove_member(self, vault_name: str, target_user_id: str):
        """Remove a member from a vault."""
        self._check_permission(vault_name, "remove_member")

        identity = get_user_identity()
        if target_user_id == identity["user_id"]:
            raise ValueError("Cannot remove yourself from the vault")

        vault_dir = self._get_vault_dir(vault_name)
        db_path = os.path.join(vault_dir, VAULT_DB_NAME)
        conn = sqlite3.connect(db_path)

        cursor = conn.execute("DELETE FROM members WHERE user_id = ?", (target_user_id,))
        conn.commit()
        conn.close()

        if cursor.rowcount == 0:
            raise ValueError(f"User '{target_user_id}' is not a member of vault '{vault_name}'")

        self._log_audit(
            vault_name,
            identity["user_id"],
            "remove_member",
            target_user_id,
            f"Removed user {target_user_id}",
        )
        logger.info(f"Removed member {target_user_id} from vault '{vault_name}'")

    def set_member_role(self, vault_name: str, target_user_id: str, new_role: str):
        """Change a member's role in a vault."""
        self._check_permission(vault_name, "set_role")

        if new_role not in [r.value for r in VaultRole]:
            raise ValueError(f"Invalid role: {new_role}. Must be one of: viewer, editor, admin")

        vault_dir = self._get_vault_dir(vault_name)
        db_path = os.path.join(vault_dir, VAULT_DB_NAME)
        conn = sqlite3.connect(db_path)

        cursor = conn.execute("UPDATE members SET role = ? WHERE user_id = ?", (new_role, target_user_id))
        conn.commit()
        conn.close()

        if cursor.rowcount == 0:
            raise ValueError(f"User '{target_user_id}' is not a member of vault '{vault_name}'")

        identity = get_user_identity()
        self._log_audit(
            vault_name,
            identity["user_id"],
            "set_role",
            target_user_id,
            f"Changed role to {new_role}",
        )

    def list_members(self, vault_name: str) -> list[dict]:
        """List all members of a vault."""
        vault_dir = self._get_vault_dir(vault_name)
        db_path = os.path.join(vault_dir, VAULT_DB_NAME)
        if not os.path.exists(db_path):
            return []
        conn = sqlite3.connect(db_path)
        rows = conn.execute("SELECT user_id, user_name, role, added_at FROM members").fetchall()
        conn.close()
        return [{"user_id": r[0], "user_name": r[1], "role": r[2], "added_at": r[3]} for r in rows]

    # ------------------------------------------------------------------
    # Vault Secrets Operations
    # ------------------------------------------------------------------

    def _get_vault_conn(self, vault_name: str) -> sqlite3.Connection:
        """Get a thread-local connection to a vault's database."""
        attr = f"vault_conn_{vault_name}"
        if not hasattr(self._local, attr) or getattr(self._local, attr) is None:
            vault_dir = self._get_vault_dir(vault_name)
            db_path = os.path.join(vault_dir, VAULT_DB_NAME)
            setattr(self._local, attr, sqlite3.connect(db_path, check_same_thread=False))
        return getattr(self._local, attr)

    def save_secret(self, vault_name: str, label: str, secret: str, secret_type: str, master_fernet: Fernet):
        """Save a secret to a vault."""
        self._check_permission(vault_name, "create_secret")
        vault_fernet = self.unlock_vault(vault_name, master_fernet)

        identity = get_user_identity()
        encrypted = vault_fernet.encrypt(secret.encode()).decode()
        now = int(time.time())
        new_id = uuid.uuid4().hex[:8]

        conn = self._get_vault_conn(vault_name)
        conn.execute(
            "INSERT INTO secrets (id, label, value_encrypted, type, created_by, creation_time, update_time) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (new_id, label, encrypted, secret_type, identity.get("user_id", ""), now, now),
        )
        conn.commit()

        self._log_audit(
            vault_name,
            identity.get("user_id", ""),
            "create",
            new_id,
            f"Created secret '{label}'",
        )
        logger.info("Secret saved to vault")
        return new_id

    def get_secret(self, vault_name: str, secret_id: str, master_fernet: Fernet) -> dict | None:
        """Get a secret from a vault by ID."""
        self._check_permission(vault_name, "get_secret")
        vault_fernet = self.unlock_vault(vault_name, master_fernet)

        conn = self._get_vault_conn(vault_name)
        row = conn.execute(
            "SELECT id, label, value_encrypted, type, created_by, creation_time, update_time "
            "FROM secrets WHERE id = ?",
            (secret_id,),
        ).fetchone()

        if not row:
            return None

        try:
            value = vault_fernet.decrypt(row[2].encode()).decode()
        except Exception as e:
            logger.error("Decryption failed for vault secret %s", e)
            return None

        identity = get_user_identity()
        self._log_audit(vault_name, identity["user_id"], "read", secret_id, f"Read secret '{row[1]}'")

        return {
            "id": row[0],
            "label": row[1],
            "secret": value,
            "type": row[3],
            "created_by": row[4],
            "creation_time": row[5],
            "update_time": row[6],
        }

    def get_secret_by_id(self, vault_name: str, secret_id: str, master_fernet: Fernet) -> dict | None:
        """Alias for get_secret."""
        return self.get_secret(vault_name, secret_id, master_fernet)

    def list_secrets(self, vault_name: str) -> list[tuple]:
        """List all secrets in a vault (without decrypting values)."""
        self._check_permission(vault_name, "list_secrets")

        conn = self._get_vault_conn(vault_name)
        return [
            (row[0], row[1], row[2], row[3], row[4], row[5])
            for row in conn.execute(
                "SELECT id, label, type, created_by, creation_time, update_time "
                "FROM secrets ORDER BY creation_time DESC"
            )
        ]

    def update_secret(self, vault_name: str, secret_id: str, new_value: str, master_fernet: Fernet):
        """Update an existing secret in a vault."""
        self._check_permission(vault_name, "update_secret")
        vault_fernet = self.unlock_vault(vault_name, master_fernet)

        encrypted = vault_fernet.encrypt(new_value.encode()).decode()
        now = int(time.time())

        conn = self._get_vault_conn(vault_name)
        cursor = conn.execute(
            "UPDATE secrets SET value_encrypted = ?, update_time = ? WHERE id = ?",
            (encrypted, now, secret_id),
        )
        conn.commit()

        if cursor.rowcount == 0:
            raise ValueError(f"Secret with ID '{secret_id}' not found in vault '{vault_name}'")

        identity = get_user_identity()
        self._log_audit(vault_name, identity.get("user_id", ""), "update", secret_id, "Updated secret value")
        logger.info(f"Secret {secret_id} updated in vault '{vault_name}'")

    def delete_secret(self, vault_name: str, secret_id: str):
        """Delete a secret by ID from a vault."""
        self._check_permission(vault_name, "delete_secret")

        conn = self._get_vault_conn(vault_name)
        cursor = conn.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
        conn.commit()

        if cursor.rowcount == 0:
            raise ValueError(f"Secret with ID '{secret_id}' not found in vault '{vault_name}'")

        identity = get_user_identity()
        self._log_audit(vault_name, identity.get("user_id", ""), "delete", secret_id, "Deleted secret")
        logger.info(f"Secret {secret_id} deleted from vault '{vault_name}'")

    def get_secrets_by_label(self, vault_name: str, label: str, master_fernet: Fernet) -> list[dict]:
        """Retrieve secrets matching label from a vault."""
        self._check_permission(vault_name, "get_secret")
        vault_fernet = self.unlock_vault(vault_name, master_fernet)

        conn = self._get_vault_conn(vault_name)
        rows = conn.execute(
            "SELECT id, label, value_encrypted, type, created_by, creation_time, update_time "
            "FROM secrets WHERE label = ? ORDER BY creation_time DESC",
            (label,),
        ).fetchall()

        identity = get_user_identity()
        results = []
        for r in rows:
            try:
                decrypted = vault_fernet.decrypt(r[2].encode()).decode()
            except Exception as e:
                logger.error("Failed to decrypt secret in vault: %s", e)
                decrypted = None
            results.append(
                {
                    "id": r[0],
                    "label": r[1],
                    "secret": decrypted,
                    "type": r[3],
                    "created_by": r[4],
                    "creation_time": r[5],
                    "update_time": r[6],
                }
            )

        if results and results[0]["secret"] is not None:
            target_id = str(results[0].get("id") or "")
            self._log_audit(vault_name, identity.get("user_id", ""), "read", target_id, f"Read secret '{label}'")

        return results

    # ------------------------------------------------------------------
    # Audit Log
    # ------------------------------------------------------------------

    def _log_audit(
        self,
        vault_name: str,
        user_id: str,
        action: str,
        target_id: str | None = "",
        details: str = "",
    ):
        """Write an entry to the vault's audit log."""
        try:
            conn = self._get_vault_conn(vault_name)
            conn.execute(
                "INSERT INTO audit_log (id, user_id, action, target_id, details, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (uuid.uuid4().hex[:8], user_id, action, target_id or "", details, int(time.time())),
            )
            conn.commit()
        except Exception as e:
            logger.error("Failed to write audit log: %s", e)

    def get_audit_log(self, vault_name: str, limit: int = 50) -> list[dict]:
        """Retrieve audit log entries for a vault."""
        self._check_permission(vault_name, "audit_log")

        conn = self._get_vault_conn(vault_name)
        rows = conn.execute(
            "SELECT id, user_id, action, target_id, details, timestamp "
            "FROM audit_log ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()

        return [
            {
                "id": r[0],
                "user_id": r[1],
                "action": r[2],
                "target_id": r[3],
                "details": r[4],
                "timestamp": r[5],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Vault Backup / Restore (Phase 2)
    # ------------------------------------------------------------------

    def export_vault_backup(self, vault_name: str, backup_password: str, master_fernet: Fernet) -> bytes:
        """
        Export all secrets in a vault to an encrypted backup blob.

        The secrets are decrypted with the vault key and re-encrypted with
        a backup password so the file is safe to share via any channel.

        Args:
            vault_name: Name of the vault to export
            backup_password: Password to encrypt the backup
            master_fernet: User's personal Fernet (to unwrap vault key)

        Returns:
            Encrypted backup bytes
        """
        self._check_permission(vault_name, "get_secret")
        vault_fernet = self.unlock_vault(vault_name, master_fernet)

        from .store import get_salt

        salt = get_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
            backend=default_backend(),
        )
        backup_key = base64.urlsafe_b64encode(kdf.derive(backup_password.encode()))
        backup_fernet = Fernet(backup_key)

        conn = self._get_vault_conn(vault_name)
        records = []
        for row in conn.execute(
            "SELECT id, label, value_encrypted, type, created_by, creation_time, update_time FROM secrets"
        ):
            try:
                plain = vault_fernet.decrypt(row[2].encode()).decode()
            except Exception as e:
                logger.error(f"Skipping {row[0]} during vault backup: {e}")
                continue
            records.append(
                {
                    "id": row[0],
                    "label": row[1],
                    "secret": plain,
                    "type": row[3],
                    "created_by": row[4],
                    "creation_time": row[5],
                    "update_time": row[6],
                }
            )

        # Include vault metadata & members
        meta = self.get_vault(vault_name)
        members = self.list_members(vault_name)

        payload = json.dumps(
            {
                "vault": meta,
                "members": members,
                "secrets": records,
            }
        ).encode()
        return backup_fernet.encrypt(payload)

    def import_vault_backup(
        self,
        vault_name: str,
        blob: bytes,
        backup_password: str,
        master_fernet: Fernet,
        merge: bool = True,
    ) -> dict:
        """
        Import secrets from an encrypted vault backup.

        If the vault doesn't exist yet, it will be created.
        If it exists, secrets are merged or overwritten based on the merge flag.

        Args:
            vault_name: Target vault name
            blob: Encrypted backup bytes
            backup_password: Password used when backup was created
            master_fernet: User's personal Fernet
            merge: True = skip duplicates; False = overwrite

        Returns:
            {"imported": int, "skipped": int, "errors": int}
        """
        from .store import get_salt

        salt = get_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
            backend=default_backend(),
        )
        backup_key = base64.urlsafe_b64encode(kdf.derive(backup_password.encode()))
        backup_fernet = Fernet(backup_key)

        try:
            payload = backup_fernet.decrypt(blob)
        except Exception:
            raise ValueError("Wrong backup password or corrupted file.")

        data = json.loads(payload.decode())
        records = data.get("secrets", [])

        # Create vault if it doesn't exist
        if vault_name not in self._registry[VAULTS_KEY]:
            self.create_vault(
                vault_name, description=data.get("vault", {}).get("description", ""), master_fernet=master_fernet
            )

        vault_fernet = self.unlock_vault(vault_name, master_fernet)
        conn = self._get_vault_conn(vault_name)
        identity = get_user_identity()
        stats = {"imported": 0, "skipped": 0, "errors": 0}

        for rec in records:
            try:
                existing = conn.execute("SELECT id FROM secrets WHERE id = ?", (rec["id"],)).fetchone()
                encrypted = vault_fernet.encrypt(rec["secret"].encode()).decode()

                if existing:
                    if merge:
                        stats["skipped"] += 1
                        continue
                    conn.execute(
                        "UPDATE secrets SET label=?, value_encrypted=?, type=?, "
                        "created_by=?, creation_time=?, update_time=? WHERE id=?",
                        (
                            rec["label"],
                            encrypted,
                            rec["type"],
                            rec.get("created_by", ""),
                            rec["creation_time"],
                            rec["update_time"],
                            rec["id"],
                        ),
                    )
                else:
                    conn.execute(
                        "INSERT INTO secrets "
                        "(id, label, value_encrypted, type, created_by, creation_time, update_time) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            rec["id"],
                            rec["label"],
                            encrypted,
                            rec["type"],
                            rec.get("created_by", identity.get("user_id", "")),
                            rec["creation_time"],
                            rec["update_time"],
                        ),
                    )
                stats["imported"] += 1
            except Exception as e:
                logger.error(f"Error importing vault secret {rec.get('id')}: {e}")
                stats["errors"] += 1

        conn.commit()

        self._log_audit(
            vault_name,
            identity.get("user_id", "unknown"),
            "import",
            "",
            f"Imported {stats['imported']} secrets from backup",
        )
        return stats
