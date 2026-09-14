import os
import uuid
import time
import base64
import sqlite3
import threading
import hashlib
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from getpass import getpass
from .log import get_logger

CONFIG_DIR = os.path.expanduser("~/.config/sinduk")
LEGACY_CONFIG_DIR = os.path.expanduser("~/.config/pacli")
BUNDLE_MAGIC = b"SINDUK1"
BUNDLE_SALT_SIZE = 16


def migrate_legacy_config(src=LEGACY_CONFIG_DIR, dst=CONFIG_DIR):
    """
    Auto-migrate existing data from ~/.config/pacli to ~/.config/sinduk.
    Preserves all existing secrets, salts, and identity.
    """
    if not os.path.exists(src):
        return

    marker = os.path.join(dst, ".migrated_from_pacli")
    if os.path.exists(marker):
        return

    legacy_salt = os.path.join(src, "salt.bin")
    if not os.path.exists(legacy_salt):
        return

    try:
        import shutil

        os.makedirs(dst, exist_ok=True)
        for item in os.listdir(src):
            s = os.path.join(src, item)
            d = os.path.join(dst, item)
            if item in ("pacli.log", "webui.log", "webui.pid", "webui_state.json"):
                continue
            if os.path.isdir(s):
                if os.path.exists(d):
                    shutil.rmtree(d)
                shutil.copytree(s, d)
            else:
                shutil.copy2(s, d)

        with open(marker, "w") as f:
            f.write("migrated")
        print("📦 Migrated existing data... ")
    except Exception as e:
        print("📦 Could not migrate existing data...")
        logger.warning(f"Failed to migrate existing data: {e}")


migrate_legacy_config()

SALT_PATH = os.path.join(CONFIG_DIR, "salt.bin")
PASSWORD_HASH_PATH = os.path.join(CONFIG_DIR, "password_hash.bin")
logger = get_logger("sinduk.store")


def get_salt():
    if not os.path.exists(SALT_PATH):
        os.makedirs(os.path.dirname(SALT_PATH), exist_ok=True)
        salt = os.urandom(16)
        with open(SALT_PATH, "wb") as f:
            f.write(salt)
        return salt
    with open(SALT_PATH, "rb") as f:
        return f.read()


class SecretStore:
    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(CONFIG_DIR, "sqlite3.db")
        self.db_path = os.path.expanduser(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._local = threading.local()
        self.fernet: Optional[Fernet] = None
        self._get_conn().execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                label TEXT,
                value_encrypted TEXT,
                type TEXT,
                creation_time INTEGER,
                update_time INTEGER
            )
            """)
        self._get_conn().commit()

    def _get_conn(self):
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        return self._local.conn

    @property
    def conn(self):
        return self._get_conn()

    def is_master_set(self):
        return os.path.exists(SALT_PATH + ".set")

    def setup_first_run(self):
        """
        Triggered automatically on first ever use — no `sinduk init` needed.
        Prompts the user to create a master password interactively.
        """
        print("\n🔐 Welcome to sinduk! Set up your master password to get started.")
        print("This password encrypts all your secrets — keep it safe.\n")
        salt = get_salt()
        while True:
            pw1 = getpass("Set a master password: ")
            if not pw1:
                print("Password cannot be empty. Try again.")
                continue
            pw2 = getpass("Confirm master password: ")
            if pw1 == pw2:
                break
            print("Passwords do not match. Try again.")
        with open(SALT_PATH + ".set", "w") as f:
            f.write("set")
        password_hash = hashlib.sha256(pw1.encode()).hexdigest()
        with open(PASSWORD_HASH_PATH, "w") as f:
            f.write(password_hash)
        self.fernet = self._derive_fernet(pw1, salt)
        logger.info("Master password set on first run.")
        print("\n✅ Master password set. You're ready to go!\n")

    def set_master_password(self):
        """Explicit init path — still used by `sinduk init`."""
        salt = get_salt()
        while True:
            pw1 = getpass("Set a master password: ")
            pw2 = getpass("Confirm master password: ")
            if pw1 == pw2 and pw1:
                break
            print("Passwords do not match or empty. Try again.")
        with open(SALT_PATH + ".set", "w") as f:
            f.write("set")
        password_hash = hashlib.sha256(pw1.encode()).hexdigest()
        with open(PASSWORD_HASH_PATH, "w") as f:
            f.write(password_hash)
        self.fernet = self._derive_fernet(pw1, salt)
        logger.info("Master password set.")

    def update_master_password(self, new_password):
        salt = get_salt()
        self.fernet = self._derive_fernet(new_password, salt)
        password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        with open(PASSWORD_HASH_PATH, "w") as f:
            f.write(password_hash)
        logger.info("Master password updated.")

    def _derive_fernet(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
            backend=default_backend(),
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def require_fernet(self, password=None, interactive=True) -> Fernet:
        """
        Ensures the Fernet key is ready and returns it.
        On first-ever run (no master set) triggers interactive setup automatically.
        """
        if not self.is_master_set():
            if not interactive:
                raise RuntimeError("Master password is not set")
            self.setup_first_run()
        if self.fernet is not None:
            return self.fernet
        salt = get_salt()
        if password is None:
            password = os.environ.get("SINDUK_MASTER_PASSWORD") or os.environ.get("PACLI_MASTER_PASSWORD")
        if password is None:
            if not interactive:
                raise RuntimeError("Master key is not loaded")
            password = getpass("Enter master password: ")
        self.fernet = self._derive_fernet(password, salt)
        if self.fernet is None:
            raise RuntimeError("Master key is not loaded")
        return self.fernet

    def save_secret(self, label, secret, secret_type):
        fernet = self.require_fernet()
        encrypted = fernet.encrypt(secret.encode()).decode()
        now = int(time.time())
        new_id = uuid.uuid4().hex[:8]
        self.conn.execute(
            "INSERT INTO secrets (id, label, value_encrypted, type, creation_time, update_time) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (new_id, label, encrypted, secret_type, now, now),
        )
        self.conn.commit()

    def get_secret(self, label):
        fernet = self.require_fernet()
        try:
            cursor = self.conn.execute(
                "SELECT value_encrypted, type FROM secrets WHERE label = ? ORDER BY rowid DESC LIMIT 1",
                (label,),
            )
            row = cursor.fetchone()
            if row:
                try:
                    value = fernet.decrypt(row[0].encode()).decode()
                    return value, row[1]
                except Exception as e:
                    logger.error(f"Decryption failed for label {label}: {e}")
                    return None, None
            return None, None
        except Exception as e:
            logger.error(f"Database error on get_secret for {label}: {e}")
            return None, None

    def list_secrets(self):
        return [
            (row[0], row[1], row[2], row[3], row[4])
            for row in self.conn.execute("SELECT id, label, type, creation_time, update_time FROM secrets")
        ]

    def update_secret(self, id, secret):
        fernet = self.require_fernet()
        encrypted = fernet.encrypt(secret.encode()).decode()
        now = int(time.time())
        self.conn.execute("UPDATE secrets SET value_encrypted = ?, update_time = ? WHERE id = ?", (encrypted, now, id))
        self.conn.commit()

    def delete_secret(self, id):
        self.require_fernet()
        self.conn.execute("DELETE FROM secrets WHERE id = ?", (id,))
        self.conn.commit()

    def get_secret_by_id(self, id):
        fernet = self.require_fernet()
        cursor = self.conn.execute(
            "SELECT label, value_encrypted, type, creation_time, update_time FROM secrets WHERE id = ?",
            (id,),
        )
        row = cursor.fetchone()
        if row:
            try:
                value = fernet.decrypt(row[1].encode()).decode()
                return {
                    "id": id,
                    "label": row[0],
                    "secret": value,
                    "type": row[2],
                    "creation_time": row[3],
                    "update_time": row[4],
                }
            except Exception as e:
                logger.error(f"Decryption failed for id {id}: {e}")
                return None
        logger.info(f"No secret found with id: {id}")
        return None

    def get_secrets_by_label(self, label):
        fernet = self.require_fernet()
        results = []
        for row in self.conn.execute(
            "SELECT id, value_encrypted, type, creation_time, update_time FROM secrets "
            "WHERE label = ? ORDER BY creation_time DESC",
            (label,),
        ):
            try:
                value = fernet.decrypt(row[1].encode()).decode()
            except Exception as e:
                logger.error(f"Decryption failed for id {row[0]}: {e}")
                value = None
            results.append(
                {
                    "id": row[0],
                    "secret": value,
                    "type": row[2],
                    "creation_time": row[3],
                    "update_time": row[4],
                }
            )
        return results

    def verify_master_password(self, password):
        try:
            if os.path.exists(PASSWORD_HASH_PATH):
                with open(PASSWORD_HASH_PATH, "r") as f:
                    stored_hash = f.read().strip()
                return hashlib.sha256(password.encode()).hexdigest() == stored_hash
            # Fallback: attempt decryption
            salt = get_salt()
            test_fernet = self._derive_fernet(password, salt)
            cursor = self.conn.execute("SELECT value_encrypted FROM secrets LIMIT 1")
            row = cursor.fetchone()
            if row:
                test_fernet.decrypt(row[0].encode())
                return True
            return False
        except Exception as e:
            logger.error(f"Master password verification failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Encrypted Cloud Backup / Restore
    # ------------------------------------------------------------------

    def export_encrypted_backup(self, backup_password: str) -> bytes:
        """
        Serialise all secrets to JSON, then encrypt with a separate
        backup password derived from a fresh self-contained salt.
        Safe to upload to cloud storage and restore on any device.
        """
        import json

        fernet = self.require_fernet()
        salt = os.urandom(BUNDLE_SALT_SIZE)
        backup_fernet = self._derive_fernet(backup_password, salt)

        records = []
        for row in self.conn.execute(
            "SELECT id, label, value_encrypted, type, creation_time, update_time FROM secrets"
        ):
            try:
                plain = fernet.decrypt(row[2].encode()).decode()
            except Exception as e:
                logger.error(f"Skipping {row[0]} during backup: {e}")
                continue
            records.append(
                {
                    "id": row[0],
                    "label": row[1],
                    "secret": plain,
                    "type": row[3],
                    "creation_time": row[4],
                    "update_time": row[5],
                }
            )

        payload = json.dumps(records).encode()
        encrypted = backup_fernet.encrypt(payload)
        return BUNDLE_MAGIC + salt + encrypted

    def import_encrypted_backup(self, blob: bytes, backup_password: str, merge: bool = True) -> dict:
        """
        Decrypt a backup blob and import secrets.

        Args:
            blob: Encrypted backup bytes (.sinduk or .pacli file)
            backup_password: Password used when backup was created
            merge: True = skip duplicates; False = overwrite

        Returns:
            {"imported": int, "skipped": int, "errors": int}
        """
        import json

        fernet = self.require_fernet()
        if blob.startswith(BUNDLE_MAGIC) and len(blob) > len(BUNDLE_MAGIC) + BUNDLE_SALT_SIZE:
            salt = blob[len(BUNDLE_MAGIC) : len(BUNDLE_MAGIC) + BUNDLE_SALT_SIZE]
            ciphertext = blob[len(BUNDLE_MAGIC) + BUNDLE_SALT_SIZE :]
        else:
            salt = get_salt()
            ciphertext = blob

        backup_fernet = self._derive_fernet(backup_password, salt)

        try:
            payload = backup_fernet.decrypt(ciphertext)
        except Exception:
            raise ValueError("Wrong backup password or corrupted file.")

        records = json.loads(payload.decode())
        stats = {"imported": 0, "skipped": 0, "errors": 0}

        for rec in records:
            try:
                existing = self.conn.execute("SELECT id FROM secrets WHERE id = ?", (rec["id"],)).fetchone()
                encrypted = fernet.encrypt(rec["secret"].encode()).decode()

                if existing:
                    if merge:
                        stats["skipped"] += 1
                        continue
                    self.conn.execute(
                        "UPDATE secrets SET label=?, value_encrypted=?, type=?, "
                        "creation_time=?, update_time=? WHERE id=?",
                        (rec["label"], encrypted, rec["type"], rec["creation_time"], rec["update_time"], rec["id"]),
                    )
                else:
                    self.conn.execute(
                        "INSERT INTO secrets (id, label, value_encrypted, type, creation_time, update_time) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (rec["id"], rec["label"], encrypted, rec["type"], rec["creation_time"], rec["update_time"]),
                    )
                stats["imported"] += 1
            except Exception as e:
                logger.error(f"Error importing {rec.get('id')}: {e}")
                stats["errors"] += 1

        self.conn.commit()
        return stats
