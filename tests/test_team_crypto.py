"""
Comprehensive test suite for Phase 1 cryptographic enhancements in sinduk:
- Self-contained PBKDF2 bundle salt for cross-machine backup/sync
- X25519 user keypairs & fingerprinting
- Asymmetric ECDH key wrapping for team vault members
- Vault encryption key rotation (re-encrypting secrets and re-wrapping keys)
- Ephemeral team invite & accept flows
- Sync status tracking metadata
"""

import os
import time
import base64
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from sinduk.vault import (
    VaultManager,
    BUNDLE_MAGIC,
    BUNDLE_SALT_SIZE,
    INVITE_TOKEN_PREFIX,
    set_user_identity,
    get_user_private_key,
)


@pytest.fixture
def temp_sinduk_home(tmp_path, monkeypatch):
    """Isolate SINDUK_DIR and config paths to a temporary directory."""
    sinduk_dir = tmp_path / "sinduk_home"
    monkeypatch.setattr("sinduk.vault.SINDUK_DIR", str(sinduk_dir))
    monkeypatch.setattr("sinduk.vault.VAULTS_DIR", str(sinduk_dir / "vaults"))
    monkeypatch.setattr("sinduk.vault.REGISTRY_PATH", str(sinduk_dir / "vaults" / "vault_registry.json"))
    monkeypatch.setattr("sinduk.vault.USER_IDENTITY_PATH", str(sinduk_dir / "user_identity.json"))
    monkeypatch.setattr("sinduk.store.CONFIG_DIR", str(sinduk_dir))
    monkeypatch.setattr("sinduk.store.SALT_PATH", str(sinduk_dir / "salt.bin"))
    monkeypatch.setattr("sinduk.store.PASSWORD_HASH_PATH", str(sinduk_dir / "password_hash.bin"))
    return sinduk_dir


def test_bundle_salt_cross_machine_transfer(temp_sinduk_home, monkeypatch, tmp_path):
    """
    Test that an encrypted vault bundle exported with a fresh self-contained salt
    can be imported on another machine having a completely different local salt.bin.
    """
    master_fernet_a = Fernet(Fernet.generate_key())
    set_user_identity("Alice", master_fernet=master_fernet_a)

    vm_a = VaultManager()
    vm_a.create_vault("cross-vault", description="Test cross-machine", master_fernet=master_fernet_a)
    vm_a.save_secret("cross-vault", "api-key", "secret-token-12345", "token", master_fernet_a)

    # Export on machine A with backup password
    backup_password = "shared-backup-password-xyz"
    bundle = vm_a.export_vault_backup("cross-vault", backup_password, master_fernet_a)

    assert bundle.startswith(BUNDLE_MAGIC)
    assert len(bundle) > len(BUNDLE_MAGIC) + BUNDLE_SALT_SIZE

    # Simulate Machine B: Switch home directory and local salt
    machine_b_dir = tmp_path / "machine_b_home"
    monkeypatch.setattr("sinduk.vault.SINDUK_DIR", str(machine_b_dir))
    monkeypatch.setattr("sinduk.vault.VAULTS_DIR", str(machine_b_dir / "vaults"))
    monkeypatch.setattr("sinduk.vault.REGISTRY_PATH", str(machine_b_dir / "vaults" / "vault_registry.json"))
    monkeypatch.setattr("sinduk.vault.USER_IDENTITY_PATH", str(machine_b_dir / "user_identity.json"))
    monkeypatch.setattr("sinduk.store.CONFIG_DIR", str(machine_b_dir))
    monkeypatch.setattr("sinduk.store.SALT_PATH", str(machine_b_dir / "salt.bin"))
    monkeypatch.setattr("sinduk.store.PASSWORD_HASH_PATH", str(machine_b_dir / "password_hash.bin"))

    # Write a totally distinct salt.bin on Machine B
    os.makedirs(machine_b_dir, exist_ok=True)
    distinct_salt_b = os.urandom(16)
    with open(machine_b_dir / "salt.bin", "wb") as f:
        f.write(distinct_salt_b)

    master_fernet_b = Fernet(Fernet.generate_key())
    set_user_identity("Bob", master_fernet=master_fernet_b)

    vm_b = VaultManager()
    # Import into machine B
    stats = vm_b.import_vault_backup("cross-vault", bundle, backup_password, master_fernet_b)
    assert stats["imported"] == 1
    assert stats["errors"] == 0

    # Verify secret is decrypted on Machine B
    secs = vm_b.get_secrets_by_label("cross-vault", "api-key", master_fernet_b)
    assert len(secs) == 1
    assert secs[0]["secret"] == "secret-token-12345"


def test_user_identity_x25519_keypair(temp_sinduk_home):
    """
    Test that set_user_identity and ensure_user_keypair manage X25519 keypairs.
    """
    master_fernet = Fernet(Fernet.generate_key())
    identity = set_user_identity("Alice", master_fernet=master_fernet)

    assert "public_key" in identity
    assert "fingerprint" in identity
    assert "encrypted_private_key" in identity
    assert identity["has_fernet_enc"] is True

    # Retrieve private key
    priv = get_user_private_key(master_fernet)
    assert isinstance(priv, x25519.X25519PrivateKey)

    pub_bytes = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert base64.urlsafe_b64encode(pub_bytes).decode() == identity["public_key"]


def test_asymmetric_vault_key_wrapping(temp_sinduk_home, monkeypatch, tmp_path):
    """
    Test ECDH asymmetric wrapping:
    Alice creates a vault, adds Bob with Bob's public key.
    Bob on his own machine unwraps the vault key using his X25519 private key.
    """
    # 1. Setup Alice
    alice_fernet = Fernet(Fernet.generate_key())
    set_user_identity("Alice", master_fernet=alice_fernet)

    # 2. Setup Bob on a separate machine profile
    bob_dir = tmp_path / "bob_profile"
    bob_fernet = Fernet(Fernet.generate_key())

    monkeypatch.setattr("sinduk.vault.USER_IDENTITY_PATH", str(bob_dir / "user_identity.json"))
    bob_id = set_user_identity("Bob", master_fernet=bob_fernet)
    bob_pubkey = bob_id["public_key"]

    # 3. Switch back to Alice's profile
    monkeypatch.setattr("sinduk.vault.USER_IDENTITY_PATH", str(temp_sinduk_home / "user_identity.json"))
    vm = VaultManager()
    vm.create_vault("infra", description="Infra Secrets", master_fernet=alice_fernet)
    vm.save_secret("infra", "prod-token", "alice-secret-token", "token", alice_fernet)

    # Alice adds Bob with Bob's public key
    vm.add_member(
        "infra",
        bob_id["user_id"],
        "Bob",
        role="editor",
        master_fernet=alice_fernet,
        target_public_key=f"x25519_pk_{bob_pubkey}",
    )

    # 4. Now simulate Bob accessing the vault
    monkeypatch.setattr("sinduk.vault.USER_IDENTITY_PATH", str(bob_dir / "user_identity.json"))
    vm_bob = VaultManager()

    # Bob unlocks vault using his personal master fernet (which unwraps via Bob's X25519 private key)
    bob_vault_fernet = vm_bob.unlock_vault("infra", bob_fernet)
    assert bob_vault_fernet is not None

    # Bob reads secret
    secret_rec = vm_bob.get_secrets_by_label("infra", "prod-token", bob_fernet)
    assert len(secret_rec) == 1
    assert secret_rec[0]["secret"] == "alice-secret-token"

    # Bob adds a new secret
    vm_bob.save_secret("infra", "bob-key", "bob-val-999", "token", bob_fernet)

    # Alice can also read the secret Bob created
    monkeypatch.setattr("sinduk.vault.USER_IDENTITY_PATH", str(temp_sinduk_home / "user_identity.json"))
    vm_alice = VaultManager()
    sec = vm_alice.get_secrets_by_label("infra", "bob-key", alice_fernet)
    assert len(sec) == 1
    assert sec[0]["secret"] == "bob-val-999"


def test_vault_key_rotation(temp_sinduk_home, monkeypatch, tmp_path):
    """
    Test vault key rotation:
    - Secrets are re-encrypted with a new symmetric key.
    - All remaining members with public keys are re-wrapped.
    - Revoked member is locked out of new key.
    """
    alice_fernet = Fernet(Fernet.generate_key())
    alice_id = set_user_identity("Alice", master_fernet=alice_fernet)

    bob_dir = tmp_path / "bob_prof"
    bob_fernet = Fernet(Fernet.generate_key())
    monkeypatch.setattr("sinduk.vault.USER_IDENTITY_PATH", str(bob_dir / "user_identity.json"))
    bob_id = set_user_identity("Bob", master_fernet=bob_fernet)
    bob_pub = bob_id["public_key"]

    monkeypatch.setattr("sinduk.vault.USER_IDENTITY_PATH", str(temp_sinduk_home / "user_identity.json"))
    vm = VaultManager()
    vm.create_vault("app-secrets", master_fernet=alice_fernet)
    vm.save_secret("app-secrets", "key1", "secret1", "password", alice_fernet)
    vm.save_secret("app-secrets", "key2", "secret2", "password", alice_fernet)

    vm.add_member("app-secrets", bob_id["user_id"], "Bob", "editor", alice_fernet, target_public_key=bob_pub)

    # Perform Key Rotation
    res = vm.rotate_vault_key("app-secrets", alice_fernet)
    assert res["secrets_reencrypted"] == 2
    assert res["members_rewrapped"] == 2

    # Verify Alice can read
    s1 = vm.get_secrets_by_label("app-secrets", "key1", alice_fernet)
    assert len(s1) == 1
    assert s1[0]["secret"] == "secret1"

    # Verify Bob can read with newly re-wrapped key
    monkeypatch.setattr("sinduk.vault.USER_IDENTITY_PATH", str(bob_dir / "user_identity.json"))
    vm_bob = VaultManager()
    s2 = vm_bob.get_secrets_by_label("app-secrets", "key2", bob_fernet)
    assert len(s2) == 1
    assert s2[0]["secret"] == "secret2"

    # Now remove Bob with automatic key rotation
    monkeypatch.setattr("sinduk.vault.USER_IDENTITY_PATH", str(temp_sinduk_home / "user_identity.json"))
    vm_alice = VaultManager()
    vm_alice.remove_member("app-secrets", bob_id["user_id"], master_fernet=alice_fernet, rotate_key=True)

    members = vm_alice.list_members("app-secrets")
    assert len(members) == 1
    assert members[0]["user_id"] == alice_id["user_id"]

    # Verify Bob is no longer a member
    monkeypatch.setattr("sinduk.vault.USER_IDENTITY_PATH", str(bob_dir / "user_identity.json"))
    vm_bob2 = VaultManager()
    with pytest.raises(PermissionError, match="not a member"):
        vm_bob2.unlock_vault("app-secrets", bob_fernet)


def test_invite_and_accept_flow(temp_sinduk_home, monkeypatch, tmp_path):
    """
    Test zero-friction invite token creation and acceptance:
    - Alice generates an invite token.
    - Bob accepts the token without exchanging keys beforehand.
    - Bob can immediately read secrets once synced.
    """
    alice_fernet = Fernet(Fernet.generate_key())
    set_user_identity("Alice", master_fernet=alice_fernet)

    vm_alice = VaultManager()
    vm_alice.create_vault("collab-vault", description="Collaboration", master_fernet=alice_fernet)
    vm_alice.save_secret("collab-vault", "shared-token", "collab-secret-val", "token", alice_fernet)

    # Alice creates invite
    invite_token = vm_alice.create_vault_invite(
        "collab-vault", role="editor", master_fernet=alice_fernet, expires_in_hours=2
    )
    assert invite_token.startswith(INVITE_TOKEN_PREFIX)

    # Bob's machine
    bob_dir = tmp_path / "bob_invite_profile"
    monkeypatch.setattr("sinduk.vault.SINDUK_DIR", str(bob_dir))
    monkeypatch.setattr("sinduk.vault.VAULTS_DIR", str(bob_dir / "vaults"))
    monkeypatch.setattr("sinduk.vault.REGISTRY_PATH", str(bob_dir / "vaults" / "vault_registry.json"))
    monkeypatch.setattr("sinduk.vault.USER_IDENTITY_PATH", str(bob_dir / "user_identity.json"))

    bob_fernet = Fernet(Fernet.generate_key())
    set_user_identity("Bob", master_fernet=bob_fernet)

    vm_bob = VaultManager()
    acc_res = vm_bob.accept_vault_invite(invite_token, bob_fernet)
    assert acc_res["vault_name"] == "collab-vault"
    assert acc_res["role"] == "editor"

    # Bob syncs/pulls secrets from shared backup
    backup = vm_alice.export_vault_backup("collab-vault", "sync-pass", alice_fernet)
    vm_bob.import_vault_backup("collab-vault", backup, "sync-pass", bob_fernet)

    sec = vm_bob.get_secrets_by_label("collab-vault", "shared-token", bob_fernet)
    assert len(sec) == 1
    assert sec[0]["secret"] == "collab-secret-val"


def test_expired_or_invalid_invite_rejected(temp_sinduk_home):
    """
    Verify expired or corrupted invite tokens are safely rejected.
    """
    alice_fernet = Fernet(Fernet.generate_key())
    set_user_identity("Alice", master_fernet=alice_fernet)

    vm = VaultManager()
    vm.create_vault("exp-vault", master_fernet=alice_fernet)

    # Create already-expired token (negative expiration)
    token = vm.create_vault_invite("exp-vault", role="viewer", master_fernet=alice_fernet, expires_in_hours=-1)

    bob_fernet = Fernet(Fernet.generate_key())
    with pytest.raises(ValueError, match="expired"):
        vm.accept_vault_invite(token, bob_fernet)

    with pytest.raises(ValueError, match="Invalid invite token format"):
        vm.accept_vault_invite("not-a-token", bob_fernet)


def test_vault_sync_status_tracking(temp_sinduk_home):
    """
    Test recording and retrieving sync tracking metadata.
    """
    fernet = Fernet(Fernet.generate_key())
    set_user_identity("Admin", master_fernet=fernet)

    vm = VaultManager()
    vm.create_vault("sync-track", master_fernet=fernet)

    status_initial = vm.get_sync_status("sync-track")
    assert status_initial == {}

    now = int(time.time())
    vm.update_sync_status(
        "sync-track",
        last_push_at=now,
        last_push_version=3,
        last_push_checksum="sha256:abc12345",
    )

    st = vm.get_sync_status("sync-track")
    assert st["last_push_at"] == now
    assert st["last_push_version"] == 3
    assert st["last_push_checksum"] == "sha256:abc12345"

    vm.update_sync_status(
        "sync-track",
        last_pull_at=now + 60,
        last_pull_version=4,
    )

    st2 = vm.get_sync_status("sync-track")
    assert st2["last_push_version"] == 3
    assert st2["last_pull_version"] == 4
    assert st2["last_pull_at"] == now + 60
