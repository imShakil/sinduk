# 🏗️ Product Engineer's Assessment of `sinduk` Team Features

> **Context**: Originally evaluated during the `pacli` era and now updated for **`sinduk`** (*সিন্দুক*). This document outlines the architectural strengths, critical gaps, and actionable roadmap for making `sinduk` enterprise-ready for small and modern engineering teams.

---

### ✅ What's Already Solid

| Feature | Why It's Good |
|---|---|
| **Local-first, zero-knowledge** | Fundamentally correct philosophy. Secrets never leave the machine unencrypted. |
| **Per-vault symmetric key, wrapped per-member** | Cryptographically correct foundation. Each member decrypts with their own wrapped copy of the vault key. |
| **RBAC (viewer / editor / admin)** | Right primitive. Industry standards (1Password, Vault) start here. |
| **Tamper-evident audit log** | Essential for enterprise compliance (SOC2, ISO27001). `sinduk` records every action with hashes. |
| **Zero-knowledge relay server** | Excellent — `sinduk server` is "dumb" and never has access to encryption keys or plaintext. |
| **Offline-first architecture** | Huge practical win for developers working in air-gapped, VPN-restricted, or unstable networks. |
| **Unified CLI & Web UI** | Smooth developer ergonomics with `sinduk` CLI and full visual dashboard with `sinduk web`. |

---

### 🚨 The Critical Gaps (What Blocks Real-World Team Adoption)

#### 1. **The `add-member` Key Problem** — #1 Architecture Flaw

Look at this line in [`sinduk/vault.py:487`](file:///Users/imshakil/GitHub/imshakil/pacli/sinduk/vault.py#L484-L488):

```python
# Wrap the key for the new member (currently uses caller's master_fernet)
raw_vault_key = self.get_raw_vault_key(vault_name, master_fernet)
wrapped_for_member = master_fernet.encrypt(raw_vault_key)
```

When Alice adds Bob to a vault:
- Alice wraps the vault key **using Alice's own master key**, not Bob's.
- Bob is registered as a member in the metadata, but **Bob can never decrypt the vault key** on his device because his copy is wrapped with Alice's master password.

**Result**: Bob cannot execute `sinduk get --vault dev-infra <secret>` on his machine.

```
┌─ Alice runs: sinduk team add-member dev-infra <bob_user_id> ─────────────────┐
│                                                                               │
│  PROBLEM: Alice does not possess Bob's master Fernet key (derived from Bob's │
│  private master password).                                                    │
│                                                                               │
│  SOLUTIONS:                                                                   │
│  A. Asymmetric bootstrap (X25519 / ECDH keypairs per user) — Recommended      │
│  B. Invite-link flow with an ephemeral one-time secret token                 │
│  C. Admin-provisioned initial vault passphrase (simpler fallback)            │
└───────────────────────────────────────────────────────────────────────────────┘
```

#### 2. **Cross-Machine Sync Derives Key from *Local* Salt**

In [`sinduk/vault.py:880-890`](file:///Users/imshakil/GitHub/imshakil/pacli/sinduk/vault.py#L880-L890) and `export_vault_backup`:

```python
from .store import get_salt
salt = get_salt()   # ← Reads from ~/.config/sinduk/salt.bin (local machine salt!)
kdf = PBKDF2HMAC(...)
backup_key = base64.urlsafe_b64encode(kdf.derive(backup_password.encode()))
```

Alice exports a `.sinduk` vault bundle with her local `salt.bin`. Bob imports on his machine with his distinct `salt.bin`.
Even with the exact same backup password:
$$\text{Same Password} + \text{Different Local Salt} \implies \text{Different Fernet Key} \implies \text{InvalidToken Exception}$$

**Fix**: The exported bundle header must store its own unique PBKDF2 salt (16 bytes) alongside the encrypted payload, rather than reading local `salt.bin`.

#### 3. **Vault Key Rotation Missing**
`rotate_key` is declared in the `VaultRole.ADMIN` permissions list, but lacks a concrete implementation in `VaultManager`. Key rotation is non-negotiable whenever an offboarded member is removed from a vault.

#### 4. **Identity is an Unsigned Local UUID**
```python
user_id = existing.get("user_id", uuid.uuid4().hex[:12])  # sinduk/vault.py:90
```
Currently, any user can claim any arbitrary `user_id`. There is no signature verification or cryptographic proof of identity.
Enterprise readiness requires:
- Cryptographic public key identity (Ed25519/X25519 public key = user identity fingerprint)
- Verified email or Git/GitHub identity signing
- OIDC/SSO federated claims (GitHub, Google, Okta)

---

### 🗺️ Redesigned Engineering Roadmap for `sinduk`

```
PHASE 1 — Core Cryptography & Sync Fixes (Immediate)     [OSS]
├── Fix add-member key wrapping via X25519 / ECDH user keypairs
├── Embed PBKDF2 salt in .sinduk sync/backup bundles (self-contained)
├── Implement vault key rotation upon member removal (sinduk team rotate-key)
└── Add vault sync status tracking (last push/pull timestamp & version hash)

PHASE 2 — Team Onboarding & Collaboration (3–6 Months)  [OSS]
├── `sinduk team invite <vault> <email/user>` — generate one-time invite token
├── `sinduk team accept <invite-token>` — exchange public keys and bootstrap vault
├── 3-way conflict resolution on sync (last-write-wins with label-level diff)
├── `sinduk team diff <vault>` — inspect changes between local and remote vault
└── GitHub Actions Integration (`uses: imshakil/sinduk-action@v1`)

PHASE 3 — Enterprise & Multi-Cloud Scale (6–12 Months)  [OSS + Extensible]
├── SSO / OIDC identity providers (GitHub, Google, Okta, Azure AD)
├── Hierarchical environments (e.g. dev / staging / prod namespaces)
├── Automated secret rotation reminders & expiration TTLs
├── Compliance & audit log export (SOC2 / ISO27001 report format)
├── Granular SCIM directory provisioning
└── Multi-Cloud storage sync backends:
    ├── AWS S3 target (`sinduk sync push --s3 s3://my-vault-bucket/`)
    ├── Cloudflare R2 / MinIO S3-compatible backends
    └── Vault bridge (import from AWS Secrets Manager / HashiCorp Vault)
```

---

### 📊 Competitive Positioning

```
                      ┌──────────────────┬──────────────────┬──────────────────┐
                      │  sinduk (Target) │ HashiCorp Vault  │  1Password Teams │
  ────────────────────┼──────────────────┼──────────────────┼──────────────────┤
  Self-hosted & Free  │  ✅ Yes (100% MIT)│  ⚠️ Complex BSL  │  ❌ Paid SaaS    │
  Zero-Knowledge      │  ✅ Client-side  │  ❌ Server reads │  ✅ Client-side  │
  CLI & Script Native │  ✅ Developer 1st│  ⚠️ Complex CLI  │  ⚠️ Extra CLI    │
  Offline-First       │  ✅ Yes          │  ❌ Requires API │  ⚠️ Cache only   │
  Setup Overhead      │  ⚡ 10 seconds   │  🛑 Days/Weeks   │  ⚡ 5 minutes    │
  Team Key Wrapping   │  🔄 Phase 1 Fix  │  ✅ Built-in     │  ✅ Built-in     │
  Air-gapped Sync     │  ✅ USB/Git/NAS  │  ❌ Network only │  ❌ Cloud only   │
  ────────────────────┴──────────────────┴──────────────────┴──────────────────┘
```

### 🎯 The Defensible Niche for `sinduk`

> **"For software engineers, startups, and DevOps teams (1–50 people) who want local-first privacy, Git/NAS sync workflows, and zero cloud vendor lock-in without the operational burden of managing a dedicated HashiCorp Vault cluster."**

---

### 📋 Recommended Immediate Priorities

1. **Fix `add-member` key exchange** — generate X25519 public/private keypair in `~/.config/sinduk/identity.json` and wrap vault keys to member public keys.
2. **Fix backup/sync bundle salt** — include a 16-byte random salt in the first 16 bytes of `.sinduk` backup blobs.
3. **`sinduk team invite` flow** — provide a seamless invite URL/token command so teams can collaborate without manual key copying.
4. **Implement Key Rotation** — re-wrap all secret values with a fresh vault key when a member is revoked.
