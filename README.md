# ⚠️ `pacli-tool` Has Migrated to `sinduk`

> [!IMPORTANT]
> **`pacli-tool` has been renamed to [`sinduk`](https://pypi.org/project/sinduk/).**
>
> Starting from version 2.0.0, all active development, new features, and security updates are published under the new package name **`sinduk`**.
>
> This package (`pacli-tool`) is now a transition/shim package that automatically installs `sinduk>=2.0.0`.

### 🔄 Migration Guide

To install and use `sinduk` directly:

```sh
pip install sinduk
```

Or with `pipx`:
```sh
pipx install sinduk
```

> [!TIP]
> Both `sinduk` and `pacli` CLI commands remain fully supported and interchangeable.

---

# 🔐 sinduk - Secrets Management CLI & Team Vaults

---

## 🌟 Key Features

- 🔒 **Local-First & Zero-Knowledge**: Secrets are encrypted at rest with PBKDF2-HMAC-SHA256 and Fernet (AES-128-CBC + HMAC). Plaintext never touches the network unencrypted.
- 👥 **Team Vaults & RBAC**: Create isolated team vaults (`dev-infra`, `prod-keys`) with granular roles (`viewer`, `editor`, `admin`) and encrypted key-wrapping per member.
- 🔄 **Multi-Target Vault Sync**: Push and pull encrypted vault bundles across team members using a shared directory (Dropbox, Google Drive, NAS, Git) or via the built-in self-hosted server.
- 🖥️ **Self-Hosted Zero-Knowledge Relay Server**: Run your own team sync server (`sinduk server start`) with token authentication and audit logging. The server never has access to encryption keys or secrets.
- 📦 **Encrypted Backups**: Export and import full encrypted vault backups with master password protection.
- 💻 **Modern Web UI**: Interactive browser dashboard (`sinduk web`) featuring a Vault Switcher, Secrets CRUD, Team Member Management, Audit Log Viewer, and an in-browser SSH Terminal.
- 🔑 **SSH Key Management**: Store and auto-connect to SSH servers using credentials or key files.
- 📋 **Clipboard & Pipeline Integration**: Copy secrets directly to clipboard (`--clip`) or pipe command outputs (`sinduk cc`).
- 🔗 **LinklyHQ URL Shortening**: Built-in shortlink generator with click tracking.

---

## 🚀 Installation

### Recommended: pipx (isolated environment)
```sh
pip install pipx
pipx ensurepath
pipx install sinduk
```

### Standard pip
```sh
pip install sinduk
```

### Install from source
```sh
git clone https://github.com/imshakil/sinduk.git
cd sinduk
pip install -e .
```

Verify installation:
```sh
sinduk version
sinduk --help
```

---

## 📖 Command Reference

| Command / Group | Description |
|---|---|
| `init` | Set or reset your master password |
| `add` | Add a secret (`--pass`, `--token`, `--ssh`) with optional `--vault` |
| `get` / `get-by-id` | Retrieve secrets by label or ID (`--clip` to copy) |
| `list` | List all saved secrets (supports `--vault`) |
| `update` / `update-by-id` | Update an existing secret value |
| `delete` / `delete-by-id` | Delete a secret |
| `team` | 👥 Team vault management (create vaults, add members, audit log) |
| `sync` | 🔄 Sync encrypted vaults with a team relay server or shared directory |
| `server` | 🖥️ Start, stop, and manage the self-hosted zero-knowledge sync server |
| `backup` | 📦 Encrypted backup export and import across machines |
| `web` | 🌐 Launch or manage the local Web UI dashboard |
| `ssh` | Connect to an SSH server using saved credentials |
| `export` | Export secrets to unencrypted JSON or CSV |
| `short` | Shorten URLs via LinklyHQ |
| `cc` | Copy stdin / pipeline output to clipboard |
| `change-master-key` | Re-encrypt all secrets with a new master password |
| `version` | Show sinduk version and project details |

---

## 👥 Team Vaults & Collaboration

### 1. Initialize Your Team Identity
Each team member initializes their identity once:
```sh
sinduk team init
# Enter display name: Alice
# ✅ Identity set! User ID: d164fe8724cb
```

To see your identity anytime:
```sh
sinduk team whoami
```

### 2. Create a Team Vault
```sh
sinduk team create-vault dev-infra -d "Backend infrastructure & database credentials"
```

### 3. Add Teammates to the Vault
Add members using their unique User ID:
```sh
# Add Bob as an editor
sinduk team add-member dev-infra a8f910e1234 --name "Bob" --role editor

# Add Charlie as a read-only viewer
sinduk team add-member dev-infra b7c821f9876 --name "Charlie" --role viewer
```

Available roles:
- `viewer`: Read secrets in the vault
- `editor`: Read, add, update, and delete secrets
- `admin`: Full control (manage members, roles, audit log, delete vault)

### 4. Working with Secrets in Team Vaults
Simply pass `--vault <name>` or `-v <name>` to any secret command:
```sh
# Add a secret to the team vault
sinduk add --vault dev-infra --password postgres_db postgres db_pass_secret
sinduk add --vault dev-infra --token stripe_key sk_test_12345

# List secrets in the team vault
sinduk list --vault dev-infra

# Retrieve a secret from the vault
sinduk get --vault dev-infra postgres_db --clip

# View immutable audit log of actions taken in the vault
sinduk team audit-log dev-infra
```

---

## 🔄 Syncing Vaults Across the Team

### Option A: Self-Hosted Zero-Knowledge Relay Server

#### 1. Start the Sync Server (DevOps / Admin)
Run on any Linux server, VPS, or cloud container:
```sh
# Start the server daemon on port 58380
sinduk server start --host 0.0.0.0 --port 58380 --daemon

# Generate a team token
sinduk server token create --name "DevTeam" --role admin
```

#### 2. Configure Team Members
Each team member configures their client once:
```sh
sinduk sync config set --server http://secrets.mycompany.internal:58380 --token sinduk_tok_...
```

#### 3. Push and Pull Updates
```sh
# Push local vault updates to the server
sinduk sync push dev-infra

# Check status of remote vault
sinduk sync status dev-infra

# Pull and merge latest changes from the server
sinduk sync pull dev-infra
```

---

### Option B: Offline / Shared Directory Sync (No Server)

Sync encrypted bundles through **Dropbox, Google Drive, NAS, or Git**:
```sh
# Push encrypted bundle to shared directory
sinduk sync push dev-infra --to ~/Dropbox/TeamSecrets/

# Pull and merge from shared directory (supports both .sinduk and .pacli files)
sinduk sync pull dev-infra --from ~/Dropbox/TeamSecrets/
```

---

## 📦 Encrypted Backups

Export and import encrypted backup archives of personal or team vaults:
```sh
# Backup personal store
sinduk backup export --output ~/sinduk_backup.sinduk

# Backup a specific team vault
sinduk backup export --vault dev-infra --output ~/dev_infra_backup.sinduk

# Restore backup
sinduk backup import --input ~/dev_infra_backup.sinduk --vault dev-infra
```

---

## 🌐 Web UI

Launch the modern browser-based UI:
```sh
# Start and open in default browser
sinduk web

# Start in background mode (daemon)
sinduk web start

# Check status / Stop
sinduk web status
sinduk web stop
```

---

## 💡 Pro Tips

### Session-based Master Password
Avoid typing your master password repeatedly by exporting it in your current terminal session:
```sh
export SINDUK_MASTER_PASSWORD="your-master-password"
```

### Pipeline & Clipboard Tools
```sh
# Copy SSH public key to clipboard
cat ~/.ssh/id_rsa.pub | sinduk cc

# Copy command output
terraform output -json | sinduk cc
```

---

## 📄 License

Distributed under the [MIT License](LICENSE). Built with ❤️ by [imShakil](https://github.com/imShakil).
