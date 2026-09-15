# 🔐 sinduk - Secrets Management CLI & Team Vaults

___

[![Build Status](https://github.com/imshakil/sinduk/actions/workflows/release.yml/badge.svg)](https://github.com/imshakil/sinduk/actions)
[![PyPI version](https://img.shields.io/pypi/v/sinduk.svg)](https://pypi.org/project/sinduk/)
[![PyPI Downloads](https://img.shields.io/pepy/dt/sinduk?style=flat)](https://pepy.tech/projects/sinduk)
[![Python Versions](https://img.shields.io/pypi/pyversions/sinduk.svg)](https://pypi.org/project/sinduk/)
[![License](https://img.shields.io/github/license/imshakil/sinduk)](LICENSE)
[![security:bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/imShakil/sinduk)

**sinduk** (*সিন্দুক* — the traditional Bengali word for a secure treasure chest or heirloom vault) is a secure, local-first secrets manager and team vault system designed for developers and DevOps teams. Store, retrieve, sync, and share passwords, API tokens, and SSH credentials with strong cryptography, master password verification, role-based permissions, and zero-knowledge synchronization.

> [!NOTE]
> Formerly known as `pacli` (`pacli-tool`). The `pacli` command remains supported as an alias for seamless backward compatibility with existing workflows and automations.

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
| `init` | (Optional) Explicitly set or reset the master password |
| `add` | Add a secret (auto-detects token/password/ssh, or `--type`) with optional `--vault` |
| `get` | Retrieve secrets by label or ID (`--clip` to copy) |
| `list` | List all saved secrets (supports `--vault`) |
| `update` | Update a secret by label or ID |
| `delete` | Delete a secret by label or ID (`-y` to skip confirmation prompt) |
| `passwd` | Change the master password without losing secrets (re-encrypts store) |
| `team` | 👥 Team vault management (create vaults, add members, audit log) |
| `sync` | 🔄 Sync encrypted vaults with a team relay server or shared directory |
| `server` | 🖥️ Start, stop, and manage the self-hosted zero-knowledge sync server |
| `login` | 🔑 Seamless 1-click terminal authentication with self-hosted server |
| `logout` | 🚪 Log out and remove stored sync credentials |
| `backup` | 📦 Encrypted backup — export and import secrets across devices |
| `web` | 🌐 Launch and manage the local Web UI dashboard |
| `ssh` | 🔑 Connect to SSH server using saved credentials |
| `export` | Export secrets to JSON or CSV format |
| `short` | Shorten URLs via LinklyHQ |
| `cc` | 📋 Copy stdin / pipeline output to clipboard |
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
# Add a secret to the team vault (using --type or auto-detection)
sinduk add --vault dev-infra --type password postgres_db postgres db_pass_secret
sinduk add --vault dev-infra --type token stripe_key sk_test_12345

# List secrets in the team vault
sinduk list --vault dev-infra

# Retrieve a secret from the vault
sinduk get --vault dev-infra postgres_db --clip

# View immutable audit log of actions taken in the vault
sinduk team audit-log dev-infra
```

---

## 🔄 Syncing Vaults Across the Team

Sinduk offers seamless zero-knowledge synchronization across team members with **automatic background push**, live server verification, and offline directory fallback.

### Option A: Self-Hosted Zero-Knowledge Relay Server (Recommended)

#### 1. Start the Sync Server (DevOps / Admin)
Run with Docker:
```sh
docker-compose up -d
```
Or directly via the CLI:
```sh
# Start the server daemon on port 58380
sinduk server start --host 0.0.0.0 --port 58380 --daemon
```

#### 2. Pair CLI in 1-Click (`sinduk login`)
Team members can connect and authenticate instantly:
```sh
# Connect with interactive browser authorization
sinduk login http://secrets.mycompany.internal:58380

# Or authenticate directly in the terminal (headless / SSH)
sinduk login http://secrets.mycompany.internal:58380 --no-browser
```
*(You can also configure tokens manually using `sinduk sync config set`).*

#### 3. Automatic Background Sync ⚡
Once configured, **all team vault changes are pushed automatically** whenever you modify secrets or membership:
- `sinduk add --vault dev-infra ...` ➡️ *Auto-pushed to server*
- `sinduk update --vault dev-infra ...` ➡️ *Auto-pushed to server*
- `sinduk delete --vault dev-infra ...` ➡️ *Auto-pushed to server*
- `sinduk team add-member dev-infra ...` ➡️ *Auto-pushed to server*

#### 4. Manual Push, Pull, and Status
You can also manually synchronize or check remote vault versions at any time:
```sh
# Push local vault updates to the server
sinduk sync push dev-infra

# Check status of remote vault vs local vault
sinduk sync status dev-infra

# Pull and merge latest changes from the server
sinduk sync pull dev-infra
```

#### 5. Web UI Sync Controls 🌐
When using the browser dashboard (`sinduk web`):
- Click **"Sync Server"** in the top navigation bar to configure server URL and bearer token with live connection testing.
- Use the **"🔄 Sync"** 1-click button on any team vault card to instantly pull and push changes.

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
