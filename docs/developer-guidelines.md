# Developer Guidelines for pacli

**pacli** is a secure, local-first secrets manager with CLI and Web UI interfaces. Built with Python, Click, Flask, and Fernet encryption.

## Quick Start

```bash
git clone https://github.com/imshakil/pacli.git && cd pacli
pip install -e ".[dev]" && pre-commit install
pacli --help
```

## Project Structure

```files
./pacli
├── LICENSE
├── README.md
├── pyproject.toml
├── requirements.txt
├── sonar-project.properties
├── uv.lock
├── docs
│   ├── developer-guidelines.md
│   └── index.html
├── sinduk
│   ├── __init__.py
│   ├── audit.py
│   ├── cli.py
│   ├── decorators.py
│   ├── helpers.py
│   ├── log.py
│   ├── server.py
│   ├── ssh_utils.py
│   ├── store.py
│   ├── strength.py
│   ├── sync_client.py
│   ├── validators.py
│   ├── vault.py
│   ├── commands
│   │   ├── __init__.py
│   │   ├── admin.py
│   │   ├── backup.py
│   │   ├── login.py
│   │   ├── secrets.py
│   │   ├── server.py
│   │   ├── ssh.py
│   │   ├── sync.py
│   │   ├── team.py
│   │   ├── utils.py
│   │   └── web.py
│   └── web
│       ├── __init__.py
│       ├── app.py
│       ├── ssh_handler.py
│       ├── static
│       │   ├── app.js
│       │   ├── ssh_terminal.js
│       │   └── style.css
│       └── templates
│           └── index.html
└── tests
    ├── __init__.py
    ├── test_command_helpers.py
    ├── test_commands_web.py
    ├── test_core_utils.py
    ├── test_server.py
    ├── test_store.py
    ├── test_sync.py
    ├── test_team_commands.py
    ├── test_vault.py
    ├── test_vault_web.py
    └── test_web_app.py

```

## Coding Standards

- **Python**: PEP 8 with Black (120 char), Flake8, MyPy, Bandit (via pre-commit)
- **Naming**: Classes=PascalCase, functions=snake_case, constants=UPPER_SNAKE_CASE
- **Docs**: Docstrings with Args, Returns, Raises
- **Types**: Add type hints to functions

Run: `pre-commit run --all-files`

## Architecture

### Core Components

- **SecretStore** ([`pacli/store.py`](pacli/store.py)): Personal master password, encryption/decryption, CRUD operations
- **VaultManager** ([`pacli/vault.py`](pacli/vault.py)): Per-vault database creation, RBAC (viewer, editor, admin), per-member wrapped Fernet keys, and audit logging
- **SyncServerDB & App** ([`pacli/server.py`](pacli/server.py)): Self-hosted zero-knowledge relay server for token auth, encrypted blob storage, and audit trails
- **SyncClient** ([`pacli/sync_client.py`](pacli/sync_client.py)): Client-side push/pull HTTP handler for syncing encrypted vault blobs
- **CLI Commands** ([`pacli/commands/`](pacli/commands/)): Click-based command handlers (`team`, `sync`, `server`, `secrets`, `backup`, `ssh`, `web`)
- **Web API** ([`pacli/web/app.py`](pacli/web/app.py)): Flask REST API with session auth, vault switching, team management, and audit log endpoints
- **Utilities**: Helpers, logging, SSH config parsing, password strength meter, URL shortening

### Data Flow

User Input → Command/Route → SecretStore (verify master password) → Fernet encryption → SQLite DB

### Key Points

- Both CLI and Web UI share the same SQLite database (`~/.config/pacli/sqlite3.db`)
- Encryption: Fernet (symmetric) with PBKDF2 key derivation
- Master password is never stored, derived on-demand
- Web endpoints require `@require_auth` decorator

## Adding Features

### New CLI Command

1. Create file in [`pacli/commands/`](pacli/commands/) or add to existing
2. Use Click decorators and `@master_password_required` if needed
3. Register in [`pacli/cli.py`](pacli/cli.py)

### New Web Endpoint

1. Add route to [`pacli/web/app.py`](pacli/web/app.py)
2. Use `@require_auth` decorator
3. Return JSON responses

### New Secret Type

1. Update [`pacli/store.py`](pacli/store.py)
2. Add CLI options in [`pacli/commands/secrets.py`](pacli/commands/secrets.py)
3. Update web UI in [`pacli/web/templates/index.html`](pacli/web/templates/index.html) and [`pacli/web/static/app.js`](pacli/web/static/app.js)

## Testing

```bash
pytest                          # Run all tests
pytest --cov=pacli              # With coverage
pytest tests/test_store.py      # Specific file
```

Focus on: encryption/decryption, database ops, master password verification, API endpoints.

## Security Checklist

- [ ] Master password verification required?
- [ ] Secrets properly encrypted?
- [ ] User input validated?
- [ ] No secrets in logs?
- [ ] Database operations safe (parameterized queries)?
- [ ] Web endpoints authenticated?
- [ ] Error messages don't leak information?

## Build & Release

```bash
python -m build && pip install dist/pacli_tool-*.whl  # Build & test
git tag v1.2.3 && git push origin v1.2.3              # GitHub Actions → PyPI
```

## Git Workflow

**Branches**: `feature/`, `fix/`, `docs/`, `refactor/` | **Commits**: `type(scope): description`

## Common Tasks

```bash
pacli web --no-browser          # Run web UI (http://localhost:5000)
export PACLI_DEBUG=1            # Enable debug logging
mypy pacli/                     # Type checking
sqlite3 ~/.config/pacli/sqlite3.db ".schema"  # View DB schema
```

## Troubleshooting

**Pre-commit failing**: `black pacli/ && pre-commit run --all-files`

**Import errors**: `pip install -e .`

**Database locked**: `rm ~/.config/pacli/sqlite3.db-wal ~/.config/pacli/sqlite3.db-shm`

**SQLite threading error in Web UI**: Add `check_same_thread=False` to sqlite3.connect() or use thread-local connections.

## Resources

- [Click Docs](https://click.palletsprojects.com/)
- [Flask Docs](https://flask.palletsprojects.com/)
- [Cryptography Lib](https://cryptography.io/)
- [PEP 8](https://pep8.org/)
- [GitHub Repo](https://github.com/imshakil/pacli)

---

**Last Updated**: 2025-12-11 | **Maintainer**: Mobarak Hosen Shakil
