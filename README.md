# LocalSecretVault

A lightweight, local-first password and developer secrets manager.

**No cloud service. No account. No telemetry. Just your secrets, encrypted locally.**

## Features

- **Strong encryption:** Argon2id key derivation + AES-256-GCM authenticated encryption
- **CLI interface:** Full-featured command-line tool built with Typer + Rich
- **TUI interface:** Interactive terminal UI built with Textual
- **Password generator:** Cryptographically secure, configurable
- **Secret types:** Login, API Key, Database, SSH Key, Secure Note, Environment, Generic
- **.env integration:** Import and export `.env` files
- **GitHub integration:** Push secrets to GitHub repositories via `gh` CLI
- **Backup/restore:** Encrypted backups with safety mechanisms
- **Search:** Fast metadata search across all secrets
- **Auto-lock:** Configurable inactivity timeout
- **Clipboard:** Cross-platform copy with auto-clear
- **Security audit:** Check vault integrity, file permissions, and configuration

## Installation

```bash
# Install from source
pip install .

# Or install in development mode
pip install -e ".[dev]"
```

### Requirements

- Python 3.10+
- `argon2-cffi` (installed automatically)
- `cryptography` (installed automatically)

### Optional

- `gh` CLI — for GitHub integration ([install](https://cli.github.com/))
- Clipboard support — `pyperclip` (installed automatically)

## Quick Start

```bash
# Initialize a new vault
localsecretvault init

# Unlock the vault
localsecretvault unlock

# Add a secret
localsecretvault add Login --name "GitHub" --username "you" --password "secret" --url "https://github.com"

# List all secrets (safe — no values shown)
localsecretvault list

# Get a specific field
localsecretvault get GitHub --field username

# Copy password to clipboard
localsecretvault get GitHub --field password --copy

# Lock the vault
localsecretvault lock
```

## CLI Reference

### Vault Management

| Command | Description |
|---------|-------------|
| `localsecretvault init` | Create a new encrypted vault |
| `localsecretvault unlock` | Unlock the vault with your master password |
| `localsecretvault lock` | Lock the vault, clearing in-memory secrets |
| `localsecretvault status` | Show vault status, config, and metadata |

### Secret Operations

| Command | Description |
|---------|-------------|
| `localsecretvault add <type> --name <name>` | Add a new secret |
| `localsecretvault get <name> [--field <field>] [--copy]` | Retrieve secret data |
| `localsecretvault edit <name> [--field value]` | Edit an existing secret |
| `localsecretvault delete <name> [--yes]` | Delete a secret |
| `localsecretvault list [--type TYPE] [--tag TAG]` | List all secrets |
| `localsecretvault search <query>` | Search secrets by metadata |

### Secret Types

| Type | Fields |
|------|--------|
| `Login` | name, username, password, url, notes, tags |
| `API Key` | name, api_key, url, notes, tags |
| `Database` | name, host, port, database, username, password, notes |
| `SSH Key` | name, host, username, private_key_path, notes |
| `Secure Note` | name, content, notes, tags |
| `Environment` | name, variables (key=value pairs), notes |
| `Generic Secret` | name, custom fields, notes, tags |

### Password Generator

```bash
# Generate a 20-character password (default)
localsecretvault generate

# Generate a 32-character password
localsecretvault generate --length 32

# Generate 5 passwords
localsecretvault generate --count 5

# Generate without ambiguous characters
localsecretvault generate --no-ambiguous

# Generate and copy to clipboard
localsecretvault generate --length 32 --copy
```

### .env Integration

```bash
# Import from .env file
localsecretvault env-import .env --name "My App"

# Export to .env file (with plaintext warning)
localsecretvault env-export .env --name "My App" --yes
```

### Backup & Restore

```bash
# Create encrypted backup
localsecretvault backup ./vault-backup.lsv

# Restore from backup (creates safety backup first)
localsecretvault restore ./vault-backup.lsv
```

### GitHub Integration

```bash
# Push a secret to GitHub
localsecretvault github push --repo owner/repo --secret "My API Key"

# List GitHub repository secrets
localsecretvault github import --repo owner/repo
```

### Security Audit

```bash
localsecretvault audit
```

Output:
```
LocalSecretVault Security Audit

Vault encryption       OK
Vault integrity        OK
File permissions       OK
Configuration          OK
Telemetry              Disabled
Clipboard integration  Available
GitHub CLI             Available
```

## TUI

Launch the interactive terminal UI:

```bash
localsecretvault tui
```

### TUI Keybindings

| Key | Action |
|-----|--------|
| `q` | Quit |
| `l` | Lock vault |
| `a` | Add secret |
| `r` | Refresh list |
| `s` | Focus search |
| `g` | Generate password |
| `Enter` | View secret details |
| `d` | Delete secret |
| `c` | Copy password |

## Configuration

Vault and configuration files are stored in platform-appropriate locations:

| OS | Location |
|----|----------|
| Linux | `~/.config/localsecretvault/` |
| macOS | `~/Library/Application Support/localsecretvault/` |
| Windows | `%APPDATA%\localsecretvault\` |

### File Permissions (Unix)

- Config directory: `700` (owner only)
- Vault file: `600` (owner read/write only)

## Synchronization

The vault file (`vault.lsv`) is a single encrypted file that can be synchronized
through external tools:

- **Git** — commit the encrypted vault to a private repository
- **Syncthing** — peer-to-peer sync
- **OneDrive / Dropbox / Google Drive** — cloud storage sync
- **USB / NAS** — physical transfer

> The synchronization system receives only the encrypted file.
> It never receives plaintext secrets.

**Note:** File metadata (size, timestamps) may reveal that a vault exists and when
it was last modified. For maximum privacy, avoid syncing through services that
expose this metadata.

## Development

```bash
# Clone the repository
git clone https://github.com/localsecretvault/localsecretvault.git
cd localsecretvault

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src/ tests/

# Type check
mypy src/
```

### Project Structure

```
localsecretvault/
├── src/localsecretvault/
│   ├── cli/          # Typer CLI application
│   ├── tui/          # Textual terminal UI
│   ├── crypto/       # Argon2id KDF + AES-256-GCM
│   ├── models/       # Secret data models
│   ├── vault/        # Vault manager (CRUD, search, lock)
│   ├── storage/      # Atomic file I/O
│   ├── services/     # Password generator, .env, backup, GitHub
│   ├── config/       # Platform configuration
│   └── utils/        # Signal handling
├── tests/            # 143 tests
├── pyproject.toml
├── SECURITY.md
└── README.md
```

## Security

See [SECURITY.md](SECURITY.md) for the complete security model, threat model,
and limitations.

### Key Points

- Master password is never stored or logged
- All secrets encrypted with Argon2id + AES-256-GCM
- Atomic writes prevent data loss from interruption
- Wrong passwords produce generic "authentication failed" errors
- No telemetry, analytics, or network access

## License

MIT License — see [LICENSE](LICENSE) for details.
