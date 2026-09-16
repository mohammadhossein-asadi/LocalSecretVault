# 🔐 LocalSecretVault

A lightweight, local-first password and developer secrets manager.

**No cloud. No account. No telemetry. Just your secrets, encrypted locally.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-143%20passing-brightgreen.svg)](#testing)

---

## Why LocalSecretVault?

Most secrets managers require cloud accounts, subscriptions, or always-on servers. LocalSecretVault takes a different approach — everything stays on your machine, encrypted with battle-tested cryptography.

- **You own your data.** The vault is a single encrypted file on your disk.
- **No accounts required.** Just a master password you choose.
- **Strong by default.** Argon2id + AES-256-GCM — the same primitives used by industry leaders.
- **Developer-first.** CLI, TUI, `.env` integration, GitHub workflow support.
- **Portable.** Sync the vault file through Git, Syncthing, Dropbox, or USB.

---

## Features

| Feature | Description |
|---------|-------------|
| 🔒 **AES-256-GCM Encryption** | Authenticated encryption with Argon2id key derivation |
| 💻 **CLI & TUI** | Full command-line interface plus interactive terminal UI |
| 🔑 **Password Generator** | Cryptographically secure, configurable length and character sets |
| 📋 **Clipboard Integration** | Cross-platform copy with auto-clear after 30 seconds |
| 🌐 **.env Import/Export** | Seamlessly work with `.env` files |
| 🐙 **GitHub Secrets** | Push and pull repository secrets via `gh` CLI |
| 💾 **Encrypted Backups** | Create and restore backups that remain encrypted |
| 🔍 **Search** | Fast metadata search across names, tags, URLs, usernames |
| 🔐 **Auto-Lock** | Automatic vault locking after inactivity |
| 🛡️ **Security Audit** | Check vault integrity, permissions, and configuration |
| 🖥️ **Cross-Platform** | Windows, macOS, and Linux |

---

## Installation

```bash
# Install from source
git clone https://github.com/mohammadhossein-asadi/LocalSecretVault.git
cd LocalSecretVault
pip install .

# Or install in development mode
pip install -e ".[dev]"
```

**Requirements:** Python 3.10+

---

## Quick Start

```bash
# 1. Create a new vault
localsecretvault init

# 2. Add your first secret
localsecretvault add Login --name "GitHub" --username "you@email.com" --password "s3cret" --url "https://github.com"

# 3. List all secrets (no values shown)
localsecretvault list

# 4. Copy a password to clipboard
localsecretvault get GitHub --field password --copy

# 5. Lock when done
localsecretvault lock
```

---

## CLI Reference

### Vault Management

```bash
localsecretvault init          # Create a new vault
localsecretvault unlock        # Unlock with master password
localsecretvault lock          # Lock the vault
localsecretvault status        # Show vault status and metadata
```

### Secret Operations

```bash
# Add
localsecretvault add Login --name "MyApp" --username "admin" --password "secret" --url "https://myapp.com"
localsecretvault add "API Key" --name "Stripe" --password "sk_live_xxx" --tags "payments,production"
localsecretvault add "Secure Note" --name "Recovery Codes" --notes "ABC-123-XYZ"

# Retrieve
localsecretvault get MyApp                       # Show all fields
localsecretvault get MyApp --field username       # Show specific field
localsecretvault get MyApp --field password --copy # Copy to clipboard

# Edit
localsecretvault edit MyApp --password "new_password" --username "new_user"

# Delete
localsecretvault delete MyApp          # With confirmation
localsecretvault delete MyApp --yes    # Skip confirmation

# List & Search
localsecretvault list                          # All secrets
localsecretvault list --type Login             # Filter by type
localsecretvault list --tag production         # Filter by tag
localsecretvault search github                 # Search metadata
```

### Secret Types

| Type | Example Use |
|------|-------------|
| `Login` | Website accounts, email, SSH |
| `API Key` | Stripe, AWS, Twilio keys |
| `Database` | PostgreSQL, MongoDB, Redis |
| `SSH Key` | Server SSH credentials |
| `Secure Note` | Recovery codes, MNEMONIC phrases |
| `Environment` | `.env` variable sets |
| `Generic Secret` | Anything else |

### Password Generator

```bash
localsecretvault generate                       # 20-char default
localsecretvault generate --length 32           # Custom length
localsecretvault generate --count 5             # Multiple passwords
localsecretvault generate --no-ambiguous        # No 0OIl1 characters
localsecretvault generate --length 64 --copy    # Generate and copy
```

### .env Integration

```bash
# Import from .env file into vault
localsecretvault env-import .env --name "My App Config"

# Export from vault to .env file (with plaintext warning)
localsecretvault env-export .env --name "My App Config" --yes
```

### Backup & Restore

```bash
# Create encrypted backup
localsecretvault backup ~/vault-backup.lsv

# Restore from backup (safety backup created automatically)
localsecretvault restore ~/vault-backup.lsv
```

### GitHub Integration

> Requires [GitHub CLI](https://cli.github.com/) installed and authenticated.

```bash
# Push a secret to GitHub repository secrets
localsecretvault github push --repo owner/repo --secret "Production API Key"

# List GitHub repository secrets
localsecretvault github import --repo owner/repo
```

### Security Audit

```bash
localsecretvault audit
```

```
   LocalSecretVault Security Audit
+-----------------------------------+
| Check                 | Status    |
|-----------------------+-----------|
| Vault encryption      | OK        |
| Vault integrity       | OK        |
| File permissions      | OK        |
| Configuration         | OK        |
| Telemetry             | Disabled  |
| Clipboard integration | Available |
| GitHub CLI             | Available |
+-----------------------------------+
```

---

## TUI (Terminal UI)

```bash
localsecretvault tui
```

### Keybindings

| Key | Action |
|-----|--------|
| `q` | Quit |
| `l` | Lock vault |
| `a` | Add new secret |
| `r` | Refresh list |
| `s` | Focus search |
| `g` | Generate password |
| `Enter` | View secret details |
| `d` | Delete secret |
| `c` | Copy password |

---

## Security

### Cryptography

| Component | Algorithm |
|-----------|-----------|
| **Key Derivation** | Argon2id (3 iterations, 64 MB memory, 4 threads) |
| **Encryption** | AES-256-GCM (128-bit authentication tag) |
| **Salt** | 32 bytes, cryptographically random |
| **Nonce** | 12 bytes, cryptographically random |

### Security Properties

- ✅ Master password is **never stored** on disk
- ✅ All secrets encrypted at rest with authenticated encryption
- ✅ Wrong passwords produce generic "authentication failed" errors
- ✅ Atomic file writes prevent corruption from crashes/interruptions
- ✅ Secrets never printed in CLI output (shown as `********`)
- ✅ Clipboard auto-clears after 30 seconds
- ✅ File permissions enforced on Unix (vault: 600, config: 700)
- ✅ No network requests, no telemetry, no analytics

### Threat Model

**Protected against:**
- Brute-force attacks on the vault file (Argon2id is memory-hard)
- Tampering with encrypted data (AES-GCM authentication)
- Accidental secret disclosure in CLI output
- Data loss from process interruption (atomic writes)

**Not protected against:**
- Malware/keyloggers on your machine
- Physical access to an unlocked machine
- Weak master passwords (use a strong, unique password)
- Clipboard snooping during the 30-second window

See [SECURITY.md](SECURITY.md) for the complete security documentation.

---

## Syncing Your Vault

The vault (`vault.lsv`) is a single encrypted file — sync it with whatever you already use:

| Method | How |
|--------|-----|
| **Git** | Commit the vault to a private repo |
| **Syncthing** | Peer-to-peer encrypted sync |
| **Cloud Storage** | Dropbox, OneDrive, Google Drive |
| **Physical** | USB drive, external HDD |
| **Network** | NAS, SSH, rsync |

> Only the encrypted file is synced. Plaintext secrets never leave your machine.

---

## Configuration

Vault and config are stored in platform-appropriate locations:

| OS | Path |
|----|------|
| **Linux** | `~/.config/localsecretvault/` |
| **macOS** | `~/Library/Application Support/localsecretvault/` |
| **Windows** | `%APPDATA%\localsecretvault\` |

---

## Development

```bash
git clone https://github.com/mohammadhossein-asadi/LocalSecretVault.git
cd LocalSecretVault
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

### Project Structure

```
LocalSecretVault/
├── src/localsecretvault/
│   ├── cli/              # Typer CLI (19 commands)
│   ├── tui/              # Textual terminal UI
│   ├── crypto/           # Argon2id + AES-256-GCM
│   ├── models/           # Secret data models (7 types)
│   ├── vault/            # Vault manager, CRUD, search
│   ├── storage/          # Atomic file I/O
│   ├── services/         # Generator, .env, backup, GitHub
│   ├── config/           # Platform configuration
│   └── utils/            # Signal handling
├── tests/                # 143 tests
│   ├── test_crypto.py    # 36 tests
│   ├── test_vault.py     # 31 tests
│   ├── test_cli.py       # 10 tests
│   ├── test_generator.py # 25 tests
│   ├── test_env.py       # 20 tests
│   ├── test_backup.py    # 11 tests
│   └── test_security.py  # 12 tests
├── pyproject.toml
├── SECURITY.md
├── LICENSE
└── README.md
```

---

## Testing

```bash
pytest                     # Run all 143 tests
pytest tests/test_crypto.py  # Crypto tests only
pytest -v                  # Verbose output
```

**Test coverage:**
- **Crypto:** Encryption/decryption roundtrips, wrong password, corruption, format validation
- **Vault:** Full CRUD, search, tags, auto-lock, persistence across lock/unlock cycles
- **CLI:** All commands via Typer test runner
- **Generator:** Character classes, entropy, edge cases
- **.env:** Parsing, import/export, quoted values, special characters
- **Backup:** Create, restore, corrupted backup rejection, safety backup
- **Security:** No secret leakage, file permission checks, vault integrity

---

## License

[MIT License](LICENSE) — use it however you want.
