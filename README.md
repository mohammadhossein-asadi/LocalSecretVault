# LocalSecretVault

<div align="center">

![LocalSecretVault Logo](public/logo.png)

**Zero-Knowledge Local-First Secrets Manager for Developers**

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://python.org/)
[![Rich](https://img.shields.io/badge/Rich-13.7-FF6B6B?logo=textual&logoColor=white)](https://github.com/Textualize/rich)
[![Click](https://img.shields.io/badge/Click-8.1-000000?logo=click&logoColor=white)](https://click.palletsprojects.com/)
[![Pydantic](https://img.shields.io/badge/Pydantic-2.7-E92063?logo=pydantic&logoColor=white)](https://pydantic.dev/)
[![Cryptography](https://img.shields.io/badge/Cryptography-42.0-FF6F61?logo=python&logoColor=white)](https://cryptography.io/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-1.0.0-blue)](https://pypi.org/project/local-secret-vault/)

[🇬🇧 English](#-localsecretvault) • [🇮🇷 فارسی](README.fa.md) • [📖 Documentation](#-documentation) • [🚀 Quick Start](#-quick-start) • [🤝 Contributing](#-contributing)

</div>

---

## 🌟 Overview

**LocalSecretVault** is a **zero-knowledge, local-first secrets manager** designed for developers who value privacy and control. All encryption happens **client-side** — your master password never leaves your machine, and your encrypted vault is just a portable file you can sync via Git, Dropbox, Syncthing, or any cloud provider.

### 🎯 Why LocalSecretVault?

| Problem | LocalSecretVault Solution |
|---------|--------------------------|
| Cloud vaults can be breached | **Zero-knowledge** — only you can decrypt |
| Vendor lock-in | **Portable file** — sync anywhere, no account needed |
| Subscription fatigue | **Free & open source** — no recurring costs |
| CLI-only tools are clunky | **Beautiful TUI** + CLI + optional GUI |
| No Persian support | **Full Persian RTL** in TUI/CLI |

---

## ✨ Features

### 🔐 **Security First**
- **Encryption** — AES-256-GCM (authenticated encryption)
- **Key Derivation** — Argon2id (memory-hard, GPU-resistant)
- **Master Password** — Never stored, never transmitted
- **Vault Format** — Single encrypted file (JSON + binary)
- **Integrity** — HMAC-SHA256 on every record
- **Versioning** — Vault schema versioning for upgrades

### 🗂️ **Secret Organization**
- **Categories** — API Keys, Database, SSH, Certificates, Notes, Custom
- **Tags** — Flexible tagging for cross-category queries
- **Projects** — Group secrets by project/repository
- **Environments** — Development, Staging, Production, Custom
- **Favorites** — Quick access to frequently used

### 🖥️ **Interfaces**
| Interface | Features |
|-----------|----------|
| **TUI** | Rich terminal UI with tables, forms, search, fuzzy finder |
| **CLI** | Scriptable commands for automation/CI |
| **GUI** | Optional Tauri/Electron desktop app (planned) |
| **Shell** | Shell completions (bash, zsh, fish, PowerShell) |

### 🔧 **Developer Workflows**
```bash
# Get secret for CI/CD
lsv get github/token --field value

# Inject into environment
eval $(lsv env my-project --export)

# Generate .env file
lsv export my-project --format dotenv > .env.local

# Sync with team (Git)
lsv sync --remote origin --branch main
```

### 🔄 **Sync & Backup**
- **Git integration** — Commit encrypted vault, diff shows only metadata changes
- **Conflict resolution** — Merge tool for concurrent edits
- **Backup** — Encrypted exports with different passwords
- **Import/Export** — 1Password, Bitwarden, LastPass, KeePass, CSV, JSON

### 🔍 **Search & Access**
- **Fuzzy search** — `lsv search "prod db"`
- **Quick copy** — `lsv copy aws/access_key` (to clipboard, auto-clear)
- **TTL/Expiration** — Rotate reminders, auto-expire
- **Audit log** — Who accessed what, when (local only)

### 🌍 **Persian Support**
| Feature | Implementation |
|---------|----------------|
| **RTL TUI** | Rich with bidirectional text |
| **Persian Prompts** | Interactive prompts in Persian |
| **Jalali Dates** | Expiration, created, modified |
| **Persian Numbers** | ۱۲۳۴۵۶۷۸۹۰ in counters |

---

## 🏗️ Architecture

### Tech Stack

| Layer | Technology |
|-------|------------|
| **Language** | Python 3.9+ |
| **CLI Framework** | Click 8.1 |
| **TUI Framework** | Textual (Rich-based) |
| **Encryption** | cryptography (AES-GCM, Argon2id) |
| **Validation** | Pydantic 2.7 |
| **Serialization** | msgpack / JSON |
| **Clipboard** | pyperclip |
| **Fuzzy Search** | rapidfuzz |
| **Testing** | pytest + pytest-asyncio |
| **Packaging** | setuptools / pyinstaller |

### Project Structure

```
LocalSecretVault/
├── src/
│   └── localsecretvault/
│       ├── __init__.py
│       ├── __main__.py              # Entry point
│       ├── cli.py                   # Click CLI
│       ├── tui/
│       │   ├── __init__.py
│       │   ├── app.py               # Textual app
│       │   ├── screens/             # TUI screens
│       │   │   ├── vault_list.py
│       │   │   ├── secret_view.py
│       │   │   ├── secret_form.py
│       │   │   ├── search.py
│       │   │   └── settings.py
│       │   └── widgets/             # Custom widgets
│       ├── crypto/
│       │   ├── __init__.py
│       │   ├── encryption.py        # AES-GCM + Argon2id
│       │   ├── vault.py             # Vault file format
│       │   └── keys.py              # Key management
│       ├── models/
│       │   ├── __init__.py
│       │   ├── secret.py            # Secret data model
│       │   ├── category.py
│       │   ├── vault.py
│       │   └── config.py
│       ├── storage/
│       │   ├── __init__.py
│       │   ├── file.py              # File vault storage
│       │   └── git.py               # Git sync
│       ├── import_export/
│       │   ├── __init__.py
│       │   ├── bitwarden.py
│       │   ├── onepassword.py
│       │   ├── keepass.py
│       │   ├── csv.py
│       │   └── json.py
│       ├── utils/
│       │   ├── __init__.py
│       │   ├── clipboard.py
│       │   ├── fuzzy.py
│       │   ├── persian.py
│       │   └── config.py
│       └── config/
│           ├── __init__.py
│           └── defaults.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── docs/
│   ├── SECURITY.md
│   ├── TUI_GUIDE.md
│   ├── CLI_REFERENCE.md
│   ├── SYNC_GUIDE.md
│   └── PERSIAN.md
├── pyproject.toml
├── README.md
├── README.fa.md
├── LICENSE
├── CHANGELOG.md
└── CONTRIBUTING.md
```

---

## 🚀 Quick Start

### Prerequisites

- **Python** 3.9+
- **pip** / **pipx** / **uv**

### Installation

```bash
# From PyPI (recommended)
pip install local-secret-vault

# Or with pipx (isolated)
pipx install local-secret-vault

# Or from source
git clone https://github.com/mohammadhossein-asadi/LocalSecretVault.git
cd LocalSecretVault
pip install -e .
```

### Initialize Vault

```bash
# Create new vault
lsv init ~/my-vault.lsv

# Or specify path via env
export LSV_VAULT_PATH=~/my-vault.lsv
lsv init
```

### Basic Usage

```bash
# Add a secret
lsv add github/token \
  --value "ghp_xxxxxxxxxxxx" \
  --category "API Keys" \
  --tags "github,ci" \
  --project "my-app"

# List secrets
lsv list
lsv list --category "Database"
lsv list --project "my-app" --tag "prod"

# Get secret value (copies to clipboard)
lsv get github/token

# Get specific field
lsv get aws/secret_key --field value

# Search
lsv search "production"

# Edit secret
lsv edit github/token --value "ghp_new..."

# Delete
lsv remove github/token

# Export for CI/CD
lsv export my-project --format dotenv > .env.local
lsv export my-project --format json | jq -r '.[] | "export \(.name)=\(.value)"'

# Shell environment injection
eval $(lsv env my-project --export)
```

### Git Sync

```bash
# Initialize git repo for vault
lsv git init ~/my-vault.lsv

# Commit changes
lsv git commit -m "Add production DB credentials"

# Push to remote
lsv git push origin main

# Pull latest
lsv git pull origin main
```

---

## ⚙️ Configuration

Create `~/.config/lsv/config.toml`:

```toml
[vault]
default_path = "~/vault.lsv"
auto_lock_timeout = 300        # Seconds (0 = never)
clipboard_clear_timeout = 30   # Seconds

[ui]
theme = "tokyo-night"          # dracula, tokyo-night, catppuccin, auto
persian_numbers = true
jalali_dates = true
rtl = true
fuzzy_threshold = 0.6

[security]
argon2_memory = 65536          # KB (64 MB)
argon2_iterations = 3
argon2_parallelism = 4
clipboard_clear = true
mask_values = true             # Show **** in list view

[git]
auto_commit = true
commit_message_template = "LSV: {action} {count} secrets"
sign_commits = false

[sync]
conflict_strategy = "prompt"   # prompt, ours, theirs, merge
backup_on_sync = true
```

---

## 🛠️ Development

### Setup

```bash
git clone https://github.com/mohammadhossein-asadi/LocalSecretVault.git
cd LocalSecretVault

python -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"

pre-commit install
```

### Commands

```bash
# Run TUI
lsv

# Run CLI
lsv --help

# Tests
pytest

# Coverage
pytest --cov=localsecretvault --cov-report=html

# Type check
mypy src/localsecretvault

# Lint
ruff check src/
ruff format src/

# Build executable
pyinstaller --onefile src/localsecretvault/__main__.py -n lsv
```

---

## 🧪 Testing

```bash
# Unit tests
pytest tests/unit -v

# Integration tests
pytest tests/integration -v

# Security tests
pytest tests/security -v

# All tests
pytest
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Security Model](docs/SECURITY.md) | Encryption, threat model |
| [TUI Guide](docs/TUI_GUIDE.md) | Keyboard shortcuts, workflows |
| [CLI Reference](docs/CLI_REFERENCE.md) | All commands |
| [Sync Guide](docs/SYNC_GUIDE.md) | Git, cloud, team workflows |
| [Persian Support](docs/PERSIAN.md) | RTL, dates, numbers |

---

## 🔒 Security Model

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Vault file stolen | Argon2id + AES-256-GCM — infeasible to brute force |
| Master password keylogged | TUI masking, clipboard auto-clear |
| Memory dump | Keys zeroed after use, `mlock` where available |
| Supply chain attack | Minimal deps, pinned versions, sigstore verification |
| Sync interception | Vault always encrypted, Git transport encrypted (SSH/HTTPS) |

### Audit

- **Cryptography** — Uses `cryptography` library (audited, FIPS-validated)
- **Argon2id** — Winner of Password Hashing Competition
- **AES-GCM** — NIST-approved authenticated encryption
- **No custom crypto** — Only standard primitives

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

---

## 📋 Roadmap

- [x] Core encryption (AES-GCM + Argon2id)
- [x] Vault file format
- [x] CLI (add, get, list, search, export)
- [x] TUI (Rich/Textual)
- [x] Git sync
- [x] Import (Bitwarden, 1Password, KeePass, CSV)
- [x] Persian RTL support
- [ ] GUI (Tauri)
- [ ] Browser extension
- [ ] SSH agent integration
- [ ] Team sharing (Shamir's Secret Sharing)
- [ ] Hardware key support (YubiKey, Nitrokey)
- [ ] Plugin system

---

## 📄 License

**MIT License** — See [LICENSE](LICENSE)

---

## 🙏 Acknowledgments

- **cryptography** — Python crypto by PyCA
- **Rich/Textual** — Terminal UI by Textualize
- **Click** — CLI by Pallets
- **Pydantic** — Validation by Samuel Colvin
- **Argon2** — Password hashing competition winner
- **Vazirmatn Font** — Persian typography by Rastikerdar

---

## 📞 Support & Community

- **Issues**: [GitHub Issues](https://github.com/mohammadhossein-asadi/LocalSecretVault/issues)
- **Discussions**: [GitHub Discussions](https://github.com/mohammadhossein-asadi/LocalSecretVault/discussions)
- **PyPI**: [local-secret-vault](https://pypi.org/project/local-secret-vault/)

---

<div align="center">

**Built with ❤️ for developers who own their secrets**

[🇬🇧 English](README.md) • [🇮🇷 فارسی](README.fa.md) • [⭐ Star us on GitHub](https://github.com/mohammadhossein-asadi/LocalSecretVault)

</div>