# Project DNA — LocalSecretVault

## Project Identity

| Field | Value |
|-------|-------|
| **Project Name** | LocalSecretVault (localsecretvault) |
| **Repository** | `LocalSecretVault` |
| **Type** | CLI Tool (Python) — Local-First Password & Developer Secrets Manager |
| **Primary Language** | Python 3.10+ |
| **Package Manager** | pip / setuptools |
| **CLI Framework** | Typer 0.9+ (with `all` extras) |
| **TUI Framework** | Textual 0.40+ |
| **Terminal Rendering** | Rich 13.0+ |

---

## Purpose & Problem Statement

**Problem**: Most secrets managers (1Password, Bitwarden, LastPass) require cloud accounts, subscriptions, always-on servers, and trust in third-party infrastructure. Developers need a lightweight, zero-dependency solution for local secrets, API keys, TOTP codes, and `.env` management that they fully control.

**Solution**: A local-first secrets manager where the vault is a single encrypted file on disk. Uses Argon2id + AES-256-GCM for encryption, provides both CLI and TUI interfaces, integrates with developer workflows (`.env`, GitHub CLI), and has zero telemetry or network calls.

---

## Target Users

- **Primary**: Developers managing local API keys, database credentials, SSH keys
- **Secondary**: Security-conscious users wanting offline password management
- **Tertiary**: Teams sharing encrypted vault files via Git/Syncthing/USB
- **Quaternary**: CI/CD pipelines needing local secret injection (via `.env` export)

---

## Core Features (Implemented)

| Feature | Status | Description |
|---------|--------|-------------|
| AES-256-GCM Encryption | ✅ Implemented | Authenticated encryption with Argon2id key derivation (3 iter, 64MB, 4 threads) |
| CLI (24 commands) | ✅ Implemented | Full Typer-based CLI with vault, secret, generator, TOTP, health, backup, GitHub |
| TUI | ✅ Implemented | Textual-based interactive terminal UI with keybindings |
| Password Generator | ✅ Implemented | Cryptographically secure, configurable length/charsets, ambiguous char exclusion |
| Passphrase Generator | ✅ Implemented | Diceware-style (1296-word list), configurable words/separator/capitalization |
| TOTP Support | ✅ Implemented | RFC 6238 compliant, store secrets, generate codes, provisioning URIs |
| Password Strength Analysis | ✅ Implemented | Offline scoring with pattern detection (sequences, keyboard walks, repeats, dates) |
| Password Health | ✅ Implemented | Weak/reused/stale detection across vault, age tracking |
| Clipboard Integration | ✅ Implemented | Cross-platform copy with 30-second auto-clear (pyperclip) |
| .env Import/Export | ✅ Implemented | Bidirectional sync with `.env` files |
| GitHub Secrets Sync | ✅ Implemented | Push/pull repository secrets via `gh` CLI |
| Encrypted Backups | ✅ Implemented | Create/restore encrypted backups with safety copies |
| Search | ✅ Implemented | Fast metadata search across names, tags, URLs, usernames |
| Auto-Lock | ✅ Implemented | Automatic vault locking after inactivity (signal handling) |
| Security Audit | ✅ Implemented | Vault integrity, permissions, config, telemetry, health, GitHub CLI checks |
| Cross-Platform | ✅ Implemented | Windows, macOS, Linux with platformdirs for config paths |

---

## Technical Requirements

| Requirement | Detail |
|-------------|--------|
| **Runtime** | Python 3.10+ |
| **Key Derivation** | Argon2id (argon2-cffi 23.1+) |
| **Encryption** | AES-256-GCM (cryptography 42.0+) |
| **CLI** | Typer 0.9+ with all extras |
| **TUI** | Textual 0.40+ |
| **Terminal** | Rich 13.0+ |
| **Config Paths** | platformdirs 3.0+ |
| **Clipboard** | pyperclip 1.8+ |
| **Environment** | python-dotenv 1.0+ |
| **Testing** | pytest 7.0+ (224 tests passing) |
| **Linting** | Ruff (comprehensive rule set, security rules enabled) |
| **Type Checking** | MyPy 1.0+ (strict mode) |

---

## Functional Requirements

| ID | Requirement | Status |
|----|-------------|--------|
| FR-01 | Create vault with master password | ✅ |
| FR-02 | Unlock/lock vault | ✅ |
| FR-03 | Add secrets (7 types: Login, API Key, Database, SSH Key, Secure Note, Environment, Generic) | ✅ |
| FR-04 | Retrieve secrets (masked display, clipboard copy) | ✅ |
| FR-05 | Edit/delete secrets | ✅ |
| FR-06 | List/search/filter secrets | ✅ |
| FR-07 | Generate secure passwords | ✅ |
| FR-08 | Generate Diceware passphrases | ✅ |
| FR-09 | Analyze password strength | ✅ |
| FR-10 | Password health report (weak/reused/stale) | ✅ |
| FR-11 | TOTP code generation | ✅ |
| FR-12 | .env file import/export | ✅ |
| FR-13 | Encrypted backup/restore | ✅ |
| FR-14 | GitHub repository secrets push/pull | ✅ |
| FR-15 | Security audit | ✅ |
| FR-16 | Auto-lock on inactivity | ✅ |
| FR-17 | Cross-platform config paths | ✅ |

---

## Non-Functional Requirements

| ID | Requirement | Status |
|----|-------------|--------|
| NFR-01 | Master password never stored on disk | ✅ |
| NFR-02 | Wrong password → generic auth failure | ✅ |
| NFR-03 | Atomic file writes (crash-safe) | ✅ |
| NFR-04 | Secrets never printed in CLI output | ✅ |
| NFR-05 | TOTP generated locally | ✅ |
| NFR-06 | Clipboard auto-clear (30s) | ✅ |
| NFR-07 | File permissions (600 vault, 700 config on Unix) | ✅ |
| NFR-08 | Zero network requests/telemetry | ✅ |
| NFR-09 | 224 tests passing | ✅ |
| NFR-10 | Memory-hard KDF (Argon2id) | ✅ |
| NFR-11 | Tamper-evident encryption (AES-GCM) | ✅ |

---

## Business/Technical Objectives

- [ ] Publish to PyPI as `localsecretvault`
- [ ] Maintain 90%+ test coverage
- [ ] Add standalone binary releases (PyInstaller)
- [ ] Implement vault migration/versioning
- [ ] Add hardware key support (YubiKey) for unlock
- [ ] Create browser extension for auto-fill
- [ ] Add team-sharing features (Shamir's Secret Sharing for vault access)
- [ ] Implement breach monitoring (haveibeenpwned integration, offline)

---

## Known Limitations

1. **Single vault only** - No multi-vault support
2. **No cloud sync built-in** - User must sync vault file manually (Git, Syncthing, etc.)
3. **No browser integration** - CLI/TUI only
4. **No team/vault sharing** - Single-user design
5. **Master password recovery impossible** - By design (no backdoors)
6. **TUI may need specific terminal** - Textual requires modern terminal emulator
7. **Windows file permissions** - Unix permissions not enforced on Windows
8. **Clipboard window** - 30-second exposure window for clipboard snooping

---

## Confirmed Decisions

| Decision | Rationale |
|----------|-----------|
| Local-first (single file vault) | User ownership, portability, no server needed |
| Argon2id + AES-256-GCM | Industry-standard, memory-hard, authenticated encryption |
| Typer for CLI | Modern, type-safe, Rich integration, easy testing |
| Textual for TUI | CSS-stylable, reactive, cross-platform, accessible |
| 7 secret types | Covers developer needs (Login, API Key, DB, SSH, Note, Env, Generic) |
| 1296-word Diceware list | Standard wordlist, ~10.5 bits/word entropy |
| RFC 6238 TOTP | Standard 2FA algorithm, compatible with all authenticator apps |
| Platformdirs for paths | Correct XDG/Base/AppData per OS |
| Pyperclip for clipboard | Cross-platform, simple API |
| gh CLI for GitHub integration | Official, maintained, handles auth |
| Ruff + MyPy strict | Fast linting, comprehensive rules, type safety |

---

## Unknown Information / Needs Confirmation

| Question | Priority |
|----------|----------|
| Is PyPI publishing automated (trusted publishing)? | HIGH |
| Are standalone binaries built for all platforms? | HIGH |
| Will multi-vault support be added? | MEDIUM |
| Is there a vault migration strategy for format changes? | MEDIUM |
| Will hardware key (YubiKey) support be added? | LOW |
| Are there plans for a browser extension? | LOW |
| What is the release versioning scheme? | LOW |

---

*Generated: 2026-10-30 | Stage 1 of 5 | [NEEDS CONFIRMATION] on unknowns*