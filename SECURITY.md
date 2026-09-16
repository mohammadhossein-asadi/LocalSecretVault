# Security Policy — LocalSecretVault

## Security Model

LocalSecretVault is a local-first secrets manager. All secrets are encrypted at rest
using the master password as the sole authentication factor. There is no cloud service,
no account system, and no telemetry.

The security boundary is the encrypted vault file. Anyone with access to both the vault
file and the master password can decrypt all secrets. The application's role is to
protect secrets from unauthorized access, accidental disclosure, and data loss.

## Cryptographic Design

### Key Derivation

- **Algorithm:** Argon2id (winner of the Password Hashing Competition)
- **Parameters:**
  - Time cost: 3 iterations
  - Memory cost: 64 MB
  - Parallelism: 4 threads
  - Salt: 32 bytes, cryptographically random
  - Key length: 32 bytes (256 bits)

### Authenticated Encryption

- **Algorithm:** AES-256-GCM (Galois/Counter Mode)
- **Nonce:** 12 bytes, cryptographically random
- **Authentication tag:** 16 bytes (128-bit), appended to ciphertext

### Vault Format (LSV1)

```
Magic:     4 bytes   "LSV1"
Version:   1 byte    (0x01)
Salt:     32 bytes   (random)
KDF time:  4 bytes   (uint32 big-endian)
KDF mem:   4 bytes   (uint32 big-endian, in KB)
KDF par:   4 bytes   (uint32 big-endian)
Nonce:    12 bytes   (random, for AES-GCM)
Payload:  variable   (encrypted JSON + GCM auth tag)
```

### What Is Encrypted

- All secret data (passwords, API keys, notes, custom fields)
- All metadata (names, usernames, URLs, tags)
- The vault structure itself

### What Is NOT Encrypted

- The vault file location on disk
- File timestamps (created/modified)
- The vault file size (an adversary can observe the file exists and its approximate size)

## Threat Model

### Protected Against

- **Offline attack on vault file:** Without the master password, the attacker must
  brute-force Argon2id (memory-hard, 3 iterations, 64MB) to derive the key, then
  break AES-256-GCM. This is computationally infeasible for strong passwords.

- **Tampering:** AES-GCM provides authenticated encryption. Any modification to the
  ciphertext (including flipping bits) will be detected and rejected.

- **Password logging:** The master password is never logged, printed, stored to disk,
  or included in error messages. Error messages reveal only "authentication failed."

- **Accidental disclosure:** The CLI never prints secret values in normal operation.
  Secrets are displayed as `********` by default and require explicit `--copy` or
  `--field` to access.

- **Data loss from interruption:** Vault modifications use atomic file writes
  (write to temp → flush → fsync → rename). Power loss or crashes during writes
  will not corrupt the existing vault.

- **Clipboard snooping:** Copied secrets auto-clear after 30 seconds (configurable).

### Not Protected Against

- **Malware/keyloggers:** If an attacker has code execution on your machine, they can
  capture the master password during input or read secrets from memory.

- **Physical access:** If the machine is unlocked and the vault is unlocked in memory,
  an attacker with physical access can read secrets.

- **Weak master password:** A weak password (e.g., "password123") is vulnerable to
  dictionary attacks. Use a strong, unique master password.

- **Memory forensics:** While the vault locks and clears references, Python's garbage
  collector may not immediately zero memory. Secrets may remain in memory briefly
  after locking.

- **Clipboard contents:** Other applications can read clipboard contents before the
  auto-clear timer fires. Clipboard clearing is best-effort, not absolute security.

- **Timestamps and file size:** The encrypted vault file reveals its existence, size,
  and modification times. This is metadata leakage.

- **Quantum computing:** AES-256 and Argon2id are currently considered quantum-resistant
  in practice, but long-term quantum resistance is not guaranteed.

## Master Password Security

- The master password is never stored anywhere — not in the vault, not in config,
  not in logs, not in temporary files.
- Password input uses hidden terminal input (getpass) to prevent shoulder surfing.
- Wrong passwords produce only "authentication failed" — no details about which
  cryptographic component failed.
- The master password exists only in process memory during the unlocked state.

## Backup Security

- Backups are encrypted with the same format as the vault.
- No plaintext backups are created unless the user explicitly exports.
- Restore operations create a safety backup before overwriting.
- Backup integrity is validated before restoration.

## Synchronization Security

The vault file is designed to be synchronized through external tools:
- Git, Syncthing, OneDrive, Dropbox, Google Drive, USB, NAS

The synchronization system receives only the encrypted file. It never receives
plaintext secrets. However, be aware:

- File synchronization may preserve file history/versions
- The sync provider can observe file size and modification timestamps
- Conflicting edits may require manual merge (the vault does not have built-in
  conflict resolution)

## Responsible Disclosure

If you discover a security vulnerability, please report it privately.
Do not open a public GitHub issue for security vulnerabilities.
