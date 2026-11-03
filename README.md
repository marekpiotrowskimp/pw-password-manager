# PW - Local Password Manager

A secure, local command-line password manager written in C++. No cloud, no network dependencies.

## Features

- **Offline** - all data is stored locally in the current directory
- **Double encryption** - the whole file + every password separately
- **Cross-platform** - Windows and macOS
- **No runtime dependencies** - a single executable

## Security

### Two-layer encryption

```
┌─────────────────────────────────────────────────┐
│         Layer 1: whole file                     │
│           (XChaCha20-Poly1305)                  │
│  ┌───────────────────────────────────────────┐  │
│  │  {                                        │  │
│  │    "entries": [                           │  │
│  │      {                                    │  │
│  │        "name": "github",                  │  │
│  │        "username": "user@mail.com",       │  │
│  │        "password": "████████",  ◄─────────│──│─ Layer 2
│  │        "url": "..."                       │  │  (AES-256-GCM)
│  │      }                                    │  │
│  │    ]                                      │  │
│  │  }                                        │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

### Key derivation

```
Master password (+ optional keyfile)
                │
                ▼
         ┌─────────────┐
         │  Argon2id   │  ← Memory: 64 MB, Iterations: 3
         └─────────────┘
                │
                ▼
        512-bit output
                │
        ┌───────┴───────┐
        ▼               ▼
   256-bit key     256-bit key
   (file)          (passwords)
```

### Authentication modes

| Mode | Description | Use |
|------|-------------|-----|
| Master password | A single password | Everyday use |
| Master password + keyfile | Password + key file | High security |

### Duress password

A safety feature for emergencies. When the duress password is entered instead of the master password:

1. **Secure wipe** of all data (overwritten 3 times with random data)
2. **Keyfile deletion** (if configured)
3. **A fake vault is created** that looks corrupted
4. **Optional deletion of the application**

An attacker sees: `"Vault file is corrupted"`

```
┌─────────────────────────────────────────────────────────────┐
│                    DURESS PASSWORD                          │
├─────────────────────────────────────────────────────────────┤
│  Entering the duress password:                              │
│                                                             │
│    1. Secure wipe of the vault (3x random + zeros)          │
│    2. Delete the keyfile                                    │
│    3. Create a fake "corrupted" vault                       │
│    4. (optional) Delete the application                     │
│                                                             │
│  Result: "Vault file is corrupted"                          │
│                                                             │
│  ⚠️  IRREVERSIBLE - all data will be lost                   │
└─────────────────────────────────────────────────────────────┘
```

## Vault file format

The `.pw_vault` file in the current directory (format v2):

```
┌────────────────────────────────────┐
│ Magic: "PWVAULT1" (8 bytes)        │
│ Version: uint32 (4 bytes)          │
│ Flags: uint8 (1 byte)              │  ← v2: vault flags
│ Duress hash: 32 bytes (if flag)    │  ← v2: duress password hash
│ Keyfile path length: uint16        │
│ Keyfile path: string (if present)  │
│ Salt: 32 bytes                     │
│ Nonce: 24 bytes                    │
│ Encrypted data + auth tag          │
└────────────────────────────────────┘
```

**Vault flags:**
- `0x01` - duress password enabled
- `0x02` - delete the application when the duress password is used

### Data structure (after decrypting layer 1)

```json
{
  "entries": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "github",
      "username": "user@example.com",
      "password": {
        "nonce": "base64...",
        "cipher": "base64..."
      },
      "url": "https://github.com",
      "notes": "2FA enabled",
      "created": 1733480000,
      "updated": 1733480000
    }
  ]
}
```

## Installation

### Build requirements

**macOS:**
- CMake 3.16+
- Clang (Xcode Command Line Tools)
- libsodium: `brew install libsodium`

**Windows cross-compilation (from macOS):**
- mingw-w64: `brew install mingw-w64`
- libsodium for Windows (built automatically by the script)

### Building

```bash
git clone https://github.com/marekpiotrowskimp/pw-password-manager.git
cd pw-password-manager

# Build both platforms (macOS + Windows)
./build.sh

# macOS only
./build.sh macos

# Windows .exe only
./build.sh windows

# Tests
./build.sh test

# Clean
./build.sh clean
```

### Output files

| Platform | File | Size |
|----------|------|------|
| macOS (arm64) | `build/pw` | ~1.7 MB |
| Windows (x64) | `build-win64/pw.exe` | ~16 MB |

The Windows .exe is fully static - it needs no DLLs.

## Portable use on a USB stick

The application is designed to be carried on a USB stick:

```
/USBSTICK/
├── pw           # macOS binary
├── pw.exe       # Windows binary
├── .pw_vault    # Encrypted vault (created automatically)
└── .pw_keyfile  # Optional key file
```

**macOS:**
```bash
chmod +x /Volumes/USBSTICK/pw   # first time only
/Volumes/USBSTICK/pw
```

**Windows:**
- Double-click `pw.exe`
- Or from the command line: `E:\pw.exe`

The application detects its own directory and looks for (or creates) the vault in the same place.

## Usage

### Initialization

```bash
# New vault with a master password
pw init
> Create master password: ********
> Confirm password: ********
✓ Vault created: .pw_vault

# New vault with a keyfile (higher security)
pw init --keyfile ~/.pw.key
> Create master password: ********
> Confirm password: ********
✓ Generated keyfile: ~/.pw.key
✓ Vault created: .pw_vault
```

### Managing entries

```bash
# Add an entry
pw add github
> Master password: ********
> Username: user@example.com
> Password (enter to generate): ********
> URL (optional): https://github.com
> Notes (optional): 2FA enabled
✓ Entry 'github' added

# Add with a generated password
pw add github --generate
> Master password: ********
> Username: user@example.com
> URL (optional): https://github.com
✓ Generated password: Kj9#mP2$xL5@nQ8
✓ Entry 'github' added

# Get a password (copies to the clipboard)
pw get github
> Master password: ********
✓ Password copied to clipboard (clears in 30s)

# Show a password
pw get github --show
> Master password: ********
Password: Kj9#mP2$xL5@nQ8

# List entries
pw list
> Master password: ********
NAME          USERNAME              URL
github        user@example.com      https://github.com
aws           admin@company.com     https://aws.amazon.com
bank          john.doe              https://bank.com

# Search
pw search git
> Master password: ********
NAME          USERNAME              URL
github        user@example.com      https://github.com
gitlab        user@example.com      https://gitlab.com

# Delete
pw rm github
> Master password: ********
> Confirm deletion of 'github'? [y/N]: y
✓ Entry 'github' deleted
```

### Password generator

```bash
# Default (20 characters)
pw generate
Kj9#mP2$xL5@nQ8wR3&t

# Specific length
pw generate 32
Kj9#mP2$xL5@nQ8wR3&tYm4^vB7*cD1!

# Without symbols
pw generate 16 --no-symbols
Kj9mP2xL5nQ8wR3t

# Alphanumeric only
pw generate 16 --alphanumeric
Kj9mP2xL5nQ8wR3t
```

### Configuration

```bash
# Add a keyfile to an existing vault
pw config --add-keyfile ~/.pw.key
> Master password: ********
✓ Generated keyfile: ~/.pw.key
✓ Vault re-encrypted

# Change the master password
pw config --change-password
> Current password: ********
> New password: ********
> Confirm new password: ********
✓ Password changed

# Remove the keyfile
pw config --remove-keyfile
> Master password: ********
✓ Keyfile removed, vault re-encrypted
```

### Duress password

```bash
# In the interactive menu: Settings > Duress password

# Enable the duress password
> Enter current master password: ********
> Enter new duress password: ****
> Confirm duress password: ****
> Delete application when duress password is used? [y/N]: y
✓ Duress password configured!

# After entering the duress password at login:
> Master password: ****
[!] Vault file is corrupted
[*] The vault file appears to be damaged and cannot be opened.
[*] You may need to restore from backup.
```

**Warning:** using the duress password is **IRREVERSIBLE**. All data
is permanently deleted. Use it only in an emergency.

### Backup and export

```bash
# Encrypted export (full backup)
pw export backup.pwvault
> Master password: ********
✓ Exported to backup.pwvault

# Import from a backup
pw import backup.pwvault
> Backup password: ********
> Current vault password: ********
✓ Imported 15 entries
```

## Project structure

```
pw-password-manager/
├── CMakeLists.txt
├── build.sh               # Build script (macOS + Windows)
├── vcpkg.json
├── cmake/
│   └── toolchain-mingw64.cmake  # Toolchain for the Windows cross-compile
├── deps/
│   ├── libsodium-1.0.20-stable.tar.gz  # libsodium sources (Windows build)
│   └── nlohmann/          # json.hpp header
├── include/
│   ├── crypto.hpp         # Encryption/decryption
│   ├── vault.hpp          # Vault management
│   ├── entry.hpp          # Entry structure
│   ├── clipboard.hpp      # Clipboard handling
│   ├── generator.hpp      # Password generator
│   └── secure_string.hpp  # Secure string (auto-zeroing)
├── src/
│   ├── main.cpp           # Main program (interactive menu)
│   ├── crypto.cpp
│   ├── vault.cpp
│   ├── entry.cpp
│   ├── generator.cpp
│   ├── clipboard.cpp
│   ├── clipboard_win.cpp  # Windows clipboard
│   └── clipboard_mac.cpp  # macOS clipboard
└── tests/
    ├── test_crypto.cpp
    ├── test_vault.cpp
    ├── test_entry.cpp
    └── test_generator.cpp
```

`build.sh windows` builds libsodium for Windows into `deps/libsodium-win64/` (not committed).

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| libsodium | 1.0.18+ | Cryptography (Argon2id, XChaCha20-Poly1305, AES-GCM) |
| nlohmann/json | 3.11+ | JSON parsing (header-only, bundled) |

## Security - implementation details

### Memory protection

- Sensitive data (passwords, keys) is kept in `SecureString`
- Memory is zeroed automatically on destruction (`sodium_memzero`)
- Sensitive objects cannot be copied

### Clipboard

- Cleared automatically after 30 seconds
- Overwritten before clearing

### Randomness

- `randombytes_buf()` from libsodium (CSPRNG)
- Entropy from the operating system

## License

MIT — see [LICENSE](LICENSE). libsodium is ISC-licensed, nlohmann/json is MIT-licensed.

## Author

Marek Piotrowski
