# PW - Local Password Manager

Bezpieczny, lokalny menedżer haseł CLI napisany w C++. Zero chmury, zero zależności sieciowych.

## Cechy

- **Offline** - wszystkie dane przechowywane lokalnie w bieżącym katalogu
- **Podwójne szyfrowanie** - cały plik + każde hasło osobno
- **Cross-platform** - Windows i macOS
- **Zero zależności runtime** - pojedynczy plik wykonywalny

## Bezpieczeństwo

### Szyfrowanie dwuwarstwowe

```
┌─────────────────────────────────────────────────┐
│         Warstwa 1: Cały plik                    │
│           (XChaCha20-Poly1305)                  │
│  ┌───────────────────────────────────────────┐  │
│  │  {                                        │  │
│  │    "entries": [                           │  │
│  │      {                                    │  │
│  │        "name": "github",                  │  │
│  │        "username": "user@mail.com",       │  │
│  │        "password": "████████",  ◄─────────│──│─ Warstwa 2
│  │        "url": "..."                       │  │  (AES-256-GCM)
│  │      }                                    │  │
│  │    ]                                      │  │
│  │  }                                        │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

### Derivacja klucza

```
Master Password (+ opcjonalnie keyfile)
                │
                ▼
         ┌─────────────┐
         │  Argon2id   │  ← Memory: 64MB, Iterations: 3
         └─────────────┘
                │
                ▼
        512-bit output
                │
        ┌───────┴───────┐
        ▼               ▼
   256-bit Key     256-bit Key
   (plik)          (hasła)
```

### Tryby uwierzytelniania

| Tryb | Opis | Użycie |
|------|------|--------|
| Master password | Pojedyncze hasło | Codzienne użycie |
| Master password + keyfile | Hasło + plik klucza | Wysokie bezpieczeństwo |

### Hasło paniki (Duress Password)

Funkcja bezpieczeństwa dla sytuacji awaryjnych. Po wprowadzeniu hasła paniki zamiast master password:

1. **Bezpieczne usunięcie** wszystkich danych (3-krotne nadpisanie losowymi danymi)
2. **Usunięcie keyfile** (jeśli skonfigurowany)
3. **Utworzenie fałszywego vault** który wygląda na uszkodzony
4. **Opcjonalne usunięcie aplikacji**

Atakujący zobaczy: `"Vault file is corrupted"`

```
┌─────────────────────────────────────────────────────────────┐
│                    DURESS PASSWORD                          │
├─────────────────────────────────────────────────────────────┤
│  Wpisanie hasła paniki:                                     │
│                                                             │
│    1. Secure wipe vault (3x random + zeros)                │
│    2. Usuń keyfile                                          │
│    3. Utwórz fake "uszkodzony" vault                        │
│    4. (opcja) Usuń aplikację                                │
│                                                             │
│  Wynik: "Vault file is corrupted"                           │
│                                                             │
│  ⚠️  NIEODWRACALNE - wszystkie dane zostaną utracone        │
└─────────────────────────────────────────────────────────────┘
```

## Format pliku vault

Plik `.pw_vault` w bieżącym katalogu (format v2):

```
┌────────────────────────────────────┐
│ Magic: "PWVAULT1" (8 bytes)        │
│ Version: uint32 (4 bytes)          │
│ Flags: uint8 (1 byte)              │  ← v2: flagi vault
│ Duress hash: 32 bytes (jeśli flag) │  ← v2: hash hasła paniki
│ Keyfile path length: uint16        │
│ Keyfile path: string (jeśli jest)  │
│ Salt: 32 bytes                     │
│ Nonce: 24 bytes                    │
│ Encrypted data + auth tag          │
└────────────────────────────────────┘
```

**Flagi vault:**
- `0x01` - Duress password włączone
- `0x02` - Usuwać aplikację przy użyciu hasła paniki

### Struktura danych (po odszyfrowaniu warstwy 1)

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

## Instalacja

### Wymagania do kompilacji

**macOS:**
- CMake 3.16+
- Clang (Xcode Command Line Tools)
- libsodium: `brew install libsodium`

**Cross-kompilacja Windows (z macOS):**
- mingw-w64: `brew install mingw-w64`
- libsodium dla Windows (budowane automatycznie przez skrypt)

### Budowanie

```bash
# Klonowanie
git clone https://github.com/user/pw.git
cd pw

# Budowanie obu platform (macOS + Windows)
./build.sh

# Tylko macOS
./build.sh macos

# Tylko Windows .exe
./build.sh windows

# Testy
./build.sh test

# Czyszczenie
./build.sh clean
```

### Wynikowe pliki

| Platforma | Plik | Rozmiar |
|-----------|------|---------|
| macOS (arm64) | `build/pw` | ~1.7 MB |
| Windows (x64) | `build-win64/pw.exe` | ~16 MB |

Plik Windows .exe jest w pełni statyczny - nie wymaga żadnych DLL.

## Użycie na pendrive (portable)

Aplikacja jest zaprojektowana do przenośnego użycia na pendrive:

```
/PENDRIVE/
├── pw           # macOS binary
├── pw.exe       # Windows binary
├── .pw_vault    # Zaszyfrowany vault (tworzony automatycznie)
└── .pw_keyfile  # Opcjonalny plik klucza
```

**macOS:**
```bash
chmod +x /Volumes/PENDRIVE/pw   # Tylko pierwszy raz
/Volumes/PENDRIVE/pw
```

**Windows:**
- Podwójne kliknięcie na `pw.exe`
- Lub z wiersza poleceń: `E:\pw.exe`

Aplikacja automatycznie wykrywa swój katalog i szuka/tworzy vault w tym samym miejscu.

## Użycie

### Inicjalizacja

```bash
# Nowy vault z master password
pw init
> Create master password: ********
> Confirm password: ********
✓ Vault created: .pw_vault

# Nowy vault z keyfile (wyższe bezpieczeństwo)
pw init --keyfile ~/.pw.key
> Create master password: ********
> Confirm password: ********
✓ Generated keyfile: ~/.pw.key
✓ Vault created: .pw_vault
```

### Zarządzanie wpisami

```bash
# Dodawanie wpisu
pw add github
> Master password: ********
> Username: user@example.com
> Password (enter to generate): ********
> URL (optional): https://github.com
> Notes (optional): 2FA enabled
✓ Entry 'github' added

# Dodawanie z wygenerowanym hasłem
pw add github --generate
> Master password: ********
> Username: user@example.com
> URL (optional): https://github.com
✓ Generated password: Kj9#mP2$xL5@nQ8
✓ Entry 'github' added

# Pobieranie hasła (kopiuje do clipboard)
pw get github
> Master password: ********
✓ Password copied to clipboard (clears in 30s)

# Wyświetlanie hasła
pw get github --show
> Master password: ********
Password: Kj9#mP2$xL5@nQ8

# Lista wpisów
pw list
> Master password: ********
NAME          USERNAME              URL
github        user@example.com      https://github.com
aws           admin@company.com     https://aws.amazon.com
bank          john.doe              https://bank.com

# Wyszukiwanie
pw search git
> Master password: ********
NAME          USERNAME              URL
github        user@example.com      https://github.com
gitlab        user@example.com      https://gitlab.com

# Usuwanie
pw rm github
> Master password: ********
> Confirm deletion of 'github'? [y/N]: y
✓ Entry 'github' deleted
```

### Generator haseł

```bash
# Domyślne (20 znaków)
pw generate
Kj9#mP2$xL5@nQ8wR3&t

# Określona długość
pw generate 32
Kj9#mP2$xL5@nQ8wR3&tYm4^vB7*cD1!

# Bez symboli
pw generate 16 --no-symbols
Kj9mP2xL5nQ8wR3t

# Tylko alfanumeryczne
pw generate 16 --alphanumeric
Kj9mP2xL5nQ8wR3t
```

### Konfiguracja

```bash
# Dodanie keyfile do istniejącego vault
pw config --add-keyfile ~/.pw.key
> Master password: ********
✓ Generated keyfile: ~/.pw.key
✓ Vault re-encrypted

# Zmiana master password
pw config --change-password
> Current password: ********
> New password: ********
> Confirm new password: ********
✓ Password changed

# Usunięcie keyfile
pw config --remove-keyfile
> Master password: ********
✓ Keyfile removed, vault re-encrypted
```

### Hasło paniki (Duress Password)

```bash
# W menu interaktywnym: Settings > Duress password

# Włączenie hasła paniki
> Enter current master password: ********
> Enter new duress password: ****
> Confirm duress password: ****
> Delete application when duress password is used? [y/N]: y
✓ Duress password configured!

# Po wpisaniu hasła paniki przy logowaniu:
> Master password: ****
[!] Vault file is corrupted
[*] The vault file appears to be damaged and cannot be opened.
[*] You may need to restore from backup.
```

**Ostrzeżenie:** Użycie hasła paniki jest **NIEODWRACALNE**. Wszystkie dane 
zostaną trwale usunięte. Używaj tylko w sytuacjach awaryjnych.

### Backup i eksport

```bash
# Eksport zaszyfrowany (pełny backup)
pw export backup.pwvault
> Master password: ********
✓ Exported to backup.pwvault

# Import z backupu
pw import backup.pwvault
> Backup password: ********
> Current vault password: ********
✓ Imported 15 entries
```

## Struktura projektu

```
password/
├── CMakeLists.txt
├── build.sh               # Skrypt budowania (macOS + Windows)
├── vcpkg.json
├── README.md
├── cmake/
│   └── toolchain-mingw64.cmake  # Toolchain dla Windows cross-compile
├── deps/
│   ├── libsodium-stable/  # Źródła libsodium
│   ├── libsodium-win64/   # Skompilowany libsodium dla Windows
│   └── nlohmann/          # json.hpp header
├── include/
│   ├── crypto.hpp         # Szyfrowanie/deszyfrowanie
│   ├── vault.hpp          # Zarządzanie vault
│   ├── entry.hpp          # Struktura wpisu
│   ├── clipboard.hpp      # Obsługa schowka
│   ├── generator.hpp      # Generator haseł
│   └── secure_string.hpp  # Bezpieczny string (auto-zerowanie)
├── src/
│   ├── main.cpp           # Główny program (interaktywne menu)
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

## Zależności

| Biblioteka | Wersja | Cel |
|------------|--------|-----|
| libsodium | 1.0.18+ | Kryptografia (Argon2id, XChaCha20-Poly1305, AES-GCM) |
| nlohmann/json | 3.11+ | Parsowanie JSON (header-only, bundled) |

## Bezpieczeństwo - szczegóły implementacji

### Ochrona pamięci

- Wrażliwe dane (hasła, klucze) przechowywane w `SecureString`
- Automatyczne zerowanie pamięci przy destrukcji (`sodium_memzero`)
- Blokada kopiowania wrażliwych obiektów

### Clipboard

- Automatyczne czyszczenie po 30 sekundach
- Nadpisanie przed wyczyszczeniem

### Generowanie losowości

- `randombytes_buf()` z libsodium (CSPRNG)
- Entropia z systemu operacyjnego

## Licencja

MIT

## Autor

[Twoje dane]
