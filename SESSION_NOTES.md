# Notatki z sesji - 6 grudnia 2025

## Wykonane zmiany

### 1. Naprawa znikającej historii haseł przy zmianie keyfile

**Problem:** Po dodaniu lub usunięciu keyfile w ustawieniach znikała historia haseł.

**Przyczyna:** Funkcje `add_keyfile`, `remove_keyfile` i `change_password` w `vault.cpp`:
- Wywoływały `open()`, które nadpisywało dane w pamięci danymi z pliku
- Nie prze-szyfrowywały historii haseł (`password_history`) nowym kluczem

**Rozwiązanie:** Zmieniono wszystkie trzy funkcje aby:
- Wymagały otwartego vaulta (`is_open_` check) zamiast wywoływać `open()`
- Operowały na danych już obecnych w pamięci
- Prze-szyfrowywały zarówno hasła jak i ich historię nowym kluczem

**Pliki zmienione:** `src/vault.cpp` (linie ~340-510)

### 2. Dodanie .gitignore

**Problem:** Do repozytorium zostało dodane wiele niepotrzebnych plików (build, cache, vcpkg).

**Rozwiązanie:**
- Utworzono `.gitignore` z kategoriami: build, IDE, cache, vcpkg, binaria, dane wrażliwe, CMake
- Usunięto ~592 plików z śledzenia git (`git rm -r --cached`)

**Pliki dodane:** `.gitignore`

### 3. Dynamiczne szerokości kolumn w liście wpisów

**Problem:** Lista wpisów obcinała długie loginy i emaile (stała szerokość 25 znaków).

**Rozwiązanie:** Zmieniono `list_entries()` i `search_entries()` w `main.cpp`:
- Obliczanie maksymalnych szerokości kolumn na podstawie danych
- Dynamiczne dopasowanie szerokości z paddingiem +2

**Pliki zmienione:** `src/main.cpp` (funkcje `list_entries` i `search_entries`)

---

# Notatki z sesji - 11 grudnia 2025

## Wykonane zmiany

### 4. Automatyczne wykrywanie katalogu executable jako domyślnej lokalizacji vault

**Problem:** Gdy aplikacja była uruchamiana przez podwójne kliknięcie (np. na macOS), current working directory był ustawiany na home (`~`) lub root (`/`), a nie na katalog gdzie znajduje się plik wykonywalny. Vault szukał plików `.pw_vault` w niewłaściwym miejscu.

**Rozwiązanie:**
1. Dodano funkcje platform-specific w `vault.cpp`:
   - `get_executable_directory()` - wykrywa katalog exe na Windows, macOS i Linux
   - `path_join()` - łączy ścieżki w sposób przenośny

2. Zmieniono konstruktor `Vault`:
   - Domyślnie ustawia `vault_dir_` na katalog executable
   - `vault_path_` jest teraz pełną ścieżką łączącą katalog i nazwę pliku

3. Dodano metodę `set_directory()` w klasie Vault do ręcznej zmiany katalogu

4. Zaktualizowano `load_keyfile()` i `generate_keyfile()`:
   - Ścieżki relatywne są rozwiązywane względem `vault_dir_`
   - Ścieżki absolutne używane bez zmian

**Pliki zmienione:**
- `include/vault.hpp` - dodano deklaracje funkcji i pole `vault_dir_`
- `src/vault.cpp` - implementacja wykrywania katalogu exe
- `src/main.cpp` - zaktualizowano komunikaty (pokazują rzeczywistą ścieżkę)

### 5. Opcja zmiany katalogu vault w ustawieniach

**Problem:** Użytkownik nie mógł zmienić lokalizacji vault w runtime.

**Rozwiązanie:** Dodano opcję [7] w menu Settings:
- Wyświetla aktualny katalog i pełną ścieżkę vault
- Pozwala na zmianę katalogu
- Waliduje czy katalog istnieje
- Ostrzega że pliki nie są przenoszone automatycznie

**Pliki zmienione:** `src/main.cpp` - funkcja `set_vault_directory()` i `settings_menu()`

### 6. Naprawa CMakeLists.txt

**Problem:** Vcpkg nie był dostępny, build nie działał.

**Rozwiązanie:** Zmieniono CMakeLists.txt aby:
- Szukać libsodium przez pkg-config lub bezpośrednio w homebrew
- Testy GTest są opcjonalne (nie blokują builda gdy brak)

**Pliki zmienione:** `CMakeLists.txt`

### 7. Naprawa testu ChangePassword

**Problem:** Test wywoływał `vault.close()` przed `change_password()`, ale funkcja wymaga otwartego vault.

**Rozwiązanie:** Usunięto niepotrzebne `vault.close()` przed zmianą hasła.

**Pliki zmienione:** `tests/test_vault.cpp`

## Stan testów

Wszystkie 41 testów przechodzi:
- CryptoTest: 11 testów
- VaultTest: 11 testów
- GeneratorTest: 14 testów
- EntryTest: 5 testów

## Do zrobienia w przyszłości

- Rozważyć dodanie weryfikacji hasła przy `add_keyfile`/`remove_keyfile`
- Testy jednostkowe dla nowych zmian w historii haseł
- Persystentne zapisywanie ustawień katalogu (obecnie reset przy restarcie)
- Opcja automatycznego przenoszenia plików vault przy zmianie katalogu

---

# Notatki z sesji - 11 grudnia 2025 (kontynuacja)

## Cross-kompilacja Windows z macOS

### 8. Konfiguracja MinGW-w64

**Cel:** Utworzenie statycznego pliku .exe dla Windows bez zależności od DLL.

**Instalacja:**
```bash
brew install mingw-w64
```

**Plik toolchain:** `cmake/toolchain-mingw64.cmake`
- Definiuje kompilator x86_64-w64-mingw32-gcc/g++
- Ustawia CMAKE_SYSTEM_NAME na Windows
- Konfiguruje ścieżki wyszukiwania bibliotek

### 9. Libsodium dla Windows

**Problem:** Potrzebna statyczna biblioteka libsodium skompilowana dla Windows.

**Rozwiązanie:** Cross-kompilacja libsodium:
```bash
cd deps/libsodium-stable
./configure --host=x86_64-w64-mingw32 \
            --prefix=$(pwd)/../libsodium-win64 \
            --enable-static \
            --disable-shared \
            --disable-pie
make && make install
```

**Lokalizacja:** `deps/libsodium-win64/` (lib/libsodium.a + include/)

### 10. Aktualizacja CMakeLists.txt

**Zmiany:**
- Wykrywanie cross-kompilacji (`CMAKE_SYSTEM_NAME STREQUAL "Windows"`)
- Automatyczne pobieranie nlohmann/json.hpp jeśli brak
- Warunkowe użycie libsodium (pkg-config dla macOS, statyczne dla Windows)
- Flagi linkowania statycznego: `-static -static-libgcc -static-libstdc++`
- Platform-specific clipboard: `clipboard_mac.cpp` vs `clipboard_win.cpp`

### 11. Skrypt budowania

**Plik:** `build.sh`

**Użycie:**
```bash
./build.sh          # Buduje macOS + Windows
./build.sh macos    # Tylko macOS
./build.sh windows  # Tylko Windows .exe
./build.sh test     # Uruchom testy
./build.sh clean    # Usuń katalogi build
```

**Funkcje:**
- Automatycznie sprawdza zależności
- Buduje libsodium dla Windows jeśli brak
- Równoległe budowanie (wszystkie rdzenie CPU)

## Wynikowe pliki

| Platforma | Ścieżka | Rozmiar | Typ |
|-----------|---------|---------|-----|
| macOS | `build/pw` | ~1.7 MB | Mach-O arm64 |
| Windows | `build-win64/pw.exe` | ~16 MB | PE32+ x86-64 |

## Użycie na pendrive

1. Skopiuj pliki na pendrive:
   ```
   /pendrive/
   ├── pw           # macOS
   ├── pw.exe       # Windows
   ├── .pw_vault    # (tworzony przy pierwszym uruchomieniu)
   └── .pw_keyfile  # (opcjonalny)
   ```

2. Na macOS:
   ```bash
   chmod +x /Volumes/PENDRIVE/pw
   /Volumes/PENDRIVE/pw
   ```

3. Na Windows:
   - Podwójne kliknięcie na `pw.exe`
   - Lub z CMD: `E:\pw.exe`

Aplikacja automatycznie wykrywa swój katalog i szuka vault w tym samym miejscu.

## Testowanie Windows .exe

**Do przetestowania na prawdziwym Windows:**
- [ ] Uruchomienie bez dodatkowych DLL
- [ ] Tworzenie i otwieranie vault
- [ ] Kopiowanie do schowka
- [ ] Zgodność formatu .pw_vault między platformami
