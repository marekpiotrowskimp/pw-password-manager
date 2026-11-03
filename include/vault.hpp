#pragma once

#include "entry.hpp"
#include "crypto.hpp"
#include <string>
#include <vector>
#include <optional>
#include <fstream>

namespace pw {

// Magic bytes dla identyfikacji pliku
constexpr char VAULT_MAGIC[] = "PWVAULT1";
constexpr size_t VAULT_MAGIC_SIZE = 8;
constexpr uint32_t VAULT_VERSION = 2;  // v2: dodano duress password
constexpr uint32_t VAULT_VERSION_MIN = 1;  // minimalna obsługiwana wersja

// Flagi vault (przechowywane w nagłówku)
enum VaultFlags : uint8_t {
    VAULT_FLAG_NONE              = 0x00,
    VAULT_FLAG_DURESS_ENABLED    = 0x01,  // Hasło paniki włączone
    VAULT_FLAG_DURESS_DELETE_APP = 0x02,  // Usuwać aplikację przy panic
};

// Rozmiar hash dla duress password (BLAKE2b)
constexpr size_t DURESS_HASH_SIZE = 32;

// Domyślna nazwa pliku vault
constexpr char DEFAULT_VAULT_FILENAME[] = ".pw_vault";

/**
 * Pobiera katalog w którym znajduje się executable
 * @return ścieżka do katalogu executable
 */
std::string get_executable_directory();

/**
 * Łączy ścieżki (path + filename)
 * @param dir katalog
 * @param filename nazwa pliku
 * @return połączona ścieżka
 */
std::string path_join(const std::string& dir, const std::string& filename);

/**
 * Klasa zarządzająca plikiem vault
 */
class Vault {
public:
    Vault();
    ~Vault() = default;
    
    // Ścieżka do katalogu vault (domyślnie katalog exe)
    void set_directory(const std::string& dir);
    std::string get_directory() const { return vault_dir_; }
    
    // Ścieżka do pliku vault
    void set_path(const std::string& path) { vault_path_ = path; }
    std::string get_path() const { return vault_path_; }
    
    // Ścieżka do keyfile (opcjonalnie)
    void set_keyfile_path(const std::string& path) { keyfile_path_ = path; }
    std::string get_keyfile_path() const { return keyfile_path_; }
    bool has_keyfile() const { return !keyfile_path_.empty(); }
    
    /**
     * Sprawdza czy vault istnieje
     */
    bool exists() const;
    
    /**
     * Tworzy nowy vault
     * @param master_password hasło główne
     * @param keyfile_path opcjonalna ścieżka do keyfile (zostanie wygenerowany)
     * @return true jeśli sukces
     */
    bool create(const SecureString& master_password, const std::string& keyfile_path = "");
    
    /**
     * Otwiera vault (deszyfruje)
     * @param master_password hasło główne
     * @return true jeśli sukces
     */
    bool open(const SecureString& master_password);
    
    /**
     * Zapisuje vault (szyfruje i zapisuje do pliku)
     * @return true jeśli sukces
     */
    bool save();
    
    /**
     * Zamyka vault (czyści dane z pamięci)
     */
    void close();
    
    /**
     * Sprawdza czy vault jest otwarty
     */
    bool is_open() const { return is_open_; }
    
    // Operacje na wpisach
    
    /**
     * Dodaje nowy wpis
     * @param name nazwa wpisu
     * @param username nazwa użytkownika
     * @param password hasło
     * @param url URL (opcjonalnie)
     * @param notes notatki (opcjonalnie)
     * @return true jeśli sukces
     */
    bool add_entry(
        const std::string& name,
        const std::string& username,
        const SecureString& password,
        const std::string& url = "",
        const std::string& notes = ""
    );
    
    /**
     * Pobiera wpis po nazwie
     * @param name nazwa wpisu
     * @return wpis lub nullopt
     */
    std::optional<Entry> get_entry(const std::string& name) const;
    
    /**
     * Pobiera odszyfrowane hasło dla wpisu
     * @param name nazwa wpisu
     * @return odszyfrowane hasło lub nullopt
     */
    std::optional<SecureString> get_password(const std::string& name) const;
    
    /**
     * Usuwa wpis
     * @param name nazwa wpisu
     * @return true jeśli usunięto
     */
    bool remove_entry(const std::string& name);
    
    /**
     * Zmienia nazwę wpisu
     * @param old_name aktualna nazwa wpisu
     * @param new_name nowa nazwa wpisu
     * @return true jeśli sukces
     */
    bool rename_entry(const std::string& old_name, const std::string& new_name);
    
    /**
     * Edytuje istniejący wpis (zapisuje stare hasło do historii)
     * @param name nazwa wpisu do edycji
     * @param new_username nowy username (pusty = bez zmian)
     * @param new_password nowe hasło (puste = bez zmian)
     * @param new_url nowy URL (nullopt = bez zmian)
     * @param new_notes nowe notatki (nullopt = bez zmian)
     * @return true jeśli sukces
     */
    bool edit_entry(
        const std::string& name,
        const std::string& new_username = "",
        const SecureString& new_password = SecureString(),
        const std::optional<std::string>& new_url = std::nullopt,
        const std::optional<std::string>& new_notes = std::nullopt
    );
    
    /**
     * Pobiera historię haseł dla wpisu
     * @param name nazwa wpisu
     * @return lista odszyfrowanych haseł z timestampami
     */
    std::vector<std::pair<SecureString, int64_t>> get_password_history(const std::string& name) const;
    
    /**
     * Zwraca listę wszystkich wpisów
     */
    const std::vector<Entry>& get_entries() const { return entries_; }
    
    /**
     * Wyszukuje wpisy po nazwie
     * @param query zapytanie
     * @return lista pasujących wpisów
     */
    std::vector<Entry> search_entries(const std::string& query) const;
    
    /**
     * Zmienia master password
     * @param old_password stare hasło
     * @param new_password nowe hasło
     * @return true jeśli sukces
     */
    bool change_password(const SecureString& old_password, const SecureString& new_password);
    
    /**
     * Dodaje keyfile do istniejącego vault
     * @param password hasło główne
     * @param keyfile_path ścieżka do nowego keyfile
     * @return true jeśli sukces
     */
    bool add_keyfile(const SecureString& password, const std::string& keyfile_path);
    
    /**
     * Usuwa keyfile z vault
     * @param password hasło główne
     * @return true jeśli sukces
     */
    bool remove_keyfile(const SecureString& password);
    
    /**
     * Pobiera ostatni błąd
     */
    std::string get_last_error() const { return last_error_; }
    
    // ========================================================================
    // Duress Password (Hasło Paniki)
    // ========================================================================
    
    /**
     * Ustawia hasło paniki
     * @param master_password hasło główne (do weryfikacji)
     * @param duress_password hasło paniki
     * @param delete_app_on_trigger czy usuwać aplikację przy użyciu
     * @return true jeśli sukces
     */
    bool set_duress_password(
        const SecureString& master_password,
        const SecureString& duress_password,
        bool delete_app_on_trigger = false
    );
    
    /**
     * Usuwa hasło paniki
     * @param master_password hasło główne (do weryfikacji)
     * @return true jeśli sukces
     */
    bool remove_duress_password(const SecureString& master_password);
    
    /**
     * Sprawdza czy hasło paniki jest skonfigurowane
     */
    bool has_duress_password() const;
    
    /**
     * Sprawdza czy aplikacja ma być usunięta przy użyciu hasła paniki
     */
    bool get_duress_delete_app() const;
    
    /**
     * Ustawia opcję usuwania aplikacji
     * @param master_password hasło główne (do weryfikacji)
     * @param value nowa wartość
     * @return true jeśli sukces
     */
    bool set_duress_delete_app(const SecureString& master_password, bool value);
    
    /**
     * Sprawdza czy podane hasło to hasło paniki
     * UWAGA: Ta funkcja wczytuje nagłówek z pliku
     * @param password hasło do sprawdzenia
     * @return true jeśli to hasło paniki
     */
    bool check_duress_password(const SecureString& password);
    
    /**
     * Uruchamia procedurę paniki - kasuje wszystkie dane
     * - Bezpiecznie nadpisuje plik vault
     * - Usuwa keyfile
     * - Tworzy fałszywy "uszkodzony" vault
     * - Opcjonalnie usuwa aplikację
     */
    void trigger_duress_wipe();
    
    /**
     * Eksportuje wpisy do pliku JSON (odszyfrowane)
     * @param path ścieżka do pliku wyjściowego
     * @return true jeśli sukces
     */
    bool export_json(const std::string& path) const;
    
    /**
     * Eksportuje wpisy do pliku CSV (odszyfrowane)
     * @param path ścieżka do pliku wyjściowego
     * @return true jeśli sukces
     */
    bool export_csv(const std::string& path) const;
    
    /**
     * Importuje wpisy z pliku JSON
     * @param path ścieżka do pliku wejściowego
     * @param overwrite czy nadpisywać istniejące wpisy
     * @return liczba zaimportowanych wpisów (-1 w przypadku błędu)
     */
    int import_json(const std::string& path, bool overwrite = false);
    
    /**
     * Importuje wpisy z pliku CSV
     * @param path ścieżka do pliku wejściowego
     * @param overwrite czy nadpisywać istniejące wpisy
     * @return liczba zaimportowanych wpisów (-1 w przypadku błędu)
     */
    int import_csv(const std::string& path, bool overwrite = false);

private:
    std::string vault_dir_;   // Katalog vault (domyślnie katalog exe)
    std::string vault_path_;  // Pełna ścieżka do pliku vault
    std::string keyfile_path_;
    std::vector<Entry> entries_;
    bool is_open_ = false;
    std::string last_error_;
    
    // Klucze (przechowywane tylko gdy vault jest otwarty)
    DerivedKeys keys_;
    std::vector<unsigned char> salt_;
    std::vector<unsigned char> nonce_;
    
    // Duress password (hasło paniki)
    uint8_t vault_flags_ = VAULT_FLAG_NONE;
    std::vector<unsigned char> duress_password_hash_;
    
    // Wersja odczytanego vault (do poprawnego obliczania header_size)
    uint32_t vault_version_ = VAULT_VERSION;
    
    /**
     * Wczytuje keyfile
     * @return zawartość keyfile lub nullopt
     */
    std::optional<std::vector<unsigned char>> load_keyfile() const;
    
    /**
     * Zapisuje keyfile
     * @param path ścieżka do pliku
     * @return true jeśli sukces
     */
    bool generate_keyfile(const std::string& path);
    
    /**
     * Serializuje wpisy do JSON
     */
    std::vector<unsigned char> serialize_entries() const;
    
    /**
     * Deserializuje wpisy z JSON
     */
    bool deserialize_entries(const std::vector<unsigned char>& data);
    
    /**
     * Migruje hasła ze starego formatu (AES-GCM) do nowego (ChaCha20)
     * Wywoływane automatycznie przy otwarciu vault ze starymi hasłami
     * @return true jeśli migracja się powiodła
     */
    bool migrate_passwords_to_chacha20();
    
    /**
     * Wczytuje nagłówek vault (bez deszyfrowania)
     */
    bool read_header();
    
    /**
     * Zapisuje nagłówek vault
     */
    bool write_header(std::ofstream& file);
    
    // ========================================================================
    // Duress Password - funkcje pomocnicze
    // ========================================================================
    
    /**
     * Oblicza hash hasła paniki (BLAKE2b)
     * @param password hasło do zahashowania
     * @return hash hasła
     */
    std::vector<unsigned char> compute_duress_hash(const SecureString& password) const;
    
    /**
     * Bezpiecznie nadpisuje i usuwa plik
     * @param path ścieżka do pliku
     * @return true jeśli sukces
     */
    bool secure_wipe_file(const std::string& path);
    
    /**
     * Tworzy fałszywy "uszkodzony" vault
     */
    void create_fake_vault();
    
    /**
     * Usuwa plik wykonywalny aplikacji
     */
    void delete_executable();
};

} // namespace pw
