#include "vault.hpp"
#include <nlohmann/json.hpp>
#include <sodium.h>
#include <fstream>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#else
#include <mach-o/dyld.h>
#include <limits.h>
#include <unistd.h>
#endif

namespace pw {

// ============================================================================
// Platform-specific executable directory detection
// ============================================================================

std::string get_executable_directory() {
#ifdef _WIN32
    char path[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return ".";  // Fallback to current directory
    }
    std::string exe_path(path);
    size_t last_sep = exe_path.find_last_of("\\/");
    if (last_sep != std::string::npos) {
        return exe_path.substr(0, last_sep);
    }
    return ".";
#elif defined(__APPLE__)
    char path[PATH_MAX];
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) == 0) {
        // Resolve symlinks and get absolute path
        char resolved[PATH_MAX];
        if (realpath(path, resolved)) {
            std::string exe_path(resolved);
            size_t last_sep = exe_path.find_last_of('/');
            if (last_sep != std::string::npos) {
                return exe_path.substr(0, last_sep);
            }
        }
    }
    return ".";  // Fallback to current directory
#else
    // Linux
    char path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len != -1) {
        path[len] = '\0';
        std::string exe_path(path);
        size_t last_sep = exe_path.find_last_of('/');
        if (last_sep != std::string::npos) {
            return exe_path.substr(0, last_sep);
        }
    }
    return ".";  // Fallback to current directory
#endif
}

std::string path_join(const std::string& dir, const std::string& filename) {
    if (dir.empty()) {
        return filename;
    }
#ifdef _WIN32
    char sep = '\\';
    if (dir.back() == '/' || dir.back() == '\\') {
        return dir + filename;
    }
#else
    char sep = '/';
    if (dir.back() == '/') {
        return dir + filename;
    }
#endif
    return dir + sep + filename;
}

// ============================================================================
// Vault implementation
// ============================================================================

Vault::Vault() {
    // Ustaw domyślny katalog na katalog executable
    vault_dir_ = get_executable_directory();
    vault_path_ = path_join(vault_dir_, DEFAULT_VAULT_FILENAME);
}

void Vault::set_directory(const std::string& dir) {
    vault_dir_ = dir;
    // Aktualizuj ścieżkę vault
    vault_path_ = path_join(vault_dir_, DEFAULT_VAULT_FILENAME);
}

bool Vault::exists() const {
    std::ifstream file(vault_path_, std::ios::binary);
    return file.good();
}

bool Vault::create(const SecureString& master_password, const std::string& keyfile_path_param) {
    if (exists()) {
        last_error_ = "Vault already exists";
        return false;
    }
    
    // Generuj keyfile jeśli podano ścieżkę
    if (!keyfile_path_param.empty()) {
        if (!generate_keyfile(keyfile_path_param)) {
            return false;
        }
        keyfile_path_ = keyfile_path_param;
    }
    
    // Generuj salt i nonce
    salt_ = generate_salt();
    nonce_ = generate_nonce_xchacha();
    
    // Wczytaj keyfile jeśli istnieje
    auto keyfile_content = load_keyfile();
    
    // Derywuj klucze
    keys_ = derive_keys(master_password, keyfile_content, salt_);
    
    // Puste wpisy
    entries_.clear();
    is_open_ = true;
    
    // Zapisz vault
    if (!save()) {
        return false;
    }
    
    return true;
}

bool Vault::open(const SecureString& master_password) {
    if (!exists()) {
        last_error_ = "Vault does not exist";
        return false;
    }
    
    // Wczytaj nagłówek
    if (!read_header()) {
        return false;
    }
    
    // Wczytaj keyfile jeśli wymagany
    auto keyfile_content = load_keyfile();
    if (!keyfile_path_.empty() && !keyfile_content) {
        last_error_ = "Keyfile not found: " + keyfile_path_;
        return false;
    }
    
    // Derywuj klucze
    keys_ = derive_keys(master_password, keyfile_content, salt_);
    
    // Wczytaj zaszyfrowane dane
    std::ifstream file(vault_path_, std::ios::binary);
    if (!file) {
        last_error_ = "Cannot open vault file";
        return false;
    }
    
    // Pomiń nagłówek
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    
    // Oblicz offset danych - RÓŻNE DLA v1 i v2
    size_t header_size = VAULT_MAGIC_SIZE + sizeof(uint32_t);  // magic + version
    
    if (vault_version_ >= 2) {
        header_size += sizeof(uint8_t);  // flags (tylko v2+)
        if (vault_flags_ & VAULT_FLAG_DURESS_ENABLED) {
            header_size += DURESS_HASH_SIZE;  // duress hash
        }
    }
    
    header_size += sizeof(uint16_t);  // keyfile path length
    if (!keyfile_path_.empty()) {
        header_size += keyfile_path_.size();
    }
    header_size += SALT_SIZE + NONCE_SIZE_XCHACHA;
    
    if (file_size <= header_size) {
        last_error_ = "Vault file is corrupted";
        return false;
    }
    
    file.seekg(header_size);
    
    // Wczytaj zaszyfrowane dane
    std::vector<unsigned char> ciphertext(file_size - header_size);
    file.read(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
    
    // Deszyfruj
    auto plaintext = decrypt_file(ciphertext, keys_.file_key, nonce_);
    if (!plaintext) {
        last_error_ = "Decryption failed (wrong password or corrupted file)";
        keys_ = DerivedKeys();  // Wyczyść klucze
        return false;
    }
    
    // Deserializuj JSON
    if (!deserialize_entries(*plaintext)) {
        last_error_ = "Failed to parse vault data";
        keys_ = DerivedKeys();
        return false;
    }
    
    is_open_ = true;
    
    // Sprawdź czy potrzebna migracja (stare hasła AES-GCM → ChaCha20)
    bool needs_migration = false;
    for (const auto& entry : entries_) {
        if (entry.password.nonce.size() == NONCE_SIZE_AES) {
            needs_migration = true;
            break;
        }
    }
    
    if (needs_migration) {
        if (migrate_passwords_to_chacha20()) {
            save();  // Zapisz zmigrowany vault
        }
        // Jeśli migracja się nie udała, vault nadal jest otwarty
        // ale hasła pozostają w starym formacie
    }
    
    return true;
}

bool Vault::save() {
    if (!is_open_) {
        last_error_ = "Vault is not open";
        return false;
    }
    
    // Serializuj wpisy
    auto plaintext = serialize_entries();
    
    // Generuj nowy nonce przy każdym zapisie
    nonce_ = generate_nonce_xchacha();
    
    // Zaszyfruj
    auto ciphertext = encrypt_file(plaintext, keys_.file_key, nonce_);
    
    // Zapisz do pliku
    std::ofstream file(vault_path_, std::ios::binary | std::ios::trunc);
    if (!file) {
        last_error_ = "Cannot write to vault file";
        return false;
    }
    
    // Zapisz nagłówek
    if (!write_header(file)) {
        return false;
    }
    
    // Zapisz zaszyfrowane dane
    file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    
    return true;
}

void Vault::close() {
    entries_.clear();
    keys_ = DerivedKeys();
    salt_.clear();
    nonce_.clear();
    is_open_ = false;
}

bool Vault::add_entry(
    const std::string& name,
    const std::string& username,
    const SecureString& password,
    const std::string& url,
    const std::string& notes
) {
    if (!is_open_) {
        last_error_ = "Vault is not open";
        return false;
    }
    
    // Sprawdź czy wpis już istnieje
    for (const auto& entry : entries_) {
        if (entry.name == name) {
            last_error_ = "Entry already exists: " + name;
            return false;
        }
    }
    
    Entry entry;
    entry.id = generate_uuid();
    entry.name = name;
    entry.username = username;
    entry.password = encrypt_password(password, keys_.password_key);
    entry.url = url;
    entry.notes = notes;
    entry.created_at = current_timestamp();
    entry.updated_at = entry.created_at;
    
    entries_.push_back(std::move(entry));
    
    return save();
}

std::optional<Entry> Vault::get_entry(const std::string& name) const {
    for (const auto& entry : entries_) {
        if (entry.name == name) {
            return entry;
        }
    }
    return std::nullopt;
}

std::optional<SecureString> Vault::get_password(const std::string& name) const {
    if (!is_open_) {
        return std::nullopt;
    }
    
    auto entry = get_entry(name);
    if (!entry) {
        return std::nullopt;
    }
    
    return decrypt_password(entry->password, keys_.password_key);
}

bool Vault::remove_entry(const std::string& name) {
    if (!is_open_) {
        last_error_ = "Vault is not open";
        return false;
    }
    
    auto it = std::find_if(entries_.begin(), entries_.end(),
        [&name](const Entry& e) { return e.name == name; });
    
    if (it == entries_.end()) {
        last_error_ = "Entry not found: " + name;
        return false;
    }
    
    entries_.erase(it);
    return save();
}

bool Vault::rename_entry(const std::string& old_name, const std::string& new_name) {
    if (!is_open_) {
        last_error_ = "Vault is not open";
        return false;
    }
    
    if (new_name.empty()) {
        last_error_ = "New name cannot be empty";
        return false;
    }
    
    // Znajdź wpis do zmiany nazwy
    auto it = std::find_if(entries_.begin(), entries_.end(),
        [&old_name](const Entry& e) { return e.name == old_name; });
    
    if (it == entries_.end()) {
        last_error_ = "Entry not found: " + old_name;
        return false;
    }
    
    // Sprawdź czy nowa nazwa nie jest już zajęta
    auto existing = std::find_if(entries_.begin(), entries_.end(),
        [&new_name](const Entry& e) { return e.name == new_name; });
    
    if (existing != entries_.end()) {
        last_error_ = "Entry with name '" + new_name + "' already exists";
        return false;
    }
    
    it->name = new_name;
    it->updated_at = current_timestamp();
    
    return save();
}

bool Vault::edit_entry(
    const std::string& name,
    const std::string& new_username,
    const SecureString& new_password,
    const std::optional<std::string>& new_url,
    const std::optional<std::string>& new_notes
) {
    if (!is_open_) {
        last_error_ = "Vault is not open";
        return false;
    }
    
    auto it = std::find_if(entries_.begin(), entries_.end(),
        [&name](const Entry& e) { return e.name == name; });
    
    if (it == entries_.end()) {
        last_error_ = "Entry not found: " + name;
        return false;
    }
    
    // Aktualizuj username jeśli podano
    if (!new_username.empty()) {
        it->username = new_username;
    }
    
    // Aktualizuj hasło jeśli podano (i zapisz stare do historii)
    if (!new_password.empty()) {
        // Zapisz aktualne hasło do historii
        PasswordHistoryEntry history_entry;
        history_entry.password = it->password;
        history_entry.changed_at = it->updated_at;
        it->password_history.push_back(std::move(history_entry));
        
        // Ogranicz historię do 10 ostatnich haseł
        while (it->password_history.size() > 10) {
            it->password_history.erase(it->password_history.begin());
        }
        
        // Zaszyfruj nowe hasło
        it->password = encrypt_password(new_password, keys_.password_key);
    }
    
    // Aktualizuj URL jeśli podano
    if (new_url.has_value()) {
        it->url = new_url.value();
    }
    
    // Aktualizuj notatki jeśli podano
    if (new_notes.has_value()) {
        it->notes = new_notes.value();
    }
    
    it->updated_at = current_timestamp();
    
    return save();
}

std::vector<std::pair<SecureString, int64_t>> Vault::get_password_history(const std::string& name) const {
    std::vector<std::pair<SecureString, int64_t>> result;
    
    if (!is_open_) {
        return result;
    }
    
    auto entry = get_entry(name);
    if (!entry) {
        return result;
    }
    
    for (const auto& h : entry->password_history) {
        auto pwd = decrypt_password(h.password, keys_.password_key);
        if (pwd) {
            result.emplace_back(std::move(*pwd), h.changed_at);
        }
    }
    
    return result;
}

std::vector<Entry> Vault::search_entries(const std::string& query) const {
    std::vector<Entry> results;
    
    std::string lower_query = query;
    std::transform(lower_query.begin(), lower_query.end(), lower_query.begin(), ::tolower);
    
    for (const auto& entry : entries_) {
        std::string lower_name = entry.name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
        
        std::string lower_username = entry.username;
        std::transform(lower_username.begin(), lower_username.end(), lower_username.begin(), ::tolower);
        
        std::string lower_url = entry.url;
        std::transform(lower_url.begin(), lower_url.end(), lower_url.begin(), ::tolower);
        
        if (lower_name.find(lower_query) != std::string::npos ||
            lower_username.find(lower_query) != std::string::npos ||
            lower_url.find(lower_query) != std::string::npos) {
            results.push_back(entry);
        }
    }
    
    return results;
}

bool Vault::change_password(const SecureString& old_password, const SecureString& new_password) {
    if (!is_open_) {
        last_error_ = "Vault is not open";
        return false;
    }
    
    // Odszyfruj wszystkie hasła i ich historię aktualnym kluczem
    std::vector<SecureString> decrypted_passwords;
    std::vector<std::vector<std::pair<SecureString, int64_t>>> decrypted_histories;
    
    for (const auto& entry : entries_) {
        auto pwd = decrypt_password(entry.password, keys_.password_key);
        if (!pwd) {
            last_error_ = "Failed to decrypt password for: " + entry.name;
            return false;
        }
        decrypted_passwords.push_back(std::move(*pwd));
        
        // Odszyfruj historię haseł
        std::vector<std::pair<SecureString, int64_t>> history;
        for (const auto& h : entry.password_history) {
            auto hist_pwd = decrypt_password(h.password, keys_.password_key);
            if (hist_pwd) {
                history.emplace_back(std::move(*hist_pwd), h.changed_at);
            }
        }
        decrypted_histories.push_back(std::move(history));
    }
    
    // Generuj nowy salt
    salt_ = generate_salt();
    
    // Wczytaj keyfile jeśli istnieje
    auto keyfile_content = load_keyfile();
    
    // Derywuj nowe klucze
    keys_ = derive_keys(new_password, keyfile_content, salt_);
    
    // Zaszyfruj hasła i historię nowym kluczem
    for (size_t i = 0; i < entries_.size(); ++i) {
        entries_[i].password = encrypt_password(decrypted_passwords[i], keys_.password_key);
        
        // Zaszyfruj historię haseł
        entries_[i].password_history.clear();
        for (const auto& [hist_pwd, changed_at] : decrypted_histories[i]) {
            PasswordHistoryEntry hist_entry;
            hist_entry.password = encrypt_password(hist_pwd, keys_.password_key);
            hist_entry.changed_at = changed_at;
            entries_[i].password_history.push_back(std::move(hist_entry));
        }
    }
    
    return save();
}

bool Vault::add_keyfile(const SecureString& password, const std::string& keyfile_path_param) {
    if (!is_open_) {
        last_error_ = "Vault is not open";
        return false;
    }
    
    // Odszyfruj wszystkie hasła i ich historię aktualnym kluczem
    std::vector<SecureString> decrypted_passwords;
    std::vector<std::vector<std::pair<SecureString, int64_t>>> decrypted_histories;
    
    for (const auto& entry : entries_) {
        auto pwd = decrypt_password(entry.password, keys_.password_key);
        if (!pwd) {
            last_error_ = "Failed to decrypt password for: " + entry.name;
            return false;
        }
        decrypted_passwords.push_back(std::move(*pwd));
        
        // Odszyfruj historię haseł
        std::vector<std::pair<SecureString, int64_t>> history;
        for (const auto& h : entry.password_history) {
            auto hist_pwd = decrypt_password(h.password, keys_.password_key);
            if (hist_pwd) {
                history.emplace_back(std::move(*hist_pwd), h.changed_at);
            }
        }
        decrypted_histories.push_back(std::move(history));
    }
    
    // Generuj keyfile
    if (!generate_keyfile(keyfile_path_param)) {
        return false;
    }
    keyfile_path_ = keyfile_path_param;
    
    // Generuj nowy salt
    salt_ = generate_salt();
    
    // Derywuj nowe klucze z keyfile
    auto keyfile_content = load_keyfile();
    keys_ = derive_keys(password, keyfile_content, salt_);
    
    // Zaszyfruj hasła i historię nowym kluczem
    for (size_t i = 0; i < entries_.size(); ++i) {
        entries_[i].password = encrypt_password(decrypted_passwords[i], keys_.password_key);
        
        // Zaszyfruj historię haseł
        entries_[i].password_history.clear();
        for (const auto& [hist_pwd, changed_at] : decrypted_histories[i]) {
            PasswordHistoryEntry hist_entry;
            hist_entry.password = encrypt_password(hist_pwd, keys_.password_key);
            hist_entry.changed_at = changed_at;
            entries_[i].password_history.push_back(std::move(hist_entry));
        }
    }
    
    return save();
}

bool Vault::remove_keyfile(const SecureString& password) {
    if (!is_open_) {
        last_error_ = "Vault is not open";
        return false;
    }
    
    if (keyfile_path_.empty()) {
        last_error_ = "No keyfile configured";
        return false;
    }
    
    // Odszyfruj wszystkie hasła i ich historię aktualnym kluczem
    std::vector<SecureString> decrypted_passwords;
    std::vector<std::vector<std::pair<SecureString, int64_t>>> decrypted_histories;
    
    for (const auto& entry : entries_) {
        auto pwd = decrypt_password(entry.password, keys_.password_key);
        if (!pwd) {
            last_error_ = "Failed to decrypt password for: " + entry.name;
            return false;
        }
        decrypted_passwords.push_back(std::move(*pwd));
        
        // Odszyfruj historię haseł
        std::vector<std::pair<SecureString, int64_t>> history;
        for (const auto& h : entry.password_history) {
            auto hist_pwd = decrypt_password(h.password, keys_.password_key);
            if (hist_pwd) {
                history.emplace_back(std::move(*hist_pwd), h.changed_at);
            }
        }
        decrypted_histories.push_back(std::move(history));
    }
    
    // Usuń keyfile z konfiguracji
    keyfile_path_.clear();
    
    // Generuj nowy salt
    salt_ = generate_salt();
    
    // Derywuj nowe klucze bez keyfile
    keys_ = derive_keys(password, std::nullopt, salt_);
    
    // Zaszyfruj hasła i historię nowym kluczem
    for (size_t i = 0; i < entries_.size(); ++i) {
        entries_[i].password = encrypt_password(decrypted_passwords[i], keys_.password_key);
        
        // Zaszyfruj historię haseł
        entries_[i].password_history.clear();
        for (const auto& [hist_pwd, changed_at] : decrypted_histories[i]) {
            PasswordHistoryEntry hist_entry;
            hist_entry.password = encrypt_password(hist_pwd, keys_.password_key);
            hist_entry.changed_at = changed_at;
            entries_[i].password_history.push_back(std::move(hist_entry));
        }
    }
    
    return save();
}

std::optional<std::vector<unsigned char>> Vault::load_keyfile() const {
    if (keyfile_path_.empty()) {
        return std::nullopt;
    }
    
    // Jeśli ścieżka jest absolutna, użyj jej bezpośrednio
    // W przeciwnym razie, szukaj relatywnie do vault_dir_
    std::string full_path = keyfile_path_;
#ifdef _WIN32
    bool is_absolute = (keyfile_path_.size() >= 2 && keyfile_path_[1] == ':') ||
                       (keyfile_path_.size() >= 1 && (keyfile_path_[0] == '/' || keyfile_path_[0] == '\\'));
#else
    bool is_absolute = !keyfile_path_.empty() && keyfile_path_[0] == '/';
#endif
    if (!is_absolute) {
        full_path = path_join(vault_dir_, keyfile_path_);
    }
    
    std::ifstream file(full_path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> content(size);
    file.read(reinterpret_cast<char*>(content.data()), size);
    
    return content;
}

bool Vault::generate_keyfile(const std::string& path) {
    // Jeśli ścieżka jest relatywna, generuj w vault_dir_
    std::string full_path = path;
#ifdef _WIN32
    bool is_absolute = (path.size() >= 2 && path[1] == ':') ||
                       (path.size() >= 1 && (path[0] == '/' || path[0] == '\\'));
#else
    bool is_absolute = !path.empty() && path[0] == '/';
#endif
    if (!is_absolute) {
        full_path = path_join(vault_dir_, path);
    }
    
    auto random_bytes = generate_random_bytes(256);
    
    std::ofstream file(full_path, std::ios::binary | std::ios::trunc);
    if (!file) {
        last_error_ = "Cannot create keyfile: " + full_path;
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(random_bytes.data()), random_bytes.size());
    return true;
}

bool Vault::migrate_passwords_to_chacha20() {
    bool any_migrated = false;
    
    for (auto& entry : entries_) {
        // Sprawdź czy hasło wymaga migracji (stary format = 12 bajtów nonce)
        if (entry.password.nonce.size() == NONCE_SIZE_AES) {
            auto decrypted = decrypt_password(entry.password, keys_.password_key);
            if (decrypted) {
                entry.password = encrypt_password(*decrypted, keys_.password_key);
                any_migrated = true;
            } else {
                // Nie udało się odszyfrować - przerwij migrację
                last_error_ = "Failed to decrypt password for migration: " + entry.name;
                return false;
            }
        }
        
        // Migruj też historię haseł
        for (auto& hist : entry.password_history) {
            if (hist.password.nonce.size() == NONCE_SIZE_AES) {
                auto hist_decrypted = decrypt_password(hist.password, keys_.password_key);
                if (hist_decrypted) {
                    hist.password = encrypt_password(*hist_decrypted, keys_.password_key);
                    any_migrated = true;
                }
                // Historia - jeśli nie uda się odszyfrować, pomijamy (nie krytyczne)
            }
        }
    }
    
    return true;
}

std::vector<unsigned char> Vault::serialize_entries() const {
    nlohmann::json j;
    j["entries"] = nlohmann::json::array();
    
    for (const auto& entry : entries_) {
        j["entries"].push_back(entry.to_json());
    }
    
    std::string json_str = j.dump();
    return std::vector<unsigned char>(json_str.begin(), json_str.end());
}

bool Vault::deserialize_entries(const std::vector<unsigned char>& data) {
    try {
        std::string json_str(data.begin(), data.end());
        auto j = nlohmann::json::parse(json_str);
        
        entries_.clear();
        for (const auto& entry_json : j["entries"]) {
            entries_.push_back(Entry::from_json(entry_json));
        }
        
        return true;
    } catch (const std::exception& e) {
        last_error_ = std::string("JSON parse error: ") + e.what();
        return false;
    }
}

bool Vault::read_header() {
    std::ifstream file(vault_path_, std::ios::binary);
    if (!file) {
        last_error_ = "Cannot open vault file";
        return false;
    }
    
    // Magic bytes
    char magic[VAULT_MAGIC_SIZE];
    file.read(magic, VAULT_MAGIC_SIZE);
    if (std::memcmp(magic, VAULT_MAGIC, VAULT_MAGIC_SIZE) != 0) {
        last_error_ = "Invalid vault file (wrong magic)";
        return false;
    }
    
    // Version
    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    vault_version_ = version;  // Zapisz wersję do późniejszego użycia
    
    if (version < VAULT_VERSION_MIN || version > VAULT_VERSION) {
        last_error_ = "Unsupported vault version: " + std::to_string(version);
        return false;
    }
    
    // Obsługa różnych wersji
    if (version == 1) {
        // Stary format v1 - brak flags i duress hash
        vault_flags_ = VAULT_FLAG_NONE;
        duress_password_hash_.clear();
    } else {
        // Format v2+ - odczytaj flags
        file.read(reinterpret_cast<char*>(&vault_flags_), sizeof(vault_flags_));
        
        // Jeśli duress enabled, odczytaj hash
        if (vault_flags_ & VAULT_FLAG_DURESS_ENABLED) {
            duress_password_hash_.resize(DURESS_HASH_SIZE);
            file.read(reinterpret_cast<char*>(duress_password_hash_.data()), 
                      duress_password_hash_.size());
        } else {
            duress_password_hash_.clear();
        }
    }
    
    // Keyfile path length
    uint16_t keyfile_path_len;
    file.read(reinterpret_cast<char*>(&keyfile_path_len), sizeof(keyfile_path_len));
    
    // Keyfile path
    if (keyfile_path_len > 0) {
        keyfile_path_.resize(keyfile_path_len);
        file.read(&keyfile_path_[0], keyfile_path_len);
    } else {
        keyfile_path_.clear();
    }
    
    // Salt
    salt_.resize(SALT_SIZE);
    file.read(reinterpret_cast<char*>(salt_.data()), SALT_SIZE);
    
    // Nonce
    nonce_.resize(NONCE_SIZE_XCHACHA);
    file.read(reinterpret_cast<char*>(nonce_.data()), NONCE_SIZE_XCHACHA);
    
    return true;
}

bool Vault::write_header(std::ofstream& file) {
    // Magic bytes
    file.write(VAULT_MAGIC, VAULT_MAGIC_SIZE);
    
    // Version (zawsze zapisujemy jako v2)
    uint32_t version = VAULT_VERSION;
    file.write(reinterpret_cast<const char*>(&version), sizeof(version));
    
    // Flags (nowe w v2)
    file.write(reinterpret_cast<const char*>(&vault_flags_), sizeof(vault_flags_));
    
    // Duress hash (jeśli enabled)
    if (vault_flags_ & VAULT_FLAG_DURESS_ENABLED) {
        file.write(reinterpret_cast<const char*>(duress_password_hash_.data()), 
                   duress_password_hash_.size());
    }
    
    // Keyfile path length
    uint16_t keyfile_path_len = static_cast<uint16_t>(keyfile_path_.size());
    file.write(reinterpret_cast<const char*>(&keyfile_path_len), sizeof(keyfile_path_len));
    
    // Keyfile path
    if (!keyfile_path_.empty()) {
        file.write(keyfile_path_.c_str(), keyfile_path_.size());
    }
    
    // Salt
    file.write(reinterpret_cast<const char*>(salt_.data()), salt_.size());
    
    // Nonce
    file.write(reinterpret_cast<const char*>(nonce_.data()), nonce_.size());
    
    return true;
}

bool Vault::export_json(const std::string& path) const {
    if (!is_open_) {
        return false;
    }
    
    nlohmann::json j;
    j["version"] = "1.0";
    j["exported_at"] = current_timestamp();
    j["entries"] = nlohmann::json::array();
    
    for (const auto& entry : entries_) {
        auto pwd = decrypt_password(entry.password, keys_.password_key);
        if (!pwd) continue;
        
        nlohmann::json entry_json;
        entry_json["name"] = entry.name;
        entry_json["username"] = entry.username;
        entry_json["password"] = pwd->to_string();
        entry_json["url"] = entry.url;
        entry_json["notes"] = entry.notes;
        entry_json["created_at"] = entry.created_at;
        entry_json["updated_at"] = entry.updated_at;
        
        j["entries"].push_back(entry_json);
    }
    
    std::ofstream file(path);
    if (!file) {
        return false;
    }
    
    file << j.dump(2);
    return true;
}

bool Vault::export_csv(const std::string& path) const {
    if (!is_open_) {
        return false;
    }
    
    std::ofstream file(path);
    if (!file) {
        return false;
    }
    
    // CSV header
    file << "name,username,password,url,notes\n";
    
    for (const auto& entry : entries_) {
        auto pwd = decrypt_password(entry.password, keys_.password_key);
        if (!pwd) continue;
        
        // Escape fields for CSV (handle quotes and commas)
        auto escape_csv = [](const std::string& s) -> std::string {
            if (s.find_first_of(",\"\n") == std::string::npos) {
                return s;
            }
            std::string escaped = "\"";
            for (char c : s) {
                if (c == '"') escaped += "\"\"";
                else escaped += c;
            }
            escaped += "\"";
            return escaped;
        };
        
        file << escape_csv(entry.name) << ","
             << escape_csv(entry.username) << ","
             << escape_csv(pwd->to_string()) << ","
             << escape_csv(entry.url) << ","
             << escape_csv(entry.notes) << "\n";
    }
    
    return true;
}

int Vault::import_json(const std::string& path, bool overwrite) {
    if (!is_open_) {
        last_error_ = "Vault is not open";
        return -1;
    }
    
    std::ifstream file(path);
    if (!file) {
        last_error_ = "Cannot open file: " + path;
        return -1;
    }
    
    nlohmann::json j;
    try {
        file >> j;
    } catch (const std::exception& e) {
        last_error_ = std::string("JSON parse error: ") + e.what();
        return -1;
    }
    
    if (!j.contains("entries") || !j["entries"].is_array()) {
        last_error_ = "Invalid JSON format: missing entries array";
        return -1;
    }
    
    int imported = 0;
    for (const auto& entry_json : j["entries"]) {
        std::string name = entry_json.value("name", "");
        if (name.empty()) continue;
        
        // Check if entry exists
        auto existing = get_entry(name);
        if (existing && !overwrite) {
            continue; // Skip existing entries
        }
        
        std::string username = entry_json.value("username", "");
        std::string password = entry_json.value("password", "");
        std::string url = entry_json.value("url", "");
        std::string notes = entry_json.value("notes", "");
        
        if (existing && overwrite) {
            // Remove existing entry first
            auto it = std::find_if(entries_.begin(), entries_.end(),
                [&name](const Entry& e) { return e.name == name; });
            if (it != entries_.end()) {
                entries_.erase(it);
            }
        }
        
        Entry entry;
        entry.id = generate_uuid();
        entry.name = name;
        entry.username = username;
        entry.password = encrypt_password(SecureString(password), keys_.password_key);
        entry.url = url;
        entry.notes = notes;
        entry.created_at = entry_json.value("created_at", current_timestamp());
        entry.updated_at = entry_json.value("updated_at", current_timestamp());
        
        entries_.push_back(std::move(entry));
        imported++;
    }
    
    if (imported > 0) {
        save();
    }
    
    return imported;
}

int Vault::import_csv(const std::string& path, bool overwrite) {
    if (!is_open_) {
        last_error_ = "Vault is not open";
        return -1;
    }
    
    std::ifstream file(path);
    if (!file) {
        last_error_ = "Cannot open file: " + path;
        return -1;
    }
    
    // CSV parser helper
    auto parse_csv_line = [](const std::string& line) -> std::vector<std::string> {
        std::vector<std::string> fields;
        std::string current;
        bool in_quotes = false;
        
        for (size_t i = 0; i < line.size(); i++) {
            char c = line[i];
            if (in_quotes) {
                if (c == '"') {
                    if (i + 1 < line.size() && line[i + 1] == '"') {
                        current += '"';
                        i++;
                    } else {
                        in_quotes = false;
                    }
                } else {
                    current += c;
                }
            } else {
                if (c == '"') {
                    in_quotes = true;
                } else if (c == ',') {
                    fields.push_back(current);
                    current.clear();
                } else {
                    current += c;
                }
            }
        }
        fields.push_back(current);
        return fields;
    };
    
    std::string line;
    // Skip header
    if (!std::getline(file, line)) {
        last_error_ = "Empty CSV file";
        return -1;
    }
    
    int imported = 0;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        
        auto fields = parse_csv_line(line);
        if (fields.size() < 3) continue; // Need at least name, username, password
        
        std::string name = fields[0];
        if (name.empty()) continue;
        
        // Check if entry exists
        auto existing = get_entry(name);
        if (existing && !overwrite) {
            continue;
        }
        
        std::string username = fields.size() > 1 ? fields[1] : "";
        std::string password = fields.size() > 2 ? fields[2] : "";
        std::string url = fields.size() > 3 ? fields[3] : "";
        std::string notes = fields.size() > 4 ? fields[4] : "";
        
        if (existing && overwrite) {
            auto it = std::find_if(entries_.begin(), entries_.end(),
                [&name](const Entry& e) { return e.name == name; });
            if (it != entries_.end()) {
                entries_.erase(it);
            }
        }
        
        Entry entry;
        entry.id = generate_uuid();
        entry.name = name;
        entry.username = username;
        entry.password = encrypt_password(SecureString(password), keys_.password_key);
        entry.url = url;
        entry.notes = notes;
        entry.created_at = current_timestamp();
        entry.updated_at = entry.created_at;
        
        entries_.push_back(std::move(entry));
        imported++;
    }
    
    if (imported > 0) {
        save();
    }
    
    return imported;
}

// ============================================================================
// Duress Password (Hasło Paniki) - implementacja
// ============================================================================

std::vector<unsigned char> Vault::compute_duress_hash(const SecureString& password) const {
    // Hash = BLAKE2b(password || salt || "DURESS_MARKER")
    // Używamy BLAKE2b bo jest szybki - sprawdzamy przed Argon2id
    
    std::vector<unsigned char> hash(DURESS_HASH_SIZE);
    
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, hash.size());
    crypto_generichash_update(&state, 
        reinterpret_cast<const unsigned char*>(password.data()), 
        password.size());
    crypto_generichash_update(&state, salt_.data(), salt_.size());
    // Marker żeby hash różnił się od innych zastosowań
    const char* marker = "DURESS_MARKER_V1";
    crypto_generichash_update(&state, 
        reinterpret_cast<const unsigned char*>(marker), 
        strlen(marker));
    crypto_generichash_final(&state, hash.data(), hash.size());
    
    return hash;
}

bool Vault::has_duress_password() const {
    return (vault_flags_ & VAULT_FLAG_DURESS_ENABLED) != 0;
}

bool Vault::get_duress_delete_app() const {
    return (vault_flags_ & VAULT_FLAG_DURESS_DELETE_APP) != 0;
}

bool Vault::set_duress_password(
    const SecureString& master_password,
    const SecureString& duress_password,
    bool delete_app_on_trigger
) {
    if (!is_open_) {
        last_error_ = "Vault is not open";
        return false;
    }
    
    // Sprawdź minimalną długość hasła paniki
    if (duress_password.size() < 4) {
        last_error_ = "Duress password must be at least 4 characters";
        return false;
    }
    
    // Sprawdź czy hasło paniki nie jest takie samo jak master
    // (porównanie przez hash żeby uniknąć timing attack)
    auto master_hash = compute_duress_hash(master_password);
    auto duress_hash = compute_duress_hash(duress_password);
    
    if (sodium_memcmp(master_hash.data(), duress_hash.data(), master_hash.size()) == 0) {
        last_error_ = "Duress password cannot be the same as master password";
        return false;
    }
    
    // Ustaw flagi
    vault_flags_ |= VAULT_FLAG_DURESS_ENABLED;
    if (delete_app_on_trigger) {
        vault_flags_ |= VAULT_FLAG_DURESS_DELETE_APP;
    } else {
        vault_flags_ &= ~VAULT_FLAG_DURESS_DELETE_APP;
    }
    
    // Zapisz hash hasła paniki
    duress_password_hash_ = duress_hash;
    
    // Zapisz vault z nowymi ustawieniami
    return save();
}

bool Vault::remove_duress_password(const SecureString& master_password) {
    if (!is_open_) {
        last_error_ = "Vault is not open";
        return false;
    }
    
    if (!has_duress_password()) {
        last_error_ = "Duress password is not configured";
        return false;
    }
    
    // Wyczyść flagi i hash
    vault_flags_ &= ~(VAULT_FLAG_DURESS_ENABLED | VAULT_FLAG_DURESS_DELETE_APP);
    duress_password_hash_.clear();
    
    // Zapisz vault
    return save();
}

bool Vault::set_duress_delete_app(const SecureString& master_password, bool value) {
    if (!is_open_) {
        last_error_ = "Vault is not open";
        return false;
    }
    
    if (!has_duress_password()) {
        last_error_ = "Duress password is not configured";
        return false;
    }
    
    if (value) {
        vault_flags_ |= VAULT_FLAG_DURESS_DELETE_APP;
    } else {
        vault_flags_ &= ~VAULT_FLAG_DURESS_DELETE_APP;
    }
    
    return save();
}

bool Vault::check_duress_password(const SecureString& password) {
    // Wczytaj nagłówek żeby mieć salt i duress hash
    if (!read_header()) {
        return false;
    }
    
    // Jeśli duress nie jest włączony, zwróć false
    if (!has_duress_password()) {
        return false;
    }
    
    // Oblicz hash podanego hasła
    auto hash = compute_duress_hash(password);
    
    // Porównaj w czasie stałym (constant-time comparison)
    return sodium_memcmp(hash.data(), duress_password_hash_.data(), 
                         hash.size()) == 0;
}

bool Vault::secure_wipe_file(const std::string& path) {
    // Otwórz plik do odczytu/zapisu
    std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
    if (!file) {
        return false;
    }
    
    // Pobierz rozmiar pliku
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    
    if (file_size == 0) {
        file.close();
        return std::remove(path.c_str()) == 0;
    }
    
    // 3 przebiegi nadpisywania losowymi danymi
    for (int pass = 0; pass < 3; ++pass) {
        auto random_data = generate_random_bytes(file_size);
        file.seekp(0);
        file.write(reinterpret_cast<char*>(random_data.data()), file_size);
        file.flush();
        
        // Wymuś zapis na dysk
        #ifndef _WIN32
        file.sync();
        #endif
    }
    
    // Nadpisz zerami
    std::vector<unsigned char> zeros(file_size, 0);
    file.seekp(0);
    file.write(reinterpret_cast<char*>(zeros.data()), file_size);
    file.flush();
    
    file.close();
    
    // Usuń plik
    return std::remove(path.c_str()) == 0;
}

void Vault::create_fake_vault() {
    // Tworzymy fałszywy vault który wygląda na uszkodzony
    // Ma poprawny nagłówek ale losowe "zaszyfrowane" dane
    
    std::vector<unsigned char> fake_data;
    
    // Magic bytes (poprawne)
    fake_data.insert(fake_data.end(), VAULT_MAGIC, VAULT_MAGIC + VAULT_MAGIC_SIZE);
    
    // Version 2
    uint32_t version = VAULT_VERSION;
    auto ver_ptr = reinterpret_cast<unsigned char*>(&version);
    fake_data.insert(fake_data.end(), ver_ptr, ver_ptr + sizeof(version));
    
    // Flags = 0 (brak duress w fake vault - żeby nie było widać że funkcja była używana)
    fake_data.push_back(0);
    
    // Keyfile path length = 0
    uint16_t keyfile_len = 0;
    auto kf_ptr = reinterpret_cast<unsigned char*>(&keyfile_len);
    fake_data.insert(fake_data.end(), kf_ptr, kf_ptr + sizeof(keyfile_len));
    
    // Random salt
    auto fake_salt = generate_salt();
    fake_data.insert(fake_data.end(), fake_salt.begin(), fake_salt.end());
    
    // Random nonce
    auto fake_nonce = generate_nonce_xchacha();
    fake_data.insert(fake_data.end(), fake_nonce.begin(), fake_nonce.end());
    
    // Losowe "zaszyfrowane" dane (200-600 bajtów)
    // Wygląda jak prawdziwy vault ale deszyfrowanie zawsze się nie uda
    size_t fake_size = 200 + (randombytes_uniform(400));
    auto fake_encrypted = generate_random_bytes(fake_size);
    fake_data.insert(fake_data.end(), fake_encrypted.begin(), fake_encrypted.end());
    
    // Zapisz fake vault
    std::ofstream file(vault_path_, std::ios::binary | std::ios::trunc);
    if (file) {
        file.write(reinterpret_cast<char*>(fake_data.data()), fake_data.size());
    }
}

void Vault::delete_executable() {
#ifdef _WIN32
    // Windows: nie można usunąć uruchomionego exe
    // Używamy sztuczki z cmd.exe który uruchomi się po zamknięciu procesu
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    
    // Utwórz batch script który usunie exe po krótkim opóźnieniu
    std::string cmd = "cmd.exe /c ping localhost -n 3 > nul & del /f /q \"" + 
                      std::string(exe_path) + "\"";
    
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Ukryj okno cmd
    
    PROCESS_INFORMATION pi = {};
    
    CreateProcessA(
        NULL,
        const_cast<char*>(cmd.c_str()),
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );
    
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
    
#elif defined(__APPLE__)
    // macOS: możemy usunąć uruchomiony plik
    char path[PATH_MAX];
    uint32_t size = sizeof(path);
    
    if (_NSGetExecutablePath(path, &size) == 0) {
        char resolved[PATH_MAX];
        if (realpath(path, resolved)) {
            // Najpierw secure wipe, potem usuń
            secure_wipe_file(resolved);
        }
    }
    
#else
    // Linux: podobnie jak macOS
    char path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len != -1) {
        path[len] = '\0';
        secure_wipe_file(path);
    }
#endif
}

void Vault::trigger_duress_wipe() {
    bool should_delete_app = (vault_flags_ & VAULT_FLAG_DURESS_DELETE_APP) != 0;
    
    // 1. Secure wipe vault file
    secure_wipe_file(vault_path_);
    
    // 2. Secure wipe keyfile (jeśli istnieje)
    if (!keyfile_path_.empty()) {
        // Sprawdź czy ścieżka jest absolutna czy relatywna
        std::string full_keyfile = keyfile_path_;
#ifdef _WIN32
        bool is_absolute = (keyfile_path_.size() >= 2 && keyfile_path_[1] == ':') ||
                           (keyfile_path_.size() >= 1 && (keyfile_path_[0] == '/' || keyfile_path_[0] == '\\'));
#else
        bool is_absolute = !keyfile_path_.empty() && keyfile_path_[0] == '/';
#endif
        if (!is_absolute) {
            full_keyfile = path_join(vault_dir_, keyfile_path_);
        }
        
        secure_wipe_file(full_keyfile);
    }
    
    // 3. Utwórz fake vault (żeby wyglądało na uszkodzony plik)
    create_fake_vault();
    
    // 4. Wyczyść pamięć
    entries_.clear();
    keys_ = DerivedKeys();
    salt_.clear();
    nonce_.clear();
    vault_flags_ = VAULT_FLAG_NONE;
    duress_password_hash_.clear();
    is_open_ = false;
    
    // 5. Opcjonalnie usuń aplikację (na końcu!)
    if (should_delete_app) {
        delete_executable();
    }
}

} // namespace pw
