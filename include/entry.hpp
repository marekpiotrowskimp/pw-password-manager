#pragma once

#include "crypto.hpp"
#include "secure_string.hpp"
#include <string>
#include <cstdint>
#include <vector>
#include <nlohmann/json.hpp>

namespace pw {

/**
 * Wpis historii hasła
 */
struct PasswordHistoryEntry {
    EncryptedPassword password;
    int64_t changed_at;
    
    nlohmann::json to_json() const {
        return nlohmann::json{
            {"password", {
                {"nonce", base64_encode(password.nonce)},
                {"cipher", base64_encode(password.ciphertext)}
            }},
            {"changed_at", changed_at}
        };
    }
    
    static PasswordHistoryEntry from_json(const nlohmann::json& j) {
        PasswordHistoryEntry entry;
        auto nonce_opt = base64_decode(j.at("password").at("nonce").get<std::string>());
        auto cipher_opt = base64_decode(j.at("password").at("cipher").get<std::string>());
        
        if (nonce_opt && cipher_opt) {
            entry.password.nonce = std::move(*nonce_opt);
            entry.password.ciphertext = std::move(*cipher_opt);
        }
        entry.changed_at = j.at("changed_at").get<int64_t>();
        return entry;
    }
};

/**
 * Reprezentuje pojedynczy wpis w vault
 */
struct Entry {
    std::string id;
    std::string name;
    std::string username;
    EncryptedPassword password;  // Zaszyfrowane hasło (warstwa 2)
    std::string url;
    std::string notes;
    int64_t created_at;
    int64_t updated_at;
    std::vector<PasswordHistoryEntry> password_history;  // Historia poprzednich haseł
    
    // Serializacja do JSON
    nlohmann::json to_json() const {
        nlohmann::json history_array = nlohmann::json::array();
        for (const auto& h : password_history) {
            history_array.push_back(h.to_json());
        }
        
        return nlohmann::json{
            {"id", id},
            {"name", name},
            {"username", username},
            {"password", {
                {"nonce", base64_encode(password.nonce)},
                {"cipher", base64_encode(password.ciphertext)}
            }},
            {"url", url},
            {"notes", notes},
            {"created", created_at},
            {"updated", updated_at},
            {"password_history", history_array}
        };
    }
    
    // Deserializacja z JSON
    static Entry from_json(const nlohmann::json& j) {
        Entry entry;
        entry.id = j.at("id").get<std::string>();
        entry.name = j.at("name").get<std::string>();
        entry.username = j.at("username").get<std::string>();
        
        auto nonce_opt = base64_decode(j.at("password").at("nonce").get<std::string>());
        auto cipher_opt = base64_decode(j.at("password").at("cipher").get<std::string>());
        
        if (nonce_opt && cipher_opt) {
            entry.password.nonce = std::move(*nonce_opt);
            entry.password.ciphertext = std::move(*cipher_opt);
        }
        
        entry.url = j.value("url", "");
        entry.notes = j.value("notes", "");
        entry.created_at = j.at("created").get<int64_t>();
        entry.updated_at = j.at("updated").get<int64_t>();
        
        // Wczytaj historię haseł (opcjonalne - dla kompatybilności wstecznej)
        if (j.contains("password_history") && j["password_history"].is_array()) {
            for (const auto& h : j["password_history"]) {
                entry.password_history.push_back(PasswordHistoryEntry::from_json(h));
            }
        }
        
        return entry;
    }
};

/**
 * Generuje UUID v4
 */
std::string generate_uuid();

/**
 * Pobiera aktualny timestamp (Unix epoch seconds)
 */
int64_t current_timestamp();

} // namespace pw
