#pragma once

#include "secure_string.hpp"
#include <string>
#include <vector>
#include <optional>

namespace pw {

// Stałe kryptograficzne
constexpr size_t SALT_SIZE = 32;
constexpr size_t NONCE_SIZE_XCHACHA = 24;
constexpr size_t NONCE_SIZE_AES = 12;
constexpr size_t NONCE_SIZE_CHACHA_IETF = 12;  // ChaCha20-Poly1305-IETF
constexpr size_t KEY_SIZE = 32;

// Identyfikatory algorytmu w nonce (nowy format - pierwszy bajt)
constexpr unsigned char ALGO_AES_GCM = 0x01;
constexpr unsigned char ALGO_CHACHA20 = 0x02;
constexpr size_t TAG_SIZE = 16;
constexpr size_t DERIVED_KEY_SIZE = 64;  // 2x 32-byte keys

// Parametry Argon2id
constexpr uint64_t ARGON2_MEMORY = 64 * 1024;  // 64 MB
constexpr uint32_t ARGON2_ITERATIONS = 3;
constexpr uint32_t ARGON2_PARALLELISM = 1;

/**
 * Struktura przechowująca zaszyfrowane hasło (warstwa 2)
 */
struct EncryptedPassword {
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> ciphertext;
};

/**
 * Klasa zarządzająca kluczami derivowanymi z master password
 */
class DerivedKeys {
public:
    DerivedKeys() = default;
    ~DerivedKeys() = default;
    
    // Move only
    DerivedKeys(DerivedKeys&&) = default;
    DerivedKeys& operator=(DerivedKeys&&) = default;
    DerivedKeys(const DerivedKeys&) = delete;
    DerivedKeys& operator=(const DerivedKeys&) = delete;
    
    SecureBytes file_key;     // Klucz do szyfrowania pliku (XChaCha20)
    SecureBytes password_key; // Klucz do szyfrowania haseł (AES-GCM)
};

/**
 * Inicjalizacja libsodium
 * @return true jeśli sukces
 */
bool crypto_init();

/**
 * Generuje losowy salt
 * @return wektor z losowymi bajtami
 */
std::vector<unsigned char> generate_salt();

/**
 * Generuje losowy nonce dla XChaCha20
 * @return wektor z losowymi bajtami
 */
std::vector<unsigned char> generate_nonce_xchacha();

/**
 * Generuje losowy nonce dla AES-GCM
 * @return wektor z losowymi bajtami
 */
std::vector<unsigned char> generate_nonce_aes();

/**
 * Generuje losowe bajty (np. dla keyfile)
 * @param size liczba bajtów
 * @return wektor z losowymi bajtami
 */
std::vector<unsigned char> generate_random_bytes(size_t size);

/**
 * Derywacja kluczy z master password
 * @param password hasło użytkownika
 * @param keyfile_content opcjonalna zawartość keyfile
 * @param salt salt do Argon2id
 * @return para kluczy (file_key, password_key)
 */
DerivedKeys derive_keys(
    const SecureString& password,
    const std::optional<std::vector<unsigned char>>& keyfile_content,
    const std::vector<unsigned char>& salt
);

/**
 * Szyfrowanie całego pliku vault (XChaCha20-Poly1305)
 * @param plaintext dane do zaszyfrowania
 * @param key klucz 256-bit
 * @param nonce nonce 24 bajty
 * @return zaszyfrowane dane z auth tag
 */
std::vector<unsigned char> encrypt_file(
    const std::vector<unsigned char>& plaintext,
    const SecureBytes& key,
    const std::vector<unsigned char>& nonce
);

/**
 * Deszyfrowanie całego pliku vault
 * @param ciphertext zaszyfrowane dane z auth tag
 * @param key klucz 256-bit
 * @param nonce nonce 24 bajty
 * @return odszyfrowane dane lub nullopt przy błędzie
 */
std::optional<std::vector<unsigned char>> decrypt_file(
    const std::vector<unsigned char>& ciphertext,
    const SecureBytes& key,
    const std::vector<unsigned char>& nonce
);

/**
 * Szyfrowanie pojedynczego hasła (AES-256-GCM)
 * @param password hasło do zaszyfrowania
 * @param key klucz 256-bit
 * @return struktura z nonce i ciphertext
 */
EncryptedPassword encrypt_password(
    const SecureString& password,
    const SecureBytes& key
);

/**
 * Deszyfrowanie pojedynczego hasła
 * @param encrypted zaszyfrowane hasło
 * @param key klucz 256-bit
 * @return odszyfrowane hasło lub nullopt przy błędzie
 */
std::optional<SecureString> decrypt_password(
    const EncryptedPassword& encrypted,
    const SecureBytes& key
);

/**
 * Kodowanie Base64
 */
std::string base64_encode(const std::vector<unsigned char>& data);
std::string base64_encode(const unsigned char* data, size_t len);

/**
 * Dekodowanie Base64
 */
std::optional<std::vector<unsigned char>> base64_decode(const std::string& encoded);

} // namespace pw
