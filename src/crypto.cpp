#include "crypto.hpp"
#include <sodium.h>
#include <stdexcept>
#include <cstring>

namespace pw {

bool crypto_init() {
    return sodium_init() >= 0;
}

std::vector<unsigned char> generate_salt() {
    std::vector<unsigned char> salt(SALT_SIZE);
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

std::vector<unsigned char> generate_nonce_xchacha() {
    std::vector<unsigned char> nonce(NONCE_SIZE_XCHACHA);
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}

std::vector<unsigned char> generate_nonce_aes() {
    std::vector<unsigned char> nonce(NONCE_SIZE_AES);
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}

std::vector<unsigned char> generate_nonce_chacha() {
    std::vector<unsigned char> nonce(NONCE_SIZE_CHACHA_IETF);
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}

std::vector<unsigned char> generate_random_bytes(size_t size) {
    std::vector<unsigned char> bytes(size);
    randombytes_buf(bytes.data(), bytes.size());
    return bytes;
}

DerivedKeys derive_keys(
    const SecureString& password,
    const std::optional<std::vector<unsigned char>>& keyfile_content,
    const std::vector<unsigned char>& salt
) {
    // Przygotuj input: password + keyfile_content
    std::vector<unsigned char> input(password.begin(), password.end());
    if (keyfile_content) {
        input.insert(input.end(), keyfile_content->begin(), keyfile_content->end());
    }
    
    // Derywuj 512 bitów (64 bajty)
    SecureBytes derived(DERIVED_KEY_SIZE);
    
    if (crypto_pwhash(
            derived.data(),
            derived.size(),
            reinterpret_cast<const char*>(input.data()),
            input.size(),
            salt.data(),
            ARGON2_ITERATIONS,
            ARGON2_MEMORY * 1024,  // w bajtach
            crypto_pwhash_ALG_ARGON2ID13
        ) != 0) {
        // Wyczyść input
        sodium_memzero(input.data(), input.size());
        throw std::runtime_error("Key derivation failed (out of memory?)");
    }
    
    // Wyczyść input
    sodium_memzero(input.data(), input.size());
    
    // Podziel na dwa klucze
    DerivedKeys keys;
    keys.file_key.resize(KEY_SIZE);
    keys.password_key.resize(KEY_SIZE);
    
    std::memcpy(keys.file_key.data(), derived.data(), KEY_SIZE);
    std::memcpy(keys.password_key.data(), derived.data() + KEY_SIZE, KEY_SIZE);
    
    return keys;
}

std::vector<unsigned char> encrypt_file(
    const std::vector<unsigned char>& plaintext,
    const SecureBytes& key,
    const std::vector<unsigned char>& nonce
) {
    std::vector<unsigned char> ciphertext(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len;
    
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(),
            &ciphertext_len,
            plaintext.data(),
            plaintext.size(),
            nullptr, 0,  // no additional data
            nullptr,     // nsec (unused)
            nonce.data(),
            key.data()
        ) != 0) {
        throw std::runtime_error("File encryption failed");
    }
    
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::optional<std::vector<unsigned char>> decrypt_file(
    const std::vector<unsigned char>& ciphertext,
    const SecureBytes& key,
    const std::vector<unsigned char>& nonce
) {
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return std::nullopt;
    }
    
    std::vector<unsigned char> plaintext(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long plaintext_len;
    
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(),
            &plaintext_len,
            nullptr,     // nsec (unused)
            ciphertext.data(),
            ciphertext.size(),
            nullptr, 0,  // no additional data
            nonce.data(),
            key.data()
        ) != 0) {
        return std::nullopt;  // Decryption failed (wrong key or corrupted)
    }
    
    plaintext.resize(plaintext_len);
    return plaintext;
}

EncryptedPassword encrypt_password(
    const SecureString& password,
    const SecureBytes& key
) {
    EncryptedPassword result;
    
    // Zawsze używaj ChaCha20-Poly1305 (działa na wszystkich platformach)
    auto raw_nonce = generate_nonce_chacha();
    
    // Nowy format nonce: [ALGO_CHACHA20] + [12 bajtów random] = 13 bajtów
    result.nonce.resize(1 + raw_nonce.size());
    result.nonce[0] = ALGO_CHACHA20;
    std::memcpy(result.nonce.data() + 1, raw_nonce.data(), raw_nonce.size());
    
    result.ciphertext.resize(password.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len;
    
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            result.ciphertext.data(),
            &ciphertext_len,
            reinterpret_cast<const unsigned char*>(password.data()),
            password.size(),
            nullptr, 0,  // no additional data
            nullptr,     // nsec (unused)
            raw_nonce.data(),
            key.data()
        ) != 0) {
        throw std::runtime_error("Password encryption failed");
    }
    
    result.ciphertext.resize(ciphertext_len);
    return result;
}

std::optional<SecureString> decrypt_password(
    const EncryptedPassword& encrypted,
    const SecureBytes& key
) {
    // Stary format: nonce.size() == 12 (AES-GCM, bez prefiksu)
    // Nowy format: nonce.size() == 13 (pierwszy bajt = algorytm)
    
    if (encrypted.nonce.size() == NONCE_SIZE_AES) {
        // Stary format - AES-GCM (kompatybilność wsteczna)
        if (crypto_aead_aes256gcm_is_available() == 0) {
            // AES-GCM niedostępne na tej platformie
            return std::nullopt;
        }
        
        if (encrypted.ciphertext.size() < crypto_aead_aes256gcm_ABYTES) {
            return std::nullopt;
        }
        
        SecureString plaintext;
        plaintext.resize(encrypted.ciphertext.size() - crypto_aead_aes256gcm_ABYTES);
        unsigned long long plaintext_len;
        
        if (crypto_aead_aes256gcm_decrypt(
                reinterpret_cast<unsigned char*>(plaintext.data()),
                &plaintext_len,
                nullptr,
                encrypted.ciphertext.data(),
                encrypted.ciphertext.size(),
                nullptr, 0,
                encrypted.nonce.data(),
                key.data()
            ) != 0) {
            return std::nullopt;
        }
        
        plaintext.resize(plaintext_len);
        return plaintext;
        
    } else if (encrypted.nonce.size() == NONCE_SIZE_CHACHA_IETF + 1) {
        // Nowy format - sprawdź algorytm
        unsigned char algo = encrypted.nonce[0];
        const unsigned char* raw_nonce = encrypted.nonce.data() + 1;
        
        if (algo == ALGO_CHACHA20) {
            // ChaCha20-Poly1305
            if (encrypted.ciphertext.size() < crypto_aead_chacha20poly1305_ietf_ABYTES) {
                return std::nullopt;
            }
            
            SecureString plaintext;
            plaintext.resize(encrypted.ciphertext.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
            unsigned long long plaintext_len;
            
            if (crypto_aead_chacha20poly1305_ietf_decrypt(
                    reinterpret_cast<unsigned char*>(plaintext.data()),
                    &plaintext_len,
                    nullptr,
                    encrypted.ciphertext.data(),
                    encrypted.ciphertext.size(),
                    nullptr, 0,
                    raw_nonce,
                    key.data()
                ) != 0) {
                return std::nullopt;
            }
            
            plaintext.resize(plaintext_len);
            return plaintext;
            
        } else if (algo == ALGO_AES_GCM) {
            // AES-GCM (nowy format)
            if (crypto_aead_aes256gcm_is_available() == 0) {
                return std::nullopt;
            }
            
            if (encrypted.ciphertext.size() < crypto_aead_aes256gcm_ABYTES) {
                return std::nullopt;
            }
            
            SecureString plaintext;
            plaintext.resize(encrypted.ciphertext.size() - crypto_aead_aes256gcm_ABYTES);
            unsigned long long plaintext_len;
            
            if (crypto_aead_aes256gcm_decrypt(
                    reinterpret_cast<unsigned char*>(plaintext.data()),
                    &plaintext_len,
                    nullptr,
                    encrypted.ciphertext.data(),
                    encrypted.ciphertext.size(),
                    nullptr, 0,
                    raw_nonce,
                    key.data()
                ) != 0) {
                return std::nullopt;
            }
            
            plaintext.resize(plaintext_len);
            return plaintext;
        }
    }
    
    // Nieznany format
    return std::nullopt;
}

std::string base64_encode(const std::vector<unsigned char>& data) {
    return base64_encode(data.data(), data.size());
}

std::string base64_encode(const unsigned char* data, size_t len) {
    size_t encoded_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string encoded(encoded_len, '\0');
    
    sodium_bin2base64(
        &encoded[0],
        encoded_len,
        data,
        len,
        sodium_base64_VARIANT_ORIGINAL
    );
    
    // Usuń trailing null
    while (!encoded.empty() && encoded.back() == '\0') {
        encoded.pop_back();
    }
    
    return encoded;
}

std::optional<std::vector<unsigned char>> base64_decode(const std::string& encoded) {
    std::vector<unsigned char> decoded(encoded.size());
    size_t decoded_len;
    
    if (sodium_base642bin(
            decoded.data(),
            decoded.size(),
            encoded.c_str(),
            encoded.size(),
            nullptr,
            &decoded_len,
            nullptr,
            sodium_base64_VARIANT_ORIGINAL
        ) != 0) {
        return std::nullopt;
    }
    
    decoded.resize(decoded_len);
    return decoded;
}

} // namespace pw
