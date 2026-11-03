#include <gtest/gtest.h>
#include "crypto.hpp"

class CryptoTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(pw::crypto_init());
    }
};

TEST_F(CryptoTest, GenerateSalt) {
    auto salt1 = pw::generate_salt();
    auto salt2 = pw::generate_salt();
    
    EXPECT_EQ(salt1.size(), pw::SALT_SIZE);
    EXPECT_EQ(salt2.size(), pw::SALT_SIZE);
    
    // Salt powinien być losowy
    EXPECT_NE(salt1, salt2);
}

TEST_F(CryptoTest, GenerateNonceXChaCha) {
    auto nonce1 = pw::generate_nonce_xchacha();
    auto nonce2 = pw::generate_nonce_xchacha();
    
    EXPECT_EQ(nonce1.size(), pw::NONCE_SIZE_XCHACHA);
    EXPECT_EQ(nonce2.size(), pw::NONCE_SIZE_XCHACHA);
    
    EXPECT_NE(nonce1, nonce2);
}

TEST_F(CryptoTest, GenerateNonceAes) {
    auto nonce1 = pw::generate_nonce_aes();
    auto nonce2 = pw::generate_nonce_aes();
    
    EXPECT_EQ(nonce1.size(), pw::NONCE_SIZE_AES);
    EXPECT_EQ(nonce2.size(), pw::NONCE_SIZE_AES);
    
    EXPECT_NE(nonce1, nonce2);
}

TEST_F(CryptoTest, DeriveKeys) {
    pw::SecureString password("test_password_123");
    auto salt = pw::generate_salt();
    
    auto keys = pw::derive_keys(password, std::nullopt, salt);
    
    EXPECT_EQ(keys.file_key.size(), pw::KEY_SIZE);
    EXPECT_EQ(keys.password_key.size(), pw::KEY_SIZE);
}

TEST_F(CryptoTest, DeriveKeysWithKeyfile) {
    pw::SecureString password("test_password_123");
    auto salt = pw::generate_salt();
    std::vector<unsigned char> keyfile(256, 0x42);
    
    auto keys_without = pw::derive_keys(password, std::nullopt, salt);
    auto keys_with = pw::derive_keys(password, keyfile, salt);
    
    // Klucze powinny być różne gdy używamy keyfile
    bool different = false;
    for (size_t i = 0; i < keys_without.file_key.size(); ++i) {
        if (keys_without.file_key[i] != keys_with.file_key[i]) {
            different = true;
            break;
        }
    }
    EXPECT_TRUE(different);
}

TEST_F(CryptoTest, DeriveKeysDeterministic) {
    pw::SecureString password("test_password_123");
    auto salt = pw::generate_salt();
    
    auto keys1 = pw::derive_keys(password, std::nullopt, salt);
    auto keys2 = pw::derive_keys(password, std::nullopt, salt);
    
    // Te same parametry powinny dać ten sam klucz
    bool same = true;
    for (size_t i = 0; i < keys1.file_key.size(); ++i) {
        if (keys1.file_key[i] != keys2.file_key[i]) {
            same = false;
            break;
        }
    }
    EXPECT_TRUE(same);
}

TEST_F(CryptoTest, EncryptDecryptFile) {
    pw::SecureString password("test_password");
    auto salt = pw::generate_salt();
    auto nonce = pw::generate_nonce_xchacha();
    auto keys = pw::derive_keys(password, std::nullopt, salt);
    
    std::string plaintext_str = "Hello, World! This is a test message.";
    std::vector<unsigned char> plaintext(plaintext_str.begin(), plaintext_str.end());
    
    auto ciphertext = pw::encrypt_file(plaintext, keys.file_key, nonce);
    
    // Ciphertext powinien być dłuższy (auth tag)
    EXPECT_GT(ciphertext.size(), plaintext.size());
    
    auto decrypted = pw::decrypt_file(ciphertext, keys.file_key, nonce);
    
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, plaintext);
}

TEST_F(CryptoTest, DecryptFileWrongKey) {
    pw::SecureString password1("test_password_1");
    pw::SecureString password2("test_password_2");
    auto salt = pw::generate_salt();
    auto nonce = pw::generate_nonce_xchacha();
    
    auto keys1 = pw::derive_keys(password1, std::nullopt, salt);
    auto keys2 = pw::derive_keys(password2, std::nullopt, salt);
    
    std::string plaintext_str = "Secret data";
    std::vector<unsigned char> plaintext(plaintext_str.begin(), plaintext_str.end());
    
    auto ciphertext = pw::encrypt_file(plaintext, keys1.file_key, nonce);
    
    // Próba deszyfrowania złym kluczem powinna zwrócić nullopt
    auto decrypted = pw::decrypt_file(ciphertext, keys2.file_key, nonce);
    
    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(CryptoTest, EncryptDecryptPassword) {
    pw::SecureString password("master_password");
    auto salt = pw::generate_salt();
    auto keys = pw::derive_keys(password, std::nullopt, salt);
    
    pw::SecureString secret("my_secret_password_123!");
    
    auto encrypted = pw::encrypt_password(secret, keys.password_key);
    
    EXPECT_FALSE(encrypted.nonce.empty());
    EXPECT_FALSE(encrypted.ciphertext.empty());
    
    auto decrypted = pw::decrypt_password(encrypted, keys.password_key);
    
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(decrypted->to_string(), secret.to_string());
}

TEST_F(CryptoTest, Base64EncodeDecode) {
    std::vector<unsigned char> data = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD};
    
    auto encoded = pw::base64_encode(data);
    EXPECT_FALSE(encoded.empty());
    
    auto decoded = pw::base64_decode(encoded);
    
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, data);
}

TEST_F(CryptoTest, Base64InvalidInput) {
    auto decoded = pw::base64_decode("invalid!!!base64");
    // Może zwrócić wartość lub nullopt w zależności od implementacji
    // Sprawdzamy tylko czy nie crashuje
}
