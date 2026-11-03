#include <gtest/gtest.h>
#include "entry.hpp"
#include "crypto.hpp"

class EntryTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(pw::crypto_init());
    }
};

TEST_F(EntryTest, GenerateUUID) {
    auto uuid1 = pw::generate_uuid();
    auto uuid2 = pw::generate_uuid();
    
    // UUID powinien mieć 36 znaków (8-4-4-4-12 + 4 myślniki)
    EXPECT_EQ(uuid1.size(), 36);
    EXPECT_EQ(uuid2.size(), 36);
    
    // UUID powinny być unikalne
    EXPECT_NE(uuid1, uuid2);
    
    // Sprawdź format (myślniki w odpowiednich miejscach)
    EXPECT_EQ(uuid1[8], '-');
    EXPECT_EQ(uuid1[13], '-');
    EXPECT_EQ(uuid1[18], '-');
    EXPECT_EQ(uuid1[23], '-');
}

TEST_F(EntryTest, CurrentTimestamp) {
    auto ts1 = pw::current_timestamp();
    
    // Timestamp powinien być dodatni i rozsądny (po roku 2020)
    EXPECT_GT(ts1, 1577836800);  // 2020-01-01
    
    // Kolejne wywołanie powinno zwrócić tę samą lub późniejszą wartość
    auto ts2 = pw::current_timestamp();
    EXPECT_GE(ts2, ts1);
}

TEST_F(EntryTest, EntryToJson) {
    pw::Entry entry;
    entry.id = "test-uuid";
    entry.name = "github";
    entry.username = "user@example.com";
    entry.password.nonce = {0x01, 0x02, 0x03};
    entry.password.ciphertext = {0x04, 0x05, 0x06};
    entry.url = "https://github.com";
    entry.notes = "Test notes";
    entry.created_at = 1234567890;
    entry.updated_at = 1234567900;
    
    auto json = entry.to_json();
    
    EXPECT_EQ(json["id"], "test-uuid");
    EXPECT_EQ(json["name"], "github");
    EXPECT_EQ(json["username"], "user@example.com");
    EXPECT_EQ(json["url"], "https://github.com");
    EXPECT_EQ(json["notes"], "Test notes");
    EXPECT_EQ(json["created"], 1234567890);
    EXPECT_EQ(json["updated"], 1234567900);
    
    // Password powinno być w formacie base64
    EXPECT_TRUE(json["password"].contains("nonce"));
    EXPECT_TRUE(json["password"].contains("cipher"));
}

TEST_F(EntryTest, EntryFromJson) {
    nlohmann::json json = {
        {"id", "test-uuid-123"},
        {"name", "gitlab"},
        {"username", "admin@gitlab.com"},
        {"password", {
            {"nonce", pw::base64_encode({0x01, 0x02, 0x03})},
            {"cipher", pw::base64_encode({0x04, 0x05, 0x06})}
        }},
        {"url", "https://gitlab.com"},
        {"notes", "GitLab account"},
        {"created", 1111111111},
        {"updated", 2222222222}
    };
    
    auto entry = pw::Entry::from_json(json);
    
    EXPECT_EQ(entry.id, "test-uuid-123");
    EXPECT_EQ(entry.name, "gitlab");
    EXPECT_EQ(entry.username, "admin@gitlab.com");
    EXPECT_EQ(entry.url, "https://gitlab.com");
    EXPECT_EQ(entry.notes, "GitLab account");
    EXPECT_EQ(entry.created_at, 1111111111);
    EXPECT_EQ(entry.updated_at, 2222222222);
}

TEST_F(EntryTest, EntryRoundTrip) {
    pw::Entry original;
    original.id = pw::generate_uuid();
    original.name = "test_service";
    original.username = "test_user";
    original.password.nonce = pw::generate_nonce_aes();
    original.password.ciphertext = {0x10, 0x20, 0x30, 0x40, 0x50};
    original.url = "https://example.com";
    original.notes = "Test notes with special chars: !@#$%";
    original.created_at = pw::current_timestamp();
    original.updated_at = original.created_at;
    
    auto json = original.to_json();
    auto restored = pw::Entry::from_json(json);
    
    EXPECT_EQ(restored.id, original.id);
    EXPECT_EQ(restored.name, original.name);
    EXPECT_EQ(restored.username, original.username);
    EXPECT_EQ(restored.url, original.url);
    EXPECT_EQ(restored.notes, original.notes);
    EXPECT_EQ(restored.created_at, original.created_at);
    EXPECT_EQ(restored.updated_at, original.updated_at);
    EXPECT_EQ(restored.password.nonce, original.password.nonce);
    EXPECT_EQ(restored.password.ciphertext, original.password.ciphertext);
}
