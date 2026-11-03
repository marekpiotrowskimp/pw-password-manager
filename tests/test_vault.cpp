#include <gtest/gtest.h>
#include "vault.hpp"
#include "crypto.hpp"
#include <fstream>
#include <cstdio>

class VaultTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(pw::crypto_init());
        // Usuń vault jeśli istnieje
        std::remove(test_vault_path.c_str());
        std::remove(test_keyfile_path.c_str());
    }
    
    void TearDown() override {
        std::remove(test_vault_path.c_str());
        std::remove(test_keyfile_path.c_str());
    }
    
    std::string test_vault_path = ".pw_vault_test";
    std::string test_keyfile_path = ".pw_keyfile_test";
};

TEST_F(VaultTest, CreateVault) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString password("test_master_password");
    
    EXPECT_FALSE(vault.exists());
    EXPECT_TRUE(vault.create(password));
    EXPECT_TRUE(vault.exists());
    EXPECT_TRUE(vault.is_open());
}

TEST_F(VaultTest, CreateVaultWithKeyfile) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString password("test_master_password");
    
    EXPECT_TRUE(vault.create(password, test_keyfile_path));
    EXPECT_TRUE(vault.exists());
    
    // Sprawdź czy keyfile został utworzony
    std::ifstream keyfile(test_keyfile_path);
    EXPECT_TRUE(keyfile.good());
}

TEST_F(VaultTest, OpenVault) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString password("test_master_password");
    
    ASSERT_TRUE(vault.create(password));
    vault.close();
    
    EXPECT_FALSE(vault.is_open());
    EXPECT_TRUE(vault.open(password));
    EXPECT_TRUE(vault.is_open());
}

TEST_F(VaultTest, OpenVaultWrongPassword) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString correct_password("correct_password");
    pw::SecureString wrong_password("wrong_password");
    
    ASSERT_TRUE(vault.create(correct_password));
    vault.close();
    
    EXPECT_FALSE(vault.open(wrong_password));
    EXPECT_FALSE(vault.is_open());
}

TEST_F(VaultTest, AddEntry) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString master("master_password");
    ASSERT_TRUE(vault.create(master));
    
    pw::SecureString entry_password("secret123");
    EXPECT_TRUE(vault.add_entry("github", "user@example.com", entry_password, "https://github.com", "My GitHub account"));
    
    auto entry = vault.get_entry("github");
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->name, "github");
    EXPECT_EQ(entry->username, "user@example.com");
    EXPECT_EQ(entry->url, "https://github.com");
    EXPECT_EQ(entry->notes, "My GitHub account");
}

TEST_F(VaultTest, GetPassword) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString master("master_password");
    ASSERT_TRUE(vault.create(master));
    
    pw::SecureString entry_password("my_secret_password");
    ASSERT_TRUE(vault.add_entry("test", "user", entry_password));
    
    auto retrieved = vault.get_password("test");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->to_string(), "my_secret_password");
}

TEST_F(VaultTest, RemoveEntry) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString master("master_password");
    ASSERT_TRUE(vault.create(master));
    
    pw::SecureString entry_password("secret");
    ASSERT_TRUE(vault.add_entry("test_entry", "user", entry_password));
    
    EXPECT_TRUE(vault.get_entry("test_entry").has_value());
    EXPECT_TRUE(vault.remove_entry("test_entry"));
    EXPECT_FALSE(vault.get_entry("test_entry").has_value());
}

TEST_F(VaultTest, SearchEntries) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString master("master_password");
    ASSERT_TRUE(vault.create(master));
    
    pw::SecureString pwd("secret");
    vault.add_entry("github", "user@github.com", pwd, "https://github.com");
    vault.add_entry("gitlab", "user@gitlab.com", pwd, "https://gitlab.com");
    vault.add_entry("bitbucket", "user@bitbucket.com", pwd, "https://bitbucket.org");
    
    auto results = vault.search_entries("git");
    EXPECT_EQ(results.size(), 2);  // github i gitlab
    
    results = vault.search_entries("bucket");
    EXPECT_EQ(results.size(), 1);  // tylko bitbucket
}

TEST_F(VaultTest, PersistenceAcrossReopen) {
    pw::SecureString master("master_password");
    pw::SecureString entry_password("entry_secret");
    
    // Utwórz vault i dodaj wpis
    {
        pw::Vault vault;
        vault.set_path(test_vault_path);
        ASSERT_TRUE(vault.create(master));
        ASSERT_TRUE(vault.add_entry("persistent", "user", entry_password));
    }
    
    // Otwórz vault ponownie
    {
        pw::Vault vault;
        vault.set_path(test_vault_path);
        ASSERT_TRUE(vault.open(master));
        
        auto entry = vault.get_entry("persistent");
        ASSERT_TRUE(entry.has_value());
        EXPECT_EQ(entry->name, "persistent");
        
        auto pwd = vault.get_password("persistent");
        ASSERT_TRUE(pwd.has_value());
        EXPECT_EQ(pwd->to_string(), "entry_secret");
    }
}

TEST_F(VaultTest, ChangePassword) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString old_master("old_password");
    pw::SecureString new_master("new_password");
    pw::SecureString entry_password("entry_secret");
    
    ASSERT_TRUE(vault.create(old_master));
    ASSERT_TRUE(vault.add_entry("test", "user", entry_password));
    
    // Vault musi być otwarty podczas zmiany hasła
    EXPECT_TRUE(vault.change_password(old_master, new_master));
    vault.close();
    
    // Stare hasło nie powinno działać
    EXPECT_FALSE(vault.open(old_master));
    
    // Nowe hasło powinno działać
    EXPECT_TRUE(vault.open(new_master));
    
    // Wpisy powinny być nadal dostępne
    auto pwd = vault.get_password("test");
    ASSERT_TRUE(pwd.has_value());
    EXPECT_EQ(pwd->to_string(), "entry_secret");
}

TEST_F(VaultTest, DuplicateEntryName) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString master("master");
    pw::SecureString pwd("secret");
    
    ASSERT_TRUE(vault.create(master));
    EXPECT_TRUE(vault.add_entry("duplicate", "user1", pwd));
    EXPECT_FALSE(vault.add_entry("duplicate", "user2", pwd));  // Powinno się nie udać
}

// ============================================================================
// Duress Password Tests
// ============================================================================

TEST_F(VaultTest, SetDuressPassword) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString master("master_password");
    pw::SecureString duress("panic!");
    
    ASSERT_TRUE(vault.create(master));
    EXPECT_FALSE(vault.has_duress_password());
    
    EXPECT_TRUE(vault.set_duress_password(master, duress, false));
    EXPECT_TRUE(vault.has_duress_password());
    EXPECT_FALSE(vault.get_duress_delete_app());
}

TEST_F(VaultTest, SetDuressPasswordWithDeleteApp) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString master("master_password");
    pw::SecureString duress("panic!");
    
    ASSERT_TRUE(vault.create(master));
    
    EXPECT_TRUE(vault.set_duress_password(master, duress, true));
    EXPECT_TRUE(vault.has_duress_password());
    EXPECT_TRUE(vault.get_duress_delete_app());
}

TEST_F(VaultTest, DuressPasswordCannotEqualMaster) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString master("same_password");
    
    ASSERT_TRUE(vault.create(master));
    
    // Hasło paniki nie może być takie samo jak master
    EXPECT_FALSE(vault.set_duress_password(master, master, false));
}

TEST_F(VaultTest, DuressPasswordMinLength) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString master("master_password");
    pw::SecureString short_duress("abc");  // Za krótkie - minimum 4 znaki
    
    ASSERT_TRUE(vault.create(master));
    
    EXPECT_FALSE(vault.set_duress_password(master, short_duress, false));
}

TEST_F(VaultTest, CheckDuressPassword) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString master("master_password");
    pw::SecureString duress("panic!");
    pw::SecureString wrong("wrong_password");
    
    ASSERT_TRUE(vault.create(master));
    ASSERT_TRUE(vault.set_duress_password(master, duress, false));
    vault.close();
    
    // Sprawdź czy rozpoznaje hasło paniki
    EXPECT_TRUE(vault.check_duress_password(duress));
    
    // Sprawdź czy nie rozpoznaje innych haseł jako panic
    EXPECT_FALSE(vault.check_duress_password(master));
    EXPECT_FALSE(vault.check_duress_password(wrong));
}

TEST_F(VaultTest, RemoveDuressPassword) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString master("master_password");
    pw::SecureString duress("panic!");
    
    ASSERT_TRUE(vault.create(master));
    ASSERT_TRUE(vault.set_duress_password(master, duress, false));
    EXPECT_TRUE(vault.has_duress_password());
    
    EXPECT_TRUE(vault.remove_duress_password(master));
    EXPECT_FALSE(vault.has_duress_password());
}

TEST_F(VaultTest, DuressPasswordPersistence) {
    pw::SecureString master("master_password");
    pw::SecureString duress("panic!");
    
    // Utwórz vault z duress password
    {
        pw::Vault vault;
        vault.set_path(test_vault_path);
        ASSERT_TRUE(vault.create(master));
        ASSERT_TRUE(vault.set_duress_password(master, duress, true));
    }
    
    // Otwórz vault ponownie i sprawdź ustawienia
    {
        pw::Vault vault;
        vault.set_path(test_vault_path);
        ASSERT_TRUE(vault.open(master));
        
        EXPECT_TRUE(vault.has_duress_password());
        EXPECT_TRUE(vault.get_duress_delete_app());
    }
}

TEST_F(VaultTest, TriggerDuressWipe) {
    pw::SecureString master("master_password");
    pw::SecureString duress("panic!");
    pw::SecureString entry_pwd("secret123");
    
    // Utwórz vault z danymi i duress password
    {
        pw::Vault vault;
        vault.set_path(test_vault_path);
        ASSERT_TRUE(vault.create(master));
        ASSERT_TRUE(vault.add_entry("github", "user@example.com", entry_pwd));
        ASSERT_TRUE(vault.set_duress_password(master, duress, false));
        vault.close();
    }
    
    // Symuluj wpisanie hasła paniki
    {
        pw::Vault vault;
        vault.set_path(test_vault_path);
        
        // Sprawdź że vault istnieje
        ASSERT_TRUE(vault.exists());
        
        // Wykryj hasło paniki
        ASSERT_TRUE(vault.check_duress_password(duress));
        
        // Uruchom wipe
        vault.trigger_duress_wipe();
        
        // Vault nadal istnieje (fake vault)
        EXPECT_TRUE(vault.exists());
    }
    
    // Próba otwarcia fake vault powinna się nie udać
    {
        pw::Vault vault;
        vault.set_path(test_vault_path);
        
        EXPECT_TRUE(vault.exists());
        
        // Ani stare hasło master ani duress nie powinno działać
        EXPECT_FALSE(vault.open(master));
        EXPECT_FALSE(vault.open(duress));
    }
}

TEST_F(VaultTest, ToggleDuressDeleteApp) {
    pw::Vault vault;
    vault.set_path(test_vault_path);
    
    pw::SecureString master("master_password");
    pw::SecureString duress("panic!");
    
    ASSERT_TRUE(vault.create(master));
    ASSERT_TRUE(vault.set_duress_password(master, duress, false));
    
    EXPECT_FALSE(vault.get_duress_delete_app());
    
    EXPECT_TRUE(vault.set_duress_delete_app(master, true));
    EXPECT_TRUE(vault.get_duress_delete_app());
    
    EXPECT_TRUE(vault.set_duress_delete_app(master, false));
    EXPECT_FALSE(vault.get_duress_delete_app());
}
