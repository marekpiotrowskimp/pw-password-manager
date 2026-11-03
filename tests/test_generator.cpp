#include <gtest/gtest.h>
#include "generator.hpp"
#include "crypto.hpp"
#include <set>
#include <algorithm>

class GeneratorTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(pw::crypto_init());
    }
};

TEST_F(GeneratorTest, DefaultLength) {
    auto password = pw::generate_password();
    EXPECT_EQ(password.size(), 20);
}

TEST_F(GeneratorTest, CustomLength) {
    auto password = pw::generate_password(32);
    EXPECT_EQ(password.size(), 32);
}

TEST_F(GeneratorTest, MinimumLength) {
    EXPECT_THROW(pw::generate_password(3), std::invalid_argument);
    EXPECT_NO_THROW(pw::generate_password(4));
}

TEST_F(GeneratorTest, ContainsUppercase) {
    pw::GeneratorOptions options;
    options.length = 100;  // Większa długość dla pewności statystycznej
    
    auto password = pw::generate_password(options);
    std::string pwd_str = password.to_string();
    
    bool has_upper = std::any_of(pwd_str.begin(), pwd_str.end(), ::isupper);
    EXPECT_TRUE(has_upper);
}

TEST_F(GeneratorTest, ContainsLowercase) {
    pw::GeneratorOptions options;
    options.length = 100;
    
    auto password = pw::generate_password(options);
    std::string pwd_str = password.to_string();
    
    bool has_lower = std::any_of(pwd_str.begin(), pwd_str.end(), ::islower);
    EXPECT_TRUE(has_lower);
}

TEST_F(GeneratorTest, ContainsDigits) {
    pw::GeneratorOptions options;
    options.length = 100;
    
    auto password = pw::generate_password(options);
    std::string pwd_str = password.to_string();
    
    bool has_digit = std::any_of(pwd_str.begin(), pwd_str.end(), ::isdigit);
    EXPECT_TRUE(has_digit);
}

TEST_F(GeneratorTest, ContainsSymbols) {
    pw::GeneratorOptions options;
    options.length = 100;
    
    auto password = pw::generate_password(options);
    std::string pwd_str = password.to_string();
    
    bool has_symbol = std::any_of(pwd_str.begin(), pwd_str.end(), [](char c) {
        return !std::isalnum(c);
    });
    EXPECT_TRUE(has_symbol);
}

TEST_F(GeneratorTest, NoSymbols) {
    pw::GeneratorOptions options;
    options.length = 50;
    options.use_symbols = false;
    
    auto password = pw::generate_password(options);
    std::string pwd_str = password.to_string();
    
    bool all_alnum = std::all_of(pwd_str.begin(), pwd_str.end(), ::isalnum);
    EXPECT_TRUE(all_alnum);
}

TEST_F(GeneratorTest, Alphanumeric) {
    auto password = pw::generate_alphanumeric(50);
    std::string pwd_str = password.to_string();
    
    bool all_alnum = std::all_of(pwd_str.begin(), pwd_str.end(), ::isalnum);
    EXPECT_TRUE(all_alnum);
}

TEST_F(GeneratorTest, Randomness) {
    std::set<std::string> passwords;
    
    for (int i = 0; i < 100; ++i) {
        auto password = pw::generate_password(20);
        passwords.insert(password.to_string());
    }
    
    // Wszystkie hasła powinny być unikalne
    EXPECT_EQ(passwords.size(), 100);
}

TEST_F(GeneratorTest, OnlyUppercase) {
    pw::GeneratorOptions options;
    options.length = 20;
    options.use_uppercase = true;
    options.use_lowercase = false;
    options.use_digits = false;
    options.use_symbols = false;
    
    auto password = pw::generate_password(options);
    std::string pwd_str = password.to_string();
    
    bool all_upper = std::all_of(pwd_str.begin(), pwd_str.end(), ::isupper);
    EXPECT_TRUE(all_upper);
}

TEST_F(GeneratorTest, OnlyDigits) {
    pw::GeneratorOptions options;
    options.length = 20;
    options.use_uppercase = false;
    options.use_lowercase = false;
    options.use_digits = true;
    options.use_symbols = false;
    
    auto password = pw::generate_password(options);
    std::string pwd_str = password.to_string();
    
    bool all_digit = std::all_of(pwd_str.begin(), pwd_str.end(), ::isdigit);
    EXPECT_TRUE(all_digit);
}

TEST_F(GeneratorTest, NoCharacterSets) {
    pw::GeneratorOptions options;
    options.length = 20;
    options.use_uppercase = false;
    options.use_lowercase = false;
    options.use_digits = false;
    options.use_symbols = false;
    
    EXPECT_THROW(pw::generate_password(options), std::invalid_argument);
}

TEST_F(GeneratorTest, CustomSymbols) {
    pw::GeneratorOptions options;
    options.length = 100;
    options.use_uppercase = false;
    options.use_lowercase = false;
    options.use_digits = false;
    options.use_symbols = true;
    options.custom_symbols = "!@#";
    
    auto password = pw::generate_password(options);
    std::string pwd_str = password.to_string();
    
    bool valid_chars = std::all_of(pwd_str.begin(), pwd_str.end(), [](char c) {
        return c == '!' || c == '@' || c == '#';
    });
    EXPECT_TRUE(valid_chars);
}
