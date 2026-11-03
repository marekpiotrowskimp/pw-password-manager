#include "generator.hpp"
#include <sodium.h>
#include <stdexcept>

namespace pw {

namespace {
    const std::string UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    const std::string DIGITS = "0123456789";
}

SecureString generate_password(const GeneratorOptions& options) {
    if (options.length < 4) {
        throw std::invalid_argument("Password length must be at least 4");
    }
    
    // Zbuduj zestaw znaków
    std::string charset;
    if (options.use_uppercase) charset += UPPERCASE;
    if (options.use_lowercase) charset += LOWERCASE;
    if (options.use_digits) charset += DIGITS;
    if (options.use_symbols) charset += options.custom_symbols;
    
    if (charset.empty()) {
        throw std::invalid_argument("At least one character set must be enabled");
    }
    
    SecureString password;
    password.reserve(options.length);
    
    // Generuj losowe znaki
    for (size_t i = 0; i < options.length; ++i) {
        uint32_t index = randombytes_uniform(static_cast<uint32_t>(charset.size()));
        password.push_back(charset[index]);
    }
    
    // Upewnij się, że hasło zawiera co najmniej jeden znak z każdego wymaganego zestawu
    size_t pos = 0;
    if (options.use_uppercase && options.length > pos) {
        uint32_t index = randombytes_uniform(static_cast<uint32_t>(UPPERCASE.size()));
        password[pos++] = UPPERCASE[index];
    }
    if (options.use_lowercase && options.length > pos) {
        uint32_t index = randombytes_uniform(static_cast<uint32_t>(LOWERCASE.size()));
        password[pos++] = LOWERCASE[index];
    }
    if (options.use_digits && options.length > pos) {
        uint32_t index = randombytes_uniform(static_cast<uint32_t>(DIGITS.size()));
        password[pos++] = DIGITS[index];
    }
    if (options.use_symbols && options.length > pos) {
        uint32_t index = randombytes_uniform(static_cast<uint32_t>(options.custom_symbols.size()));
        password[pos++] = options.custom_symbols[index];
    }
    
    // Przetasuj hasło (Fisher-Yates shuffle)
    for (size_t i = password.size() - 1; i > 0; --i) {
        size_t j = randombytes_uniform(static_cast<uint32_t>(i + 1));
        std::swap(password[i], password[j]);
    }
    
    return password;
}

SecureString generate_password(size_t length) {
    GeneratorOptions options;
    options.length = length;
    return generate_password(options);
}

SecureString generate_alphanumeric(size_t length) {
    GeneratorOptions options;
    options.length = length;
    options.use_symbols = false;
    return generate_password(options);
}

} // namespace pw
