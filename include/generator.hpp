#pragma once

#include "secure_string.hpp"
#include <string>

namespace pw {

/**
 * Opcje generatora haseł
 */
struct GeneratorOptions {
    size_t length = 20;
    bool use_uppercase = true;
    bool use_lowercase = true;
    bool use_digits = true;
    bool use_symbols = true;
    std::string custom_symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
};

/**
 * Generuje bezpieczne losowe hasło
 * @param options opcje generatora
 * @return wygenerowane hasło
 */
SecureString generate_password(const GeneratorOptions& options = GeneratorOptions{});

/**
 * Generuje hasło o określonej długości z domyślnymi opcjami
 * @param length długość hasła
 * @return wygenerowane hasło
 */
SecureString generate_password(size_t length);

/**
 * Generuje hasło alfanumeryczne (bez symboli)
 * @param length długość hasła
 * @return wygenerowane hasło
 */
SecureString generate_alphanumeric(size_t length);

} // namespace pw
