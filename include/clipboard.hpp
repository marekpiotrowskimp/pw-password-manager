#pragma once

#include <string>

namespace pw {

/**
 * Kopiuje tekst do schowka systemowego
 * @param text tekst do skopiowania
 * @return true jeśli sukces
 */
bool clipboard_copy(const std::string& text);

/**
 * Czyści schowek systemowy
 * @return true jeśli sukces
 */
bool clipboard_clear();

/**
 * Kopiuje do schowka i planuje wyczyszczenie po timeout
 * @param text tekst do skopiowania
 * @param timeout_seconds czas w sekundach do wyczyszczenia (0 = nie czyść)
 * @return true jeśli sukces
 */
bool clipboard_copy_with_timeout(const std::string& text, int timeout_seconds = 30);

} // namespace pw
