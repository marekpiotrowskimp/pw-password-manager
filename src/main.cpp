#include "vault.hpp"
#include "generator.hpp"
#include "clipboard.hpp"
#include "crypto.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <cctype>
#include <algorithm>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace pw {

// ============================================================================
// ANSI Color Codes - Kali Linux style (green theme)
// ============================================================================

namespace color {
    // Reset
    const std::string RESET = "\033[0m";
    
    // Regular colors
    const std::string BLACK = "\033[0;30m";
    const std::string RED = "\033[0;31m";
    const std::string GREEN = "\033[0;32m";
    const std::string YELLOW = "\033[0;33m";
    const std::string BLUE = "\033[0;34m";
    const std::string MAGENTA = "\033[0;35m";
    const std::string CYAN = "\033[0;36m";
    const std::string WHITE = "\033[0;37m";
    
    // Bold colors
    const std::string BOLD_BLACK = "\033[1;30m";
    const std::string BOLD_RED = "\033[1;31m";
    const std::string BOLD_GREEN = "\033[1;32m";
    const std::string BOLD_YELLOW = "\033[1;33m";
    const std::string BOLD_BLUE = "\033[1;34m";
    const std::string BOLD_MAGENTA = "\033[1;35m";
    const std::string BOLD_CYAN = "\033[1;36m";
    const std::string BOLD_WHITE = "\033[1;37m";
    
    // Dim colors
    const std::string DIM = "\033[2m";
    const std::string DIM_GREEN = "\033[2;32m";
    
    // Background
    const std::string BG_GREEN = "\033[42m";
    const std::string BG_BLACK = "\033[40m";
}

// Kali-style colors
const std::string& TITLE = color::BOLD_GREEN;
const std::string& MENU_NUM = color::BOLD_CYAN;
const std::string& MENU_TEXT = color::GREEN;
const std::string& PROMPT = color::BOLD_GREEN;
const std::string& SUCCESS = color::BOLD_GREEN;
const std::string& ERROR_CLR = color::BOLD_RED;
const std::string& WARNING = color::BOLD_YELLOW;
const std::string& INFO = color::CYAN;
const std::string& DIM_TEXT = color::DIM_GREEN;
const std::string& HEADER = color::BOLD_WHITE;
const std::string& VALUE = color::WHITE;
const std::string& RESET = color::RESET;

// ============================================================================
// ASCII Logo
// ============================================================================

void print_logo() {
    std::cout << "\n";
    std::cout << color::BOLD_GREEN << "    PW VAULT" << color::RESET << color::DIM << " - Local Password Manager v1.0" << color::RESET << "\n";
    std::cout << color::DIM_GREEN << "    Encrypted with XChaCha20-Poly1305 + AES-256-GCM" << color::RESET << "\n\n";
}

// ============================================================================
// Terminal utilities
// ============================================================================

void clear_screen() {
#ifdef _WIN32
    system("cls");
#else
    std::cout << "\033[2J\033[H";
#endif
}

void press_enter_to_continue() {
    std::cout << "\n" << DIM_TEXT << "Press Enter to continue..." << RESET;
    std::cin.get();
}

SecureString read_password(const std::string& prompt) {
    std::cout << PROMPT << prompt << RESET << std::flush;
    
    SecureString password;
    
#ifdef _WIN32
    char c;
    while ((c = _getch()) != '\r') {
        if (c == '\b' && !password.empty()) {
            password.resize(password.size() - 1);
            std::cout << "\b \b";
        } else if (c != '\b') {
            password.push_back(c);
            std::cout << "*";
        }
    }
#else
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    std::string input;
    std::getline(std::cin, input);
    password = SecureString(input);
    
    for (auto& c : input) c = '\0';
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    
    std::cout << std::endl;
    return password;
}

std::string read_line(const std::string& prompt, const std::string& default_value = "") {
    std::cout << PROMPT << prompt;
    if (!default_value.empty()) {
        std::cout << DIM_TEXT << " [" << default_value << "]";
    }
    std::cout << ": " << RESET << std::flush;
    
    std::string input;
    std::getline(std::cin, input);
    
    if (input.empty() && !default_value.empty()) {
        return default_value;
    }
    return input;
}

bool confirm(const std::string& prompt) {
    std::cout << WARNING << prompt << " [y/N]: " << RESET << std::flush;
    std::string response;
    std::getline(std::cin, response);
    return !response.empty() && (response[0] == 'y' || response[0] == 'Y');
}

std::string format_timestamp(int64_t timestamp) {
    time_t time = static_cast<time_t>(timestamp);
    struct tm* tm_info = localtime(&time);
    if (!tm_info) {
        return "N/A";
    }
    char buffer[26];
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    return std::string(buffer);
}

void print_separator() {
    std::cout << DIM_TEXT << "------------------------------------------------------------" << RESET << "\n";
}

void print_error(const std::string& msg) {
    std::cout << ERROR_CLR << "[!] " << msg << RESET << "\n";
}

void print_success(const std::string& msg) {
    std::cout << SUCCESS << "[+] " << msg << RESET << "\n";
}

void print_info(const std::string& msg) {
    std::cout << INFO << "[*] " << msg << RESET << "\n";
}

// ============================================================================
// Search Highlighting Helper
// ============================================================================

std::string highlight_match(const std::string& text, const std::string& query, const std::string& base_color) {
    if (query.empty()) return base_color + text + RESET;
    
    std::string lower_text = text;
    std::string lower_query = query;
    std::transform(lower_text.begin(), lower_text.end(), lower_text.begin(), ::tolower);
    std::transform(lower_query.begin(), lower_query.end(), lower_query.begin(), ::tolower);
    
    std::string result;
    size_t pos = 0;
    size_t last_pos = 0;
    
    while ((pos = lower_text.find(lower_query, last_pos)) != std::string::npos) {
        // Add text before match
        result += base_color + text.substr(last_pos, pos - last_pos);
        // Add highlighted match
        result += color::BOLD_YELLOW + text.substr(pos, query.length()) + base_color;
        last_pos = pos + query.length();
    }
    // Add remaining text
    result += text.substr(last_pos);
    result += RESET;
    
    return result;
}

// ============================================================================
// Password Strength Indicator
// ============================================================================

struct PasswordStrength {
    int score;           // 0-100
    std::string label;   // "Very Weak", "Weak", "Fair", "Strong", "Very Strong"
    std::string color;   // ANSI color
};

PasswordStrength calculate_password_strength(const std::string& password) {
    int score = 0;
    int length = password.length();
    
    // Length score (up to 30 points)
    if (length >= 8) score += 10;
    if (length >= 12) score += 10;
    if (length >= 16) score += 5;
    if (length >= 20) score += 5;
    
    // Character variety (up to 40 points)
    bool has_lower = false, has_upper = false, has_digit = false, has_symbol = false;
    int unique_chars = 0;
    std::string seen;
    
    for (char c : password) {
        if (std::islower(static_cast<unsigned char>(c))) has_lower = true;
        else if (std::isupper(static_cast<unsigned char>(c))) has_upper = true;
        else if (std::isdigit(static_cast<unsigned char>(c))) has_digit = true;
        else has_symbol = true;
        
        if (seen.find(c) == std::string::npos) {
            seen += c;
            unique_chars++;
        }
    }
    
    if (has_lower) score += 10;
    if (has_upper) score += 10;
    if (has_digit) score += 10;
    if (has_symbol) score += 10;
    
    // Unique character ratio (up to 20 points)
    if (length > 0) {
        double ratio = static_cast<double>(unique_chars) / length;
        score += static_cast<int>(ratio * 20);
    }
    
    // Penalty for common patterns
    std::string lower_pwd = password;
    for (auto& c : lower_pwd) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    
    // Sequential characters penalty
    int sequential = 0;
    for (size_t i = 1; i < password.length(); i++) {
        if (password[i] == password[i-1] + 1 || password[i] == password[i-1] - 1) {
            sequential++;
        }
    }
    score -= sequential * 2;
    
    // Repeated characters penalty
    int repeats = 0;
    for (size_t i = 1; i < password.length(); i++) {
        if (password[i] == password[i-1]) repeats++;
    }
    score -= repeats * 3;
    
    // Common patterns penalty
    if (lower_pwd.find("password") != std::string::npos) score -= 20;
    if (lower_pwd.find("123456") != std::string::npos) score -= 20;
    if (lower_pwd.find("qwerty") != std::string::npos) score -= 20;
    
    // Clamp score
    if (score < 0) score = 0;
    if (score > 100) score = 100;
    
    // Determine label and color
    PasswordStrength result;
    result.score = score;
    
    if (score < 20) {
        result.label = "Very Weak";
        result.color = color::BOLD_RED;
    } else if (score < 40) {
        result.label = "Weak";
        result.color = color::RED;
    } else if (score < 60) {
        result.label = "Fair";
        result.color = color::YELLOW;
    } else if (score < 80) {
        result.label = "Strong";
        result.color = color::GREEN;
    } else {
        result.label = "Very Strong";
        result.color = color::BOLD_GREEN;
    }
    
    return result;
}

void print_password_strength(const std::string& password) {
    auto strength = calculate_password_strength(password);
    
    // Visual bar (20 chars wide)
    int filled = strength.score / 5;
    std::string bar = "[";
    for (int i = 0; i < 20; i++) {
        bar += (i < filled) ? "#" : "-";
    }
    bar += "]";
    
    std::cout << "  " << HEADER << "Strength: " << strength.color << bar << " " 
              << strength.label << " (" << strength.score << "%)" << RESET << "\n";
}

// ============================================================================
// TUI Application class
// ============================================================================

class App {
public:
    App() = default;
    
    void run() {
        if (!crypto_init()) {
            print_error("Failed to initialize cryptography library");
            return;
        }
        
        clear_screen();
        print_logo();
        
        if (vault_.exists()) {
            login_screen();
        } else {
            first_run_screen();
        }
    }

private:
    Vault vault_;
    bool running_ = true;
    int auto_lock_timeout_ = 300;  // Default: 5 minutes (in seconds), 0 = disabled
    std::time_t last_activity_ = std::time(nullptr);
    
    void update_activity() {
        last_activity_ = std::time(nullptr);
    }
    
    bool check_auto_lock() {
        if (auto_lock_timeout_ <= 0) return false;
        
        std::time_t now = std::time(nullptr);
        int elapsed = static_cast<int>(now - last_activity_);
        
        if (elapsed >= auto_lock_timeout_) {
            vault_.close();
            running_ = false;
            clear_screen();
            std::cout << WARNING << "\n[!] Session timed out due to inactivity.\n" << RESET;
            std::cout << INFO << "Vault has been locked for security.\n" << RESET;
            return true;
        }
        return false;
    }
    
    // ========================================================================
    // Screens
    // ========================================================================
    
    void first_run_screen() {
        std::cout << INFO << "No vault found in: " << vault_.get_directory() << "\n" << RESET;
        std::cout << MENU_TEXT << "Would you like to create a new vault?\n\n" << RESET;
        
        if (!confirm("Create new vault")) {
            std::cout << "\nGoodbye!\n";
            return;
        }
        
        create_vault();
    }
    
    void create_vault() {
        std::cout << "\n";
        print_separator();
        std::cout << TITLE << "  CREATE NEW VAULT\n" << RESET;
        print_separator();
        
        auto password = read_password("Enter master password: ");
        auto confirm_pwd = read_password("Confirm master password: ");
        
        if (!password.equals(confirm_pwd)) {
            print_error("Passwords do not match");
            press_enter_to_continue();
            return;
        }
        
        if (password.size() < 8) {
            print_error("Password must be at least 8 characters");
            press_enter_to_continue();
            return;
        }
        
        std::string keyfile_path;
        if (confirm("Add keyfile for extra security")) {
            keyfile_path = read_line("Keyfile path", "vault.key");
        }
        
        if (vault_.create(password, keyfile_path)) {
            print_success("Vault created successfully!");
            if (!keyfile_path.empty()) {
                print_info("Keyfile generated: " + keyfile_path);
                print_info("Keep this file safe - you'll need it to unlock the vault!");
            }
            press_enter_to_continue();
            main_menu();
        } else {
            print_error(vault_.get_last_error());
            press_enter_to_continue();
        }
    }
    
    void login_screen() {
        std::cout << INFO << "Vault found: " << vault_.get_path() << "\n\n" << RESET;
        
        for (int attempts = 3; attempts > 0; --attempts) {
            auto password = read_password("Master password: ");
            
            // Sprawdź czy to hasło paniki (duress password)
            if (vault_.check_duress_password(password)) {
                // Uruchom procedurę paniki
                vault_.trigger_duress_wipe();
                
                // Symuluj opóźnienie jakby próbował odszyfrować
                std::this_thread::sleep_for(std::chrono::milliseconds(800));
                
                // Wyświetl fałszywy komunikat o uszkodzeniu
                print_error("Vault file is corrupted");
                std::cout << INFO << "The vault file appears to be damaged and cannot be opened.\n" << RESET;
                std::cout << INFO << "You may need to restore from backup.\n" << RESET;
                return;
            }
            
            if (vault_.open(password)) {
                print_success("Vault unlocked!");
                std::cout << "\n";
                main_menu();
                return;
            }
            
            print_error(vault_.get_last_error());
            if (attempts > 1) {
                std::cout << WARNING << "Remaining attempts: " << (attempts - 1) << RESET << "\n\n";
            }
        }
        
        print_error("Too many failed attempts. Exiting.");
    }
    
    void main_menu() {
        update_activity();
        
        while (running_) {
            if (check_auto_lock()) return;
            
            clear_screen();
            print_logo();
            
            std::cout << TITLE << "  MAIN MENU\n" << RESET;
            print_separator();
            
            size_t entry_count = vault_.get_entries().size();
            std::cout << DIM_TEXT << "  Entries in vault: " << entry_count;
            if (auto_lock_timeout_ > 0) {
                int remaining = auto_lock_timeout_ - static_cast<int>(std::time(nullptr) - last_activity_);
                if (remaining > 0) {
                    std::cout << "  |  Auto-lock in: " << remaining / 60 << "m " << remaining % 60 << "s";
                }
            }
            std::cout << RESET << "\n\n";
            
            std::cout << MENU_NUM << "  [1] " << MENU_TEXT << "List all entries\n" << RESET;
            std::cout << MENU_NUM << "  [2] " << MENU_TEXT << "Search entries\n" << RESET;
            std::cout << MENU_NUM << "  [3] " << MENU_TEXT << "Add new entry\n" << RESET;
            std::cout << MENU_NUM << "  [4] " << MENU_TEXT << "Generate password\n" << RESET;
            std::cout << MENU_NUM << "  [5] " << MENU_TEXT << "Settings\n" << RESET;
            std::cout << MENU_NUM << "  [0] " << MENU_TEXT << "Lock & Exit\n" << RESET;
            
            std::cout << "\n";
            std::string choice = read_line("Select option");
            update_activity();
            
            if (choice == "1") list_entries();
            else if (choice == "2") search_entries();
            else if (choice == "3") add_entry();
            else if (choice == "4") generate_password_menu();
            else if (choice == "5") settings_menu();
            else if (choice == "0" || choice == "q" || choice == "Q") {
                vault_.close();
                running_ = false;
                clear_screen();
                std::cout << SUCCESS << "\nVault locked. Goodbye!\n" << RESET;
            }
        }
    }
    
    // ========================================================================
    // Entry operations
    // ========================================================================
    
    void list_entries() {
        while (true) {
            clear_screen();
            std::cout << TITLE << "  ALL ENTRIES\n" << RESET;
            print_separator();
            
            const auto& entries = vault_.get_entries();
            
            if (entries.empty()) {
                std::cout << DIM_TEXT << "  No entries in vault\n" << RESET;
                press_enter_to_continue();
                return;
            }
            
            // Oblicz maksymalne szerokości kolumn
            size_t max_name = 4;  // min "NAME"
            size_t max_user = 8;  // min "USERNAME"
            size_t max_url = 3;   // min "URL"
            
            for (const auto& entry : entries) {
                if (entry.name.length() > max_name) max_name = entry.name.length();
                if (entry.username.length() > max_user) max_user = entry.username.length();
                if (entry.url.length() > max_url) max_url = entry.url.length();
            }
            
            // Dodaj padding
            max_name += 2;
            max_user += 2;
            
            std::cout << HEADER << std::left 
                      << std::setw(6) << "#"
                      << std::setw(max_name) << "NAME" 
                      << std::setw(max_user) << "USERNAME" 
                      << "URL" << RESET << "\n";
            print_separator();
            
            int idx = 1;
            for (const auto& entry : entries) {
                std::cout << MENU_NUM << std::left << std::setw(6) << idx++ << RESET
                          << VALUE << std::setw(max_name) << entry.name
                          << std::setw(max_user) << entry.username
                          << entry.url << RESET << "\n";
            }
            
            std::cout << "\n" << DIM_TEXT << "  [#] View details    [c#] Copy password    [Enter] Back\n" << RESET;
            std::cout << "\n";
            std::string choice = read_line("Choice");
            
            if (choice.empty()) return;
            
            // Handle "c#" - copy password
            if (choice.length() >= 2 && (choice[0] == 'c' || choice[0] == 'C')) {
                std::string num_str = choice.substr(1);
                try {
                    int num = std::stoi(num_str);
                    if (num >= 1 && num <= static_cast<int>(entries.size())) {
                        const auto& entry = entries[num - 1];
                        auto password = vault_.get_password(entry.name);
                        if (password) {
                            if (clipboard_copy_with_timeout(password->to_string(), 30)) {
                                print_success("Password for '" + entry.name + "' copied (30s timeout)");
                            } else {
                                print_error("Failed to copy to clipboard");
                            }
                        } else {
                            print_error("Failed to decrypt password");
                        }
                        press_enter_to_continue();
                    }
                } catch (...) {}
                continue;
            }
            
            // Handle "#" - view details
            try {
                int num = std::stoi(choice);
                if (num >= 1 && num <= static_cast<int>(entries.size())) {
                    view_entry_details(entries[num - 1].name);
                }
            } catch (...) {}
        }
    }
    
    void search_entries() {
        clear_screen();
        std::cout << TITLE << "  SEARCH ENTRIES\n" << RESET;
        print_separator();
        
        std::string query = read_line("Search query");
        if (query.empty()) return;
        
        while (true) {
            clear_screen();
            std::cout << TITLE << "  SEARCH RESULTS: " << query << "\n" << RESET;
            print_separator();
            
            auto results = vault_.search_entries(query);
            
            if (results.empty()) {
                print_info("No entries found matching: " + query);
                press_enter_to_continue();
                return;
            }
            
            std::cout << SUCCESS << "Found " << results.size() << " entry(ies):\n\n" << RESET;
            
            // Oblicz maksymalne szerokości kolumn
            size_t max_name = 4;  // min "NAME"
            size_t max_user = 8;  // min "USERNAME"
            
            for (const auto& entry : results) {
                if (entry.name.length() > max_name) max_name = entry.name.length();
                if (entry.username.length() > max_user) max_user = entry.username.length();
            }
            
            // Dodaj padding
            max_name += 2;
            max_user += 2;
            
            std::cout << HEADER << std::left 
                      << std::setw(6) << "#"
                      << std::setw(max_name) << "NAME" 
                      << std::setw(max_user) << "USERNAME" 
                      << "URL" << RESET << "\n";
            print_separator();
            
            int idx = 1;
            for (const auto& entry : results) {
                std::cout << MENU_NUM << std::left << std::setw(6) << idx++ << RESET;
                
                // Pad for alignment (manual since highlighting breaks setw)
                std::string name_disp = entry.name;
                std::string user_disp = entry.username;
                
                while (name_disp.length() < max_name) name_disp += " ";
                while (user_disp.length() < max_user) user_disp += " ";
                
                std::cout << highlight_match(name_disp, query, VALUE)
                          << highlight_match(user_disp, query, VALUE)
                          << highlight_match(entry.url, query, VALUE) << "\n";
            }
            
            std::cout << "\n" << DIM_TEXT << "  [#] View details    [c#] Copy password    [Enter] Back\n" << RESET;
            std::cout << "\n";
            std::string choice = read_line("Choice");
            
            if (choice.empty()) return;
            
            // Handle "c#" - copy password
            if (choice.length() >= 2 && (choice[0] == 'c' || choice[0] == 'C')) {
                std::string num_str = choice.substr(1);
                try {
                    int num = std::stoi(num_str);
                    if (num >= 1 && num <= static_cast<int>(results.size())) {
                        const auto& entry = results[num - 1];
                        auto password = vault_.get_password(entry.name);
                        if (password) {
                            if (clipboard_copy_with_timeout(password->to_string(), 30)) {
                                print_success("Password for '" + entry.name + "' copied (30s timeout)");
                            } else {
                                print_error("Failed to copy to clipboard");
                            }
                        } else {
                            print_error("Failed to decrypt password");
                        }
                        press_enter_to_continue();
                    }
                } catch (...) {}
                continue;
            }
            
            // Handle "#" - view details
            try {
                int num = std::stoi(choice);
                if (num >= 1 && num <= static_cast<int>(results.size())) {
                    view_entry_details(results[num - 1].name);
                }
            } catch (...) {}
        }
    }
    
    void view_entry_details(const std::string& entry_name) {
        std::string current_name = entry_name;
        
        while (true) {
            clear_screen();
            
            auto entry = vault_.get_entry(current_name);
            if (!entry) {
                print_error("Entry not found: " + current_name);
                press_enter_to_continue();
                return;
            }
            
            auto password = vault_.get_password(current_name);
            
            std::cout << TITLE << "  ENTRY: " << entry->name << "\n" << RESET;
            print_separator();
            
            std::cout << HEADER << "  Username:  " << VALUE << entry->username << RESET << "\n";
            
            if (password) {
                std::cout << HEADER << "  Password:  " << VALUE << password->to_string() << RESET << "\n";
                print_password_strength(password->to_string());
            } else {
                std::cout << HEADER << "  Password:  " << ERROR_CLR << "(decryption failed)" << RESET << "\n";
            }
            
            std::cout << HEADER << "  URL:       " << VALUE << (entry->url.empty() ? "-" : entry->url) << RESET << "\n";
            std::cout << HEADER << "  Notes:     " << VALUE << (entry->notes.empty() ? "-" : entry->notes) << RESET << "\n";
            std::cout << HEADER << "  Created:   " << DIM_TEXT << format_timestamp(entry->created_at) << RESET << "\n";
            std::cout << HEADER << "  Modified:  " << DIM_TEXT << format_timestamp(entry->updated_at) << RESET << "\n";
            
            std::cout << "\n";
            std::cout << MENU_NUM << "  [c] " << MENU_TEXT << "Copy...\n" << RESET;
            std::cout << MENU_NUM << "  [e] " << MENU_TEXT << "Edit entry\n" << RESET;
            std::cout << MENU_NUM << "  [h] " << MENU_TEXT << "Password history\n" << RESET;
            std::cout << MENU_NUM << "  [d] " << MENU_TEXT << "Delete entry\n" << RESET;
            std::cout << MENU_NUM << "  [b] " << MENU_TEXT << "Back\n" << RESET;
            
            std::cout << "\n";
            std::string choice = read_line("Choice");
            
            if (choice.empty() || choice == "b" || choice == "B") {
                return;
            } else if (choice == "c" || choice == "C") {
                // Podmenu kopiowania
                std::cout << "\n" << INFO << "  Copy what?\n" << RESET;
                std::cout << MENU_NUM << "  [p] " << MENU_TEXT << "Password\n" << RESET;
                std::cout << MENU_NUM << "  [u] " << MENU_TEXT << "Username\n" << RESET;
                std::cout << MENU_NUM << "  [l] " << MENU_TEXT << "URL\n" << RESET;
                std::cout << "\n";
                std::string copy_choice = read_line("Choice", "p");
                
                std::string to_copy;
                std::string what;
                
                if (copy_choice == "p" || copy_choice == "P" || copy_choice.empty()) {
                    if (password) {
                        to_copy = password->to_string();
                        what = "Password";
                    } else {
                        print_error("Cannot copy - password decryption failed");
                        press_enter_to_continue();
                        continue;
                    }
                } else if (copy_choice == "u" || copy_choice == "U") {
                    to_copy = entry->username;
                    what = "Username";
                } else if (copy_choice == "l" || copy_choice == "L") {
                    if (entry->url.empty()) {
                        print_error("URL is empty");
                        press_enter_to_continue();
                        continue;
                    }
                    to_copy = entry->url;
                    what = "URL";
                } else {
                    continue;
                }
                
                if (clipboard_copy_with_timeout(to_copy, 30)) {
                    print_success(what + " copied to clipboard (30s timeout)");
                } else {
                    print_error("Failed to copy to clipboard");
                }
                press_enter_to_continue();
            } else if (choice == "e" || choice == "E") {
                edit_entry_direct(current_name);
                // Po edycji sprawdź czy wpis nadal istnieje (nazwa mogła się zmienić)
                if (!vault_.get_entry(current_name)) {
                    return;  // Nazwa zmieniona, wróć do listy
                }
            } else if (choice == "h" || choice == "H") {
                view_password_history_direct(current_name);
            } else if (choice == "d" || choice == "D") {
                if (delete_entry_with_confirmation(current_name)) {
                    return;  // Entry deleted, go back to list
                }
            }
        }
    }
    
    void edit_entry_direct(const std::string& entry_name) {
        clear_screen();
        std::cout << TITLE << "  EDIT ENTRY: " << entry_name << "\n" << RESET;
        print_separator();
        
        auto entry = vault_.get_entry(entry_name);
        if (!entry) {
            print_error("Entry not found");
            press_enter_to_continue();
            return;
        }
        
        std::cout << INFO << "Current values (press Enter to keep):\n\n" << RESET;
        
        std::string new_name = read_line("Name", entry->name);
        std::string new_username = read_line("Username", entry->username);
        
        SecureString new_password;
        std::cout << "\n" << MENU_NUM << "[1] " << MENU_TEXT << "Keep current password\n" << RESET;
        std::cout << MENU_NUM << "[2] " << MENU_TEXT << "Enter new password\n" << RESET;
        std::cout << MENU_NUM << "[3] " << MENU_TEXT << "Generate new password\n" << RESET;
        std::string pwd_choice = read_line("Choose", "1");
        
        if (pwd_choice == "2") {
            new_password = read_password("New password: ");
            print_password_strength(new_password.to_string());
        } else if (pwd_choice == "3") {
            std::string len_str = read_line("Password length", "20");
            int length = std::stoi(len_str);
            new_password = generate_password(length);
            std::cout << SUCCESS << "Generated: " << VALUE << new_password.to_string() << RESET << "\n";
            print_password_strength(new_password.to_string());
        }
        
        std::string new_url = read_line("URL", entry->url);
        std::string new_notes = read_line("Notes", entry->notes);
        
        std::cout << "\n";
        
        bool name_changed = (new_name != entry->name);
        bool username_changed = (new_username != entry->username);
        bool url_changed = (new_url != entry->url);
        bool notes_changed = (new_notes != entry->notes);
        bool password_changed = !new_password.empty();
        
        // Najpierw zmień nazwę jeśli trzeba
        std::string current_name = entry_name;
        if (name_changed) {
            if (vault_.rename_entry(entry_name, new_name)) {
                print_success("Entry renamed to '" + new_name + "'");
                current_name = new_name;
            } else {
                print_error(vault_.get_last_error());
                press_enter_to_continue();
                return;
            }
        }
        
        // Następnie edytuj pozostałe pola
        if (username_changed || password_changed || url_changed || notes_changed) {
            if (vault_.edit_entry(
                current_name,
                username_changed ? new_username : "",
                new_password,
                url_changed ? std::optional<std::string>(new_url) : std::nullopt,
                notes_changed ? std::optional<std::string>(new_notes) : std::nullopt
            )) {
                print_success("Entry updated successfully!");
                if (password_changed) {
                    print_info("Previous password saved to history");
                }
            } else {
                print_error(vault_.get_last_error());
            }
        } else if (!name_changed) {
            print_info("No changes made");
        }
        
        press_enter_to_continue();
    }
    
    void view_password_history_direct(const std::string& entry_name) {
        clear_screen();
        std::cout << TITLE << "  PASSWORD HISTORY: " << entry_name << "\n" << RESET;
        print_separator();
        
        auto entry = vault_.get_entry(entry_name);
        if (!entry) {
            print_error("Entry not found");
            press_enter_to_continue();
            return;
        }
        
        auto history = vault_.get_password_history(entry_name);
        
        std::cout << HEADER << "  Current password set: " << VALUE << format_timestamp(entry->updated_at) << RESET << "\n\n";
        
        if (history.empty()) {
            print_info("No password history available");
        } else {
            std::cout << HEADER << "  Previous passwords:\n" << RESET;
            print_separator();
            
            int idx = 1;
            for (const auto& [pwd, timestamp] : history) {
                std::cout << MENU_NUM << "  " << idx++ << ". " << RESET;
                std::cout << DIM_TEXT << "[" << format_timestamp(timestamp) << "] " << RESET;
                std::cout << VALUE << pwd.to_string() << RESET << "\n";
            }
        }
        
        press_enter_to_continue();
    }
    
    bool delete_entry_with_confirmation(const std::string& entry_name) {
        std::cout << "\n";
        std::cout << WARNING << "  WARNING: You are about to delete entry \"" << entry_name << "\"\n" << RESET;
        std::cout << "\n";
        
        std::string confirm_name = read_line("Type entry name to confirm deletion");
        
        if (confirm_name != entry_name) {
            print_error("Name does not match. Deletion cancelled.");
            press_enter_to_continue();
            return false;
        }
        
        if (vault_.remove_entry(entry_name)) {
            print_success("Entry \"" + entry_name + "\" deleted");
            press_enter_to_continue();
            return true;
        } else {
            print_error(vault_.get_last_error());
            press_enter_to_continue();
            return false;
        }
    }
    
    void add_entry() {
        clear_screen();
        std::cout << TITLE << "  ADD NEW ENTRY\n" << RESET;
        print_separator();
        
        std::string name = read_line("Entry name");
        if (name.empty()) {
            print_error("Name cannot be empty");
            press_enter_to_continue();
            return;
        }
        
        std::string username = read_line("Username");
        
        SecureString password;
        std::cout << "\n" << MENU_NUM << "[1] " << MENU_TEXT << "Enter password manually\n" << RESET;
        std::cout << MENU_NUM << "[2] " << MENU_TEXT << "Generate password\n" << RESET;
        std::string pwd_choice = read_line("Choose", "2");
        
        if (pwd_choice == "1") {
            password = read_password("Password: ");
            print_password_strength(password.to_string());
        } else {
            std::string len_str = read_line("Password length", "20");
            int length = std::stoi(len_str);
            password = generate_password(length);
            std::cout << SUCCESS << "Generated: " << VALUE << password.to_string() << RESET << "\n";
            print_password_strength(password.to_string());
        }
        
        std::string url = read_line("URL (optional)");
        std::string notes = read_line("Notes (optional)");
        
        std::cout << "\n";
        if (vault_.add_entry(name, username, password, url, notes)) {
            print_success("Entry '" + name + "' added successfully!");
        } else {
            print_error(vault_.get_last_error());
        }
        
        press_enter_to_continue();
    }
    
    void generate_password_menu() {
        clear_screen();
        std::cout << TITLE << "  GENERATE PASSWORD\n" << RESET;
        print_separator();
        
        std::string len_str = read_line("Password length", "20");
        int length = std::stoi(len_str);
        
        std::cout << "\n" << MENU_NUM << "[1] " << MENU_TEXT << "All characters (letters, digits, symbols)\n" << RESET;
        std::cout << MENU_NUM << "[2] " << MENU_TEXT << "Alphanumeric only (no symbols)\n" << RESET;
        std::cout << MENU_NUM << "[3] " << MENU_TEXT << "Letters only\n" << RESET;
        std::cout << MENU_NUM << "[4] " << MENU_TEXT << "Digits only\n" << RESET;
        std::string type = read_line("Type", "1");
        
        GeneratorOptions options;
        options.length = length;
        
        if (type == "2") {
            options.use_symbols = false;
        } else if (type == "3") {
            options.use_symbols = false;
            options.use_digits = false;
        } else if (type == "4") {
            options.use_uppercase = false;
            options.use_lowercase = false;
            options.use_symbols = false;
        }
        
        std::cout << "\n";
        std::cout << HEADER << "  Generated passwords:\n\n" << RESET;
        
        std::vector<std::string> generated_passwords;
        for (int i = 0; i < 5; ++i) {
            auto pwd = generate_password(options);
            std::string pwd_str = pwd.to_string();
            generated_passwords.push_back(pwd_str);
            auto strength = calculate_password_strength(pwd_str);
            int filled = strength.score / 5;
            std::string bar = "[";
            for (int j = 0; j < 20; j++) {
                bar += (j < filled) ? "#" : "-";
            }
            bar += "]";
            std::cout << "    " << MENU_NUM << "[" << (i + 1) << "] " << VALUE << pwd_str 
                      << "  " << strength.color << bar << " " << strength.score << "%" << RESET << "\n";
        }
        
        std::cout << "\n";
        std::string choice = read_line("Copy to clipboard (1-5, or Enter to skip)");
        
        if (!choice.empty() && choice[0] >= '1' && choice[0] <= '5') {
            int idx = choice[0] - '1';
            if (clipboard_copy_with_timeout(generated_passwords[idx], 30)) {
                print_success("Password copied to clipboard (30s timeout)");
            }
        }
        
        press_enter_to_continue();
    }
    
    void settings_menu() {
        while (true) {
            clear_screen();
            std::cout << TITLE << "  SETTINGS\n" << RESET;
            print_separator();
            
            std::cout << MENU_NUM << "  [1] " << MENU_TEXT << "Change master password\n" << RESET;
            std::cout << MENU_NUM << "  [2] " << MENU_TEXT << "Add keyfile\n" << RESET;
            std::cout << MENU_NUM << "  [3] " << MENU_TEXT << "Remove keyfile\n" << RESET;
            std::cout << MENU_NUM << "  [4] " << MENU_TEXT << "Export vault\n" << RESET;
            std::cout << MENU_NUM << "  [5] " << MENU_TEXT << "Import from file\n" << RESET;
            std::cout << MENU_NUM << "  [6] " << MENU_TEXT << "Auto-lock timeout";
            if (auto_lock_timeout_ > 0) {
                std::cout << DIM_TEXT << " [" << auto_lock_timeout_ / 60 << " min]";
            } else {
                std::cout << DIM_TEXT << " [disabled]";
            }
            std::cout << "\n" << RESET;
            std::cout << MENU_NUM << "  [7] " << MENU_TEXT << "Vault directory";
            std::cout << DIM_TEXT << " [" << vault_.get_directory() << "]\n" << RESET;
            
            // Duress password option
            std::cout << MENU_NUM << "  [8] " << MENU_TEXT << "Duress password (panic)";
            if (vault_.has_duress_password()) {
                std::cout << SUCCESS << " [enabled]";
                if (vault_.get_duress_delete_app()) {
                    std::cout << WARNING << " +delete app";
                }
            } else {
                std::cout << DIM_TEXT << " [disabled]";
            }
            std::cout << "\n" << RESET;
            
            std::cout << MENU_NUM << "  [0] " << MENU_TEXT << "Back to main menu\n" << RESET;
            
            std::cout << "\n";
            std::string choice = read_line("Select option");
            update_activity();
            
            if (choice == "1") change_master_password();
            else if (choice == "2") add_keyfile();
            else if (choice == "3") remove_keyfile();
            else if (choice == "4") export_vault();
            else if (choice == "5") import_vault();
            else if (choice == "6") set_auto_lock_timeout();
            else if (choice == "7") set_vault_directory();
            else if (choice == "8") duress_password_menu();
            else if (choice == "0" || choice.empty()) return;
        }
    }
    
    void change_master_password() {
        clear_screen();
        std::cout << TITLE << "  CHANGE MASTER PASSWORD\n" << RESET;
        print_separator();
        
        auto old_password = read_password("Current password: ");
        auto new_password = read_password("New password: ");
        auto confirm_pwd = read_password("Confirm new password: ");
        
        if (!new_password.equals(confirm_pwd)) {
            print_error("Passwords do not match");
            press_enter_to_continue();
            return;
        }
        
        if (new_password.size() < 8) {
            print_error("Password must be at least 8 characters");
            press_enter_to_continue();
            return;
        }
        
        std::cout << "\n";
        if (vault_.change_password(old_password, new_password)) {
            print_success("Master password changed successfully!");
        } else {
            print_error(vault_.get_last_error());
        }
        
        press_enter_to_continue();
    }
    
    void add_keyfile() {
        clear_screen();
        std::cout << TITLE << "  ADD KEYFILE\n" << RESET;
        print_separator();
        
        if (vault_.has_keyfile()) {
            print_error("Vault already has a keyfile configured");
            press_enter_to_continue();
            return;
        }
        
        auto password = read_password("Master password: ");
        std::string keyfile_path = read_line("Keyfile path", "vault.key");
        
        std::cout << "\n";
        if (vault_.add_keyfile(password, keyfile_path)) {
            print_success("Keyfile added: " + keyfile_path);
            print_info("Keep this file safe!");
        } else {
            print_error(vault_.get_last_error());
        }
        
        press_enter_to_continue();
    }
    
    void remove_keyfile() {
        clear_screen();
        std::cout << TITLE << "  REMOVE KEYFILE\n" << RESET;
        print_separator();
        
        if (!vault_.has_keyfile()) {
            print_error("No keyfile configured");
            press_enter_to_continue();
            return;
        }
        
        std::cout << WARNING << "Warning: This will remove keyfile protection from the vault.\n" << RESET;
        
        if (!confirm("Continue")) {
            print_info("Cancelled");
            press_enter_to_continue();
            return;
        }
        
        auto password = read_password("Master password: ");
        
        std::cout << "\n";
        if (vault_.remove_keyfile(password)) {
            print_success("Keyfile removed");
        } else {
            print_error(vault_.get_last_error());
        }
        
        press_enter_to_continue();
    }
    
    void export_vault() {
        clear_screen();
        std::cout << TITLE << "  EXPORT VAULT\n" << RESET;
        print_separator();
        
        std::cout << WARNING << "WARNING: Exported file will contain UNENCRYPTED passwords!\n" << RESET;
        std::cout << DIM_TEXT << "Make sure to store it securely or delete after use.\n\n" << RESET;
        
        std::cout << MENU_NUM << "[1] " << MENU_TEXT << "Export as JSON\n" << RESET;
        std::cout << MENU_NUM << "[2] " << MENU_TEXT << "Export as CSV\n" << RESET;
        std::cout << MENU_NUM << "[0] " << MENU_TEXT << "Cancel\n" << RESET;
        
        std::string format = read_line("Choose format", "1");
        if (format == "0") return;
        
        std::string default_file = (format == "2") ? "passwords.csv" : "passwords.json";
        std::string path = read_line("Output file", default_file);
        
        if (!confirm("Export " + std::to_string(vault_.get_entries().size()) + " entries to " + path)) {
            print_info("Cancelled");
            press_enter_to_continue();
            return;
        }
        
        bool success = false;
        if (format == "2") {
            success = vault_.export_csv(path);
        } else {
            success = vault_.export_json(path);
        }
        
        std::cout << "\n";
        if (success) {
            print_success("Exported to: " + path);
            print_info("Remember to securely delete this file when done!");
        } else {
            print_error("Export failed: " + vault_.get_last_error());
        }
        
        press_enter_to_continue();
    }
    
    void import_vault() {
        clear_screen();
        std::cout << TITLE << "  IMPORT FROM FILE\n" << RESET;
        print_separator();
        
        std::cout << MENU_NUM << "[1] " << MENU_TEXT << "Import from JSON\n" << RESET;
        std::cout << MENU_NUM << "[2] " << MENU_TEXT << "Import from CSV\n" << RESET;
        std::cout << MENU_NUM << "[0] " << MENU_TEXT << "Cancel\n" << RESET;
        
        std::string format = read_line("Choose format", "1");
        if (format == "0") return;
        
        std::string default_file = (format == "2") ? "passwords.csv" : "passwords.json";
        std::string path = read_line("Input file", default_file);
        
        bool overwrite = confirm("Overwrite existing entries with same name");
        
        std::cout << "\n";
        
        int imported = -1;
        if (format == "2") {
            imported = vault_.import_csv(path, overwrite);
        } else {
            imported = vault_.import_json(path, overwrite);
        }
        
        if (imported >= 0) {
            print_success("Imported " + std::to_string(imported) + " entries");
        } else {
            print_error("Import failed: " + vault_.get_last_error());
        }
        
        press_enter_to_continue();
    }
    
    void set_auto_lock_timeout() {
        clear_screen();
        std::cout << TITLE << "  AUTO-LOCK TIMEOUT\n" << RESET;
        print_separator();
        
        std::cout << INFO << "Current setting: ";
        if (auto_lock_timeout_ > 0) {
            std::cout << auto_lock_timeout_ / 60 << " minutes (" << auto_lock_timeout_ << " seconds)\n";
        } else {
            std::cout << "Disabled\n";
        }
        std::cout << RESET << "\n";
        
        std::cout << DIM_TEXT << "The vault will automatically lock after this period of inactivity.\n";
        std::cout << "Enter 0 to disable auto-lock.\n\n" << RESET;
        
        std::string input = read_line("Timeout in minutes", std::to_string(auto_lock_timeout_ / 60));
        
        try {
            int minutes = std::stoi(input);
            if (minutes < 0) {
                print_error("Invalid timeout value");
            } else if (minutes == 0) {
                auto_lock_timeout_ = 0;
                print_success("Auto-lock disabled");
            } else {
                auto_lock_timeout_ = minutes * 60;
                print_success("Auto-lock set to " + std::to_string(minutes) + " minutes");
            }
        } catch (...) {
            print_error("Invalid number");
        }
        
        press_enter_to_continue();
    }
    
    void set_vault_directory() {
        clear_screen();
        std::cout << TITLE << "  VAULT DIRECTORY\n" << RESET;
        print_separator();
        
        std::cout << INFO << "Current directory: " << vault_.get_directory() << "\n" << RESET;
        std::cout << INFO << "Vault file: " << vault_.get_path() << "\n\n" << RESET;
        
        std::cout << DIM_TEXT << "The vault file (.pw_vault) and keyfile are stored in this directory.\n";
        std::cout << "By default, this is the directory where the application is located.\n\n" << RESET;
        
        std::cout << WARNING << "Warning: Changing the directory will NOT move existing files.\n";
        std::cout << "You need to manually move .pw_vault and keyfile to the new location.\n\n" << RESET;
        
        std::string new_dir = read_line("New directory (or Enter to keep current)", vault_.get_directory());
        
        if (new_dir != vault_.get_directory()) {
            // Sprawdź czy katalog istnieje
            std::ifstream test(new_dir + "/.");
            if (!test.good()) {
                print_error("Directory does not exist: " + new_dir);
                press_enter_to_continue();
                return;
            }
            
            vault_.set_directory(new_dir);
            print_success("Vault directory changed to: " + new_dir);
            print_info("New vault path: " + vault_.get_path());
            
            // Sprawdź czy vault istnieje w nowej lokalizacji
            if (!vault_.exists()) {
                print_info("No vault found in the new directory.");
                print_info("You need to create a new vault or move your existing .pw_vault file there.");
            }
        } else {
            print_info("Directory unchanged");
        }
        
        press_enter_to_continue();
    }
    
    // ========================================================================
    // Duress Password (Hasło Paniki) - UI
    // ========================================================================
    
    void duress_password_menu() {
        clear_screen();
        std::cout << TITLE << "  DURESS PASSWORD (PANIC PASSWORD)\n" << RESET;
        print_separator();
        
        std::cout << WARNING << R"(
  IMPORTANT SECURITY FEATURE
  
  When you enter the duress password instead of your master password:
  
  1. All vault data will be PERMANENTLY DESTROYED
  2. The vault file will be securely wiped (3-pass overwrite)
  3. The keyfile will be deleted (if configured)
  4. A fake "corrupted" vault will be created
  5. Optionally: the application itself will be deleted
  
  The attacker will see: "Vault file is corrupted"
  
  THIS ACTION IS IRREVERSIBLE. Use only in genuine emergencies.
)" << RESET << "\n";
        
        if (vault_.has_duress_password()) {
            std::cout << SUCCESS << "  Status: ENABLED\n" << RESET;
            std::cout << INFO << "  Delete app on trigger: " 
                      << (vault_.get_duress_delete_app() ? "YES" : "NO") << "\n\n" << RESET;
            
            std::cout << MENU_NUM << "  [1] " << MENU_TEXT << "Change duress password\n" << RESET;
            std::cout << MENU_NUM << "  [2] " << MENU_TEXT << "Toggle 'delete app' option\n" << RESET;
            std::cout << MENU_NUM << "  [3] " << MENU_TEXT << "Remove duress password\n" << RESET;
            std::cout << MENU_NUM << "  [0] " << MENU_TEXT << "Back\n" << RESET;
            
            std::cout << "\n";
            std::string choice = read_line("Choice");
            
            if (choice == "1") set_duress_password_screen();
            else if (choice == "2") toggle_duress_delete_app();
            else if (choice == "3") remove_duress_password_screen();
        } else {
            std::cout << DIM_TEXT << "  Status: DISABLED\n\n" << RESET;
            
            std::cout << MENU_NUM << "  [1] " << MENU_TEXT << "Enable duress password\n" << RESET;
            std::cout << MENU_NUM << "  [0] " << MENU_TEXT << "Back\n" << RESET;
            
            std::cout << "\n";
            std::string choice = read_line("Choice");
            if (choice == "1") set_duress_password_screen();
        }
    }
    
    void set_duress_password_screen() {
        clear_screen();
        std::cout << TITLE << "  SET DURESS PASSWORD\n" << RESET;
        print_separator();
        
        std::cout << WARNING << "Remember: This password will DESTROY all your data when used!\n\n" << RESET;
        
        auto master_pwd = read_password("Enter current master password: ");
        
        // Weryfikacja - próbuj otworzyć ponownie żeby sprawdzić hasło
        // (vault jest już otwarty więc to tylko weryfikacja)
        
        std::cout << "\n";
        auto duress_pwd = read_password("Enter new duress password: ");
        auto confirm_pwd = read_password("Confirm duress password: ");
        
        if (!duress_pwd.equals(confirm_pwd)) {
            print_error("Passwords do not match");
            press_enter_to_continue();
            return;
        }
        
        if (duress_pwd.size() < 4) {
            print_error("Duress password must be at least 4 characters");
            press_enter_to_continue();
            return;
        }
        
        // Sprawdzenie czy nie jest takie samo jak master jest w vault_.set_duress_password()
        
        bool delete_app = confirm("Delete application when duress password is used");
        
        std::cout << "\n";
        std::cout << WARNING << "Final confirmation:\n" << RESET;
        std::cout << INFO << "  - Duress password will be set\n" << RESET;
        std::cout << INFO << "  - Delete app on trigger: " << (delete_app ? "YES" : "NO") << "\n" << RESET;
        
        if (!confirm("Proceed with setting duress password")) {
            print_info("Cancelled");
            press_enter_to_continue();
            return;
        }
        
        if (vault_.set_duress_password(master_pwd, duress_pwd, delete_app)) {
            print_success("Duress password configured!");
            print_info("Remember: entering this password at login will DESTROY all data.");
        } else {
            print_error(vault_.get_last_error());
        }
        
        press_enter_to_continue();
    }
    
    void toggle_duress_delete_app() {
        bool current = vault_.get_duress_delete_app();
        bool new_value = !current;
        
        std::cout << "\n";
        if (new_value) {
            std::cout << WARNING << "WARNING: Enabling this option will DELETE the application\n";
            std::cout << "when the duress password is used!\n\n" << RESET;
        }
        
        std::string msg = new_value ? 
            "Enable 'delete app' option" : 
            "Disable 'delete app' option";
        
        if (!confirm(msg)) {
            print_info("Cancelled");
            press_enter_to_continue();
            return;
        }
        
        auto master_pwd = read_password("Enter master password to confirm: ");
        
        if (vault_.set_duress_delete_app(master_pwd, new_value)) {
            if (new_value) {
                print_success("'Delete app' option ENABLED");
                print_info("The application will be deleted when duress password is used.");
            } else {
                print_success("'Delete app' option DISABLED");
                print_info("Only vault data will be destroyed.");
            }
        } else {
            print_error(vault_.get_last_error());
        }
        
        press_enter_to_continue();
    }
    
    void remove_duress_password_screen() {
        std::cout << "\n";
        std::cout << INFO << "This will remove the duress password protection.\n" << RESET;
        
        if (!confirm("Remove duress password")) {
            print_info("Cancelled");
            press_enter_to_continue();
            return;
        }
        
        auto master_pwd = read_password("Enter master password to confirm: ");
        
        if (vault_.remove_duress_password(master_pwd)) {
            print_success("Duress password removed");
        } else {
            print_error(vault_.get_last_error());
        }
        
        press_enter_to_continue();
    }
};

} // namespace pw

// ============================================================================
// Main entry point
// ============================================================================

int main() {
    pw::App app;
    app.run();
    return 0;
}
