#include "clipboard.hpp"
#include <cstdlib>
#include <thread>
#include <chrono>

#ifdef __APPLE__
#include <ApplicationServices/ApplicationServices.h>
#endif

namespace pw {

bool clipboard_copy(const std::string& text) {
#ifdef __APPLE__
    // Użyj pbcopy przez popen
    FILE* pipe = popen("pbcopy", "w");
    if (!pipe) {
        return false;
    }
    fwrite(text.c_str(), 1, text.size(), pipe);
    pclose(pipe);
    return true;
#else
    return false;
#endif
}

bool clipboard_clear() {
#ifdef __APPLE__
    // Wyczyść schowek przez pbcopy z pustym stringiem
    FILE* pipe = popen("pbcopy", "w");
    if (!pipe) {
        return false;
    }
    pclose(pipe);
    return true;
#else
    return false;
#endif
}

bool clipboard_copy_with_timeout(const std::string& text, int timeout_seconds) {
    if (!clipboard_copy(text)) {
        return false;
    }
    
    if (timeout_seconds > 0) {
        // Uruchom wątek czyszczący w tle
        std::thread cleaner([timeout_seconds]() {
            std::this_thread::sleep_for(std::chrono::seconds(timeout_seconds));
            clipboard_clear();
        });
        cleaner.detach();
    }
    
    return true;
}

} // namespace pw
