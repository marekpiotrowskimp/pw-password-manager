#include "clipboard.hpp"

#ifdef _WIN32
#include <windows.h>
#include <thread>
#include <chrono>
#endif

namespace pw {

bool clipboard_copy(const std::string& text) {
#ifdef _WIN32
    if (!OpenClipboard(nullptr)) {
        return false;
    }
    
    EmptyClipboard();
    
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (!hMem) {
        CloseClipboard();
        return false;
    }
    
    char* pMem = static_cast<char*>(GlobalLock(hMem));
    if (!pMem) {
        GlobalFree(hMem);
        CloseClipboard();
        return false;
    }
    
    memcpy(pMem, text.c_str(), text.size());
    pMem[text.size()] = '\0';
    
    GlobalUnlock(hMem);
    SetClipboardData(CF_TEXT, hMem);
    CloseClipboard();
    
    return true;
#else
    (void)text;
    return false;
#endif
}

bool clipboard_clear() {
#ifdef _WIN32
    if (!OpenClipboard(nullptr)) {
        return false;
    }
    EmptyClipboard();
    CloseClipboard();
    return true;
#else
    return false;
#endif
}

bool clipboard_copy_with_timeout(const std::string& text, int timeout_seconds) {
#ifdef _WIN32
    if (!clipboard_copy(text)) {
        return false;
    }
    
    if (timeout_seconds > 0) {
        std::thread cleaner([timeout_seconds]() {
            std::this_thread::sleep_for(std::chrono::seconds(timeout_seconds));
            clipboard_clear();
        });
        cleaner.detach();
    }
    
    return true;
#else
    (void)text;
    (void)timeout_seconds;
    return false;
#endif
}

} // namespace pw
