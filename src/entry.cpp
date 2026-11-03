#include "entry.hpp"
#include <sodium.h>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace pw {

std::string generate_uuid() {
    unsigned char uuid_bytes[16];
    randombytes_buf(uuid_bytes, sizeof(uuid_bytes));
    
    // Set version 4
    uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40;
    // Set variant
    uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80;
    
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            ss << '-';
        }
        ss << std::setw(2) << static_cast<int>(uuid_bytes[i]);
    }
    
    return ss.str();
}

int64_t current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
}

} // namespace pw
