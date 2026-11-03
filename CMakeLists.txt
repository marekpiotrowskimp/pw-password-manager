cmake_minimum_required(VERSION 3.16)
project(pw VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Detect cross-compilation for Windows
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(CROSS_COMPILING_WINDOWS TRUE)
    message(STATUS "Cross-compiling for Windows")
else()
    set(CROSS_COMPILING_WINDOWS FALSE)
endif()

# ============================================================================
# Find libsodium
# ============================================================================
if(CROSS_COMPILING_WINDOWS)
    # For Windows cross-compilation, use pre-built libsodium
    set(SODIUM_WIN_DIR "${CMAKE_SOURCE_DIR}/deps/libsodium-win64")
    if(EXISTS "${SODIUM_WIN_DIR}/lib/libsodium.a")
        set(SODIUM_INCLUDE_DIR "${SODIUM_WIN_DIR}/include")
        set(SODIUM_LIBRARY "${SODIUM_WIN_DIR}/lib/libsodium.a")
        set(SODIUM_FOUND TRUE)
        message(STATUS "Found Windows libsodium: ${SODIUM_LIBRARY}")
    else()
        message(FATAL_ERROR "Windows libsodium not found. Build it first with:\n  cd deps/libsodium-stable && ./configure --host=x86_64-w64-mingw32 --prefix=../libsodium-win64 --enable-static --disable-shared && make && make install")
    endif()
else()
    # Native build - try pkg-config first
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(SODIUM IMPORTED_TARGET libsodium)
    endif()

    if(NOT SODIUM_FOUND)
        # Fallback: find manually
        find_path(SODIUM_INCLUDE_DIR sodium.h
            HINTS /opt/homebrew/include /usr/local/include /usr/include
        )
        find_library(SODIUM_LIBRARY sodium
            HINTS /opt/homebrew/lib /usr/local/lib /usr/lib
        )
        if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
            set(SODIUM_FOUND TRUE)
            message(STATUS "Found libsodium: ${SODIUM_LIBRARY}")
        endif()
    endif()

    if(NOT SODIUM_FOUND)
        message(FATAL_ERROR "libsodium not found. Install with: brew install libsodium")
    endif()
endif()

# ============================================================================
# Find nlohmann_json (header-only, use bundled if not found)
# ============================================================================
find_package(nlohmann_json CONFIG QUIET)
if(NOT nlohmann_json_FOUND)
    # Download nlohmann_json header
    if(NOT EXISTS "${CMAKE_SOURCE_DIR}/deps/nlohmann/json.hpp")
        message(STATUS "Downloading nlohmann/json.hpp...")
        file(DOWNLOAD 
            "https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp"
            "${CMAKE_SOURCE_DIR}/deps/nlohmann/json.hpp"
            STATUS DOWNLOAD_STATUS
        )
        list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
        if(NOT STATUS_CODE EQUAL 0)
            message(FATAL_ERROR "Failed to download nlohmann/json.hpp")
        endif()
    endif()
    set(NLOHMANN_JSON_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/deps")
    message(STATUS "Using bundled nlohmann_json from ${NLOHMANN_JSON_INCLUDE_DIR}")
endif()

# ============================================================================
# Main library
# ============================================================================
add_library(pw_lib STATIC
    src/crypto.cpp
    src/vault.cpp
    src/entry.cpp
    src/generator.cpp
    src/clipboard.cpp
)

target_include_directories(pw_lib PUBLIC ${CMAKE_SOURCE_DIR}/include)

# Link sodium
if(TARGET PkgConfig::SODIUM)
    target_link_libraries(pw_lib PUBLIC PkgConfig::SODIUM)
else()
    target_include_directories(pw_lib PUBLIC ${SODIUM_INCLUDE_DIR})
    target_link_libraries(pw_lib PUBLIC ${SODIUM_LIBRARY})
endif()

# Link nlohmann_json
if(nlohmann_json_FOUND)
    target_link_libraries(pw_lib PUBLIC nlohmann_json::nlohmann_json)
else()
    target_include_directories(pw_lib PUBLIC ${NLOHMANN_JSON_INCLUDE_DIR})
endif()

# ============================================================================
# Platform-specific code
# ============================================================================
if(APPLE)
    target_sources(pw_lib PRIVATE src/clipboard_mac.cpp)
    target_link_libraries(pw_lib PUBLIC "-framework AppKit")
elseif(WIN32 OR CROSS_COMPILING_WINDOWS)
    target_sources(pw_lib PRIVATE src/clipboard_win.cpp)
endif()

# ============================================================================
# Main executable
# ============================================================================
add_executable(pw src/main.cpp)
target_link_libraries(pw PRIVATE pw_lib)

# Static linking for Windows
if(CROSS_COMPILING_WINDOWS)
    # Static link everything for portable .exe
    target_link_options(pw PRIVATE -static -static-libgcc -static-libstdc++)
    # Set Windows subsystem to console
    target_link_options(pw PRIVATE -mconsole)
endif()

# ============================================================================
# Tests (only for native builds)
# ============================================================================
if(NOT CROSS_COMPILING_WINDOWS)
    find_package(GTest CONFIG QUIET)
    if(GTest_FOUND)
        enable_testing()
        add_executable(pw_tests
            tests/test_crypto.cpp
            tests/test_vault.cpp
            tests/test_generator.cpp
            tests/test_entry.cpp
        )
        target_link_libraries(pw_tests PRIVATE
            pw_lib
            GTest::gtest
            GTest::gtest_main
        )
        include(GoogleTest)
        gtest_discover_tests(pw_tests)
    else()
        message(STATUS "GTest not found, skipping tests")
    endif()
endif()

# ============================================================================
# Install
# ============================================================================
install(TARGETS pw DESTINATION bin)
