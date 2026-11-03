# CMake Toolchain File for MinGW-w64 cross-compilation
# Kompilacja Windows .exe na macOS

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# MinGW-w64 compiler paths (homebrew)
set(MINGW_PREFIX "x86_64-w64-mingw32")
set(MINGW_ROOT "/opt/homebrew/bin")

set(CMAKE_C_COMPILER "${MINGW_ROOT}/${MINGW_PREFIX}-gcc")
set(CMAKE_CXX_COMPILER "${MINGW_ROOT}/${MINGW_PREFIX}-g++")
set(CMAKE_RC_COMPILER "${MINGW_ROOT}/${MINGW_PREFIX}-windres")
set(CMAKE_AR "${MINGW_ROOT}/${MINGW_PREFIX}-ar")
set(CMAKE_RANLIB "${MINGW_ROOT}/${MINGW_PREFIX}-ranlib")

# Target environment
set(CMAKE_FIND_ROOT_PATH "/opt/homebrew/opt/mingw-w64/toolchain-x86_64")

# Search for programs in host, libraries and headers in target
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# Windows specific defines
add_definitions(-DWIN32 -D_WIN32 -D_WINDOWS)
add_definitions(-DSODIUM_STATIC)
