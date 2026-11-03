#!/bin/bash
# Build script for pw - portable password manager
# Builds both macOS native and Windows cross-compiled binaries

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() { echo -e "${GREEN}[*]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    echo "Usage: $0 [target]"
    echo ""
    echo "Targets:"
    echo "  macos    - Build native macOS binary"
    echo "  windows  - Cross-compile Windows .exe (requires mingw-w64)"
    echo "  all      - Build both (default)"
    echo "  clean    - Remove build directories"
    echo "  test     - Run tests (macOS only)"
    echo ""
    echo "Prerequisites:"
    echo "  macOS:   brew install libsodium"
    echo "  Windows: brew install mingw-w64 (for cross-compilation)"
    echo ""
}

check_macos_deps() {
    if ! command -v cmake &> /dev/null; then
        print_error "cmake not found. Install with: brew install cmake"
        exit 1
    fi
    
    if ! pkg-config --exists libsodium 2>/dev/null; then
        if [ ! -f /opt/homebrew/lib/libsodium.a ] && [ ! -f /usr/local/lib/libsodium.a ]; then
            print_error "libsodium not found. Install with: brew install libsodium"
            exit 1
        fi
    fi
}

check_windows_deps() {
    if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        print_error "mingw-w64 not found. Install with: brew install mingw-w64"
        exit 1
    fi
    
    if [ ! -f "$SCRIPT_DIR/deps/libsodium-win64/lib/libsodium.a" ]; then
        print_warning "Windows libsodium not found. Building from source..."
        build_libsodium_windows
    fi
}

build_libsodium_windows() {
    print_status "Building libsodium for Windows..."
    
    SODIUM_VERSION="1.0.20"
    SODIUM_DIR="$SCRIPT_DIR/deps/libsodium-stable"
    SODIUM_INSTALL="$SCRIPT_DIR/deps/libsodium-win64"
    
    # Download if not present
    if [ ! -d "$SODIUM_DIR" ]; then
        print_status "Downloading libsodium ${SODIUM_VERSION}..."
        cd "$SCRIPT_DIR/deps"
        curl -L "https://download.libsodium.org/libsodium/releases/libsodium-${SODIUM_VERSION}-stable.tar.gz" -o libsodium.tar.gz
        tar xzf libsodium.tar.gz
        mv libsodium-stable libsodium-stable || true
        rm libsodium.tar.gz
    fi
    
    cd "$SODIUM_DIR"
    
    # Clean previous build
    make clean 2>/dev/null || true
    
    # Configure for Windows cross-compilation
    ./configure \
        --host=x86_64-w64-mingw32 \
        --prefix="$SODIUM_INSTALL" \
        --enable-static \
        --disable-shared \
        --disable-pie
    
    # Build and install
    make -j$(sysctl -n hw.ncpu)
    make install
    
    print_status "Windows libsodium built successfully"
    cd "$SCRIPT_DIR"
}

build_macos() {
    print_status "Building macOS binary..."
    check_macos_deps
    
    BUILD_DIR="$SCRIPT_DIR/build"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH="$SCRIPT_DIR/vcpkg_installed/arm64-osx"
    
    make -j$(sysctl -n hw.ncpu) pw
    
    print_status "macOS build complete: $BUILD_DIR/pw"
    file "$BUILD_DIR/pw"
    ls -lh "$BUILD_DIR/pw"
}

build_windows() {
    print_status "Cross-compiling Windows binary..."
    check_windows_deps
    
    BUILD_DIR="$SCRIPT_DIR/build-win64"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE="$SCRIPT_DIR/cmake/toolchain-mingw64.cmake"
    
    make -j$(sysctl -n hw.ncpu) pw
    
    print_status "Windows build complete: $BUILD_DIR/pw.exe"
    file "$BUILD_DIR/pw.exe"
    ls -lh "$BUILD_DIR/pw.exe"
}

run_tests() {
    print_status "Running tests..."
    check_macos_deps
    
    BUILD_DIR="$SCRIPT_DIR/build"
    
    if [ ! -f "$BUILD_DIR/pw_tests" ]; then
        print_warning "Tests not built. Building now..."
        mkdir -p "$BUILD_DIR"
        cd "$BUILD_DIR"
        cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_PREFIX_PATH="$SCRIPT_DIR/vcpkg_installed/arm64-osx"
        make -j$(sysctl -n hw.ncpu) pw_tests
    fi
    
    cd "$BUILD_DIR"
    ./pw_tests
}

clean_builds() {
    print_status "Cleaning build directories..."
    rm -rf "$SCRIPT_DIR/build"
    rm -rf "$SCRIPT_DIR/build-win64"
    print_status "Clean complete"
}

# Main
case "${1:-all}" in
    macos)
        build_macos
        ;;
    windows)
        build_windows
        ;;
    all)
        build_macos
        echo ""
        build_windows
        echo ""
        print_status "All builds complete!"
        echo ""
        echo "Output files:"
        echo "  macOS:   build/pw"
        echo "  Windows: build-win64/pw.exe"
        echo ""
        echo "Copy both binaries + .pw_vault + .pw_keyfile to your USB drive."
        ;;
    clean)
        clean_builds
        ;;
    test)
        run_tests
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        print_error "Unknown target: $1"
        usage
        exit 1
        ;;
esac
