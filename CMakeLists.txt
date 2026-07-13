cmake_minimum_required(VERSION 3.10)
project(pixiewps C)

# Set C standard to C99 with POSIX extensions
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS_INIT "-Wall -Wextra -Wno-unused-parameter -Wstrict-prototypes -D_POSIX_C_SOURCE=200809L")

# Compiler flag compatibility checks
include(CheckCCompilerFlag)
function(try_add_c_flag flag target_var)
    string(REGEX REPLACE "[^A-Za-z0-9]" "_" flag_var "${flag}")
    check_c_compiler_flag("${flag}" "HAVE_FLAG_${flag_var}")
    if(HAVE_FLAG_${flag_var})
        set(${target_var} "${${target_var}} ${flag}" PARENT_SCOPE)
    endif()
endfunction()

# Detect the target architecture
string(TOLOWER ${CMAKE_SYSTEM_PROCESSOR} ARCH)

# === ENHANCED ARM ARCHITECTURE DETECTION ===
# Optimized for modern mobile CPUs found in Termux
if(ARCH MATCHES "aarch64|arm64|armv8")
    message(STATUS "Detected: ARMv8-A (64-bit) - Snapdragon/Exynos/MediaTek optimized")
    # Check if this is Apple (M1/M2) or actual ARM hardware
    if(APPLE)
        set(ARM_FLAGS "-march=armv8-a")
        set(EXTRA_FLAGS "-falign-loops=32 -falign-functions=32")
        message(STATUS "Apple Silicon detected - using native flags")
    else()
        # Real ARM hardware (Termux, Linux ARM servers)
        # NOTE: ARM64 does NOT support -mfpu and -mfloat-abi (32-bit only)
        set(ARM_FLAGS "-march=armv8-a+crc -mtune=cortex-a53")
        set(EXTRA_FLAGS "-falign-loops=32 -falign-functions=32")
    endif()
    
elseif(ARCH MATCHES "armv7|armv7l|armhf|arm32")
    message(STATUS "Detected: ARMv7-A (32-bit) - Older high-end devices optimized")
    # ARMv7-A with NEON for mobile phones
    if(APPLE)
        set(ARM_FLAGS "-march=armv7-a")
        set(EXTRA_FLAGS "-falign-loops=16 -falign-functions=16")
    else()
        set(ARM_FLAGS "-march=armv7-a -mtune=cortex-a9 -mfpu=neon")
        set(ARM_FLAGS "${ARM_FLAGS} -mfloat-abi=softfp -mfp16-format=ieee")
        set(EXTRA_FLAGS "-falign-loops=16 -falign-functions=16")
    endif()
    
elseif(ARCH MATCHES "armv6|arm11")
    message(STATUS "Detected: ARMv6 (32-bit) - Raspberry Pi & older devices")
    # Older ARMv6 with VFP
    set(ARM_FLAGS "-march=armv6 -mtune=arm1176jzf-s -mfpu=vfp")
    set(ARM_FLAGS "${ARM_FLAGS} -mfloat-abi=hard")
    set(EXTRA_FLAGS "-falign-loops=16 -falign-functions=16")
    
else()
    message(STATUS "Building with native architecture optimizations")
    set(ARM_FLAGS "-march=native -mtune=native")
    set(EXTRA_FLAGS "-falign-loops=32 -falign-functions=32")
endif()

# === AGGRESSIVE OPTIMIZATION FLAGS ===
# Geared for CPU-bound cryptography operations
# Use compiler detection to avoid unsupported flags on Clang

if(CMAKE_C_COMPILER_ID MATCHES "GNU|GCC")
    # GCC-specific optimizations (for full Linux/Termux build)
    set(OPT_FLAGS "-O3 -funroll-loops")
    set(OPT_FLAGS "${OPT_FLAGS} -funroll-all-loops")
    try_add_c_flag("-fweb" OPT_FLAGS)
    try_add_c_flag("-frename-registers" OPT_FLAGS)
    try_add_c_flag("-fmerge-all-constants" OPT_FLAGS)
    try_add_c_flag("-fgcse" OPT_FLAGS)
    try_add_c_flag("-fgcse-sm" OPT_FLAGS)
    try_add_c_flag("-fgcse-las" OPT_FLAGS)
    try_add_c_flag("-fipa-pta" OPT_FLAGS)
    try_add_c_flag("-ftree-loop-distribution" OPT_FLAGS)
    try_add_c_flag("-ftree-vect-loop-version" OPT_FLAGS)
    try_add_c_flag("-ftree-vectorize" OPT_FLAGS)
    try_add_c_flag("-finline-small-functions" OPT_FLAGS)
    try_add_c_flag("-fno-limit-inline-depth" OPT_FLAGS)
    try_add_c_flag("--param inline-unit-growth=300" OPT_FLAGS)
    try_add_c_flag("--param large-function-growth=1000" OPT_FLAGS)
    try_add_c_flag("--param max-inline-insns-single=10000" OPT_FLAGS)
    try_add_c_flag("--param max-inline-insns-auto=10000" OPT_FLAGS)
    try_add_c_flag("--param ipcp-unit-growth=1000" OPT_FLAGS)
    message(STATUS "Using GCC-specific optimizations")
else()
    # Clang/Apple Clang compatible optimizations
    set(OPT_FLAGS "-O3 -funroll-loops")
    set(OPT_FLAGS "${OPT_FLAGS} -fmerge-all-constants")
    set(OPT_FLAGS "${OPT_FLAGS} -ftree-vectorize")
    set(OPT_FLAGS "${OPT_FLAGS} -finline-functions")
    message(STATUS "Using Clang-compatible optimizations")
endif()

# Universal optimizations (GCC and Clang)
set(OPT_FLAGS "${OPT_FLAGS} -finline-functions")
set(OPT_FLAGS "${OPT_FLAGS} -fno-common")
set(OPT_FLAGS "${OPT_FLAGS} -fomit-frame-pointer")

# Combine all compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OPT_FLAGS} ${ARM_FLAGS} ${EXTRA_FLAGS}")


# Default to Release build with aggressive optimizations
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Release flags
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG "-g3 -D_DEBUG")

# === PLATFORM DETECTION ===
if(ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "Building for Linux/Android/Termux")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
endif()

# === DEPENDENCY DETECTION ===
# Threads are usually built-in on modern systems
if(APPLE OR ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # macOS, Android, Termux, Linux: pthread is built-in
    find_package(Threads QUIET)
    if(NOT Threads_FOUND)
        set(CMAKE_THREAD_LIBS_INIT "-lpthread")
        set(CMAKE_HAVE_THREADS_LIBRARY 1)
        set(Threads_FOUND TRUE)
    endif()
else()
    find_package(Threads REQUIRED)
endif()

message(STATUS "Using threading library: ${CMAKE_THREAD_LIBS_INIT}")

# === OPTIONAL FEATURES ===

# OpenSSL: Use system SHA-256 for potential speed boost
option(USE_OPENSSL "Use OpenSSL for SHA-256 acceleration" OFF)
if(USE_OPENSSL)
    find_package(OpenSSL QUIET)
    if(OPENSSL_FOUND)
        message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
        set(HAVE_OPENSSL TRUE)
    else()
        message(WARNING "OpenSSL requested but not found, using built-in crypto")
        set(USE_OPENSSL OFF)
    endif()
else()
    message(STATUS "Using built-in cryptography (no OpenSSL)")
endif()

# OpenMP: Parallel processing (careful on low-RAM Termux)
option(ENABLE_OPENMP "Enable OpenMP for parallel HMAC operations" OFF)
if(ENABLE_OPENMP)
    find_package(OpenMP QUIET)
    if(OpenMP_C_FOUND)
        message(STATUS "OpenMP enabled for thread-level parallelism")
    else()
        message(STATUS "OpenMP not found, continuing without it")
    endif()
else()
    message(STATUS "OpenMP disabled (recommended for low-RAM Termux)")
endif()

# Debug/Profiling: Optional profiling support
option(ENABLE_DEBUG "Build with debug symbols (-g)" OFF)
option(ENABLE_PROFILING "Build with profiling support (-pg)" OFF)

if(ENABLE_DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g3")
    message(STATUS "Debug symbols enabled")
else()
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s")
    message(STATUS "Binary stripping enabled (Release mode)")
endif()

if(ENABLE_PROFILING)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pg -fprofile-arcs")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pg")
    message(STATUS "Profiling support enabled")
endif()

# LTO (Link-Time Optimization): For better optimization
option(ENABLE_LTO "Enable Link-Time Optimization" OFF)
if(ENABLE_LTO)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto -fuse-linker-plugin")
        message(STATUS "LTO (Link-Time Optimization) enabled")
    else()
        message(WARNING "LTO not supported by this compiler")
    endif()
endif()

# === INSTALLATION PREFIX (Termux-compatible) ===
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    if(DEFINED ENV{TERMUX_PREFIX})
        set(CMAKE_INSTALL_PREFIX $ENV{TERMUX_PREFIX})
        message(STATUS "Using Termux PREFIX from env: ${CMAKE_INSTALL_PREFIX}")
    elseif(ANDROID OR EXISTS "/data/data/com.termux/files")
        # Termux Android detection by filesystem
        if(DEFINED ENV{PREFIX})
            set(CMAKE_INSTALL_PREFIX $ENV{PREFIX})
        else()
            set(CMAKE_INSTALL_PREFIX "/data/data/com.termux/files/usr")
        endif()
        message(STATUS "Using Android/Termux PREFIX: ${CMAKE_INSTALL_PREFIX}")
    elseif(EXISTS "/system/build.prop" OR EXISTS "/data/system/")
        # More robust Termux detection
        if(DEFINED ENV{PREFIX})
            set(CMAKE_INSTALL_PREFIX $ENV{PREFIX})
        else()
            set(CMAKE_INSTALL_PREFIX "/data/data/com.termux/files/usr")
        endif()
        message(STATUS "Detected Termux environment, using: ${CMAKE_INSTALL_PREFIX}")
    else()
        set(CMAKE_INSTALL_PREFIX "/usr/local")
        message(STATUS "Standard Linux/macOS installation to: ${CMAKE_INSTALL_PREFIX}")
    endif()
endif()

# === SOURCE FILES ===

# Main pixiewps source
set(PIXIEWPS_SOURCES
    src/pixiewps.c
)

# New extended framework modules
set(FRAMEWORK_SOURCES
    src/pixiewps_modules.c
    src/wifi_scanner.c
)

# Header files for reference
set(PIXIEWPS_HEADERS
    src/config.h
    src/endianness.h
    src/version.h
    src/pixiewps.h
    src/utils.h
    src/wps.h
    src/pixiewps_extended.h
)

# Extended framework headers (new modules)
set(FRAMEWORK_HEADERS
    src/wifi_scanner.h
    src/client_recon.h
    src/monitor_mode.h
    src/adapter_intel.h
    src/packet_injection.h
    src/wps_engine.h
    src/pmkid_capture.h
    src/handshake_capture.h
    src/wpa3_handler.h
    src/target_priority.h
    src/router_prng.h
    src/wps_protocol.h
)

# Tom's Fast Math (TFM) - Big integer operations
file(GLOB TFM_SOURCES "src/crypto/tfm/*.c")
message(STATUS "Including TFM sources for cryptography")

# Tiny Crypt (tc) - AES operations
set(TC_SOURCES
    src/crypto/tc/aes.c
    src/crypto/tc/aes_cbc.c
)

# HMAC-SHA256 and key derivation
set(HMAC_SOURCES
    src/crypto/hmac_sha256.c
    src/crypto/crypto_internal-modexp.c
)

# Random number generation sources
set(RANDOM_SOURCES
    src/random/glibc_random_yura.c
)

# === CREATE EXECUTABLE ===
# Note: pixiewps.c includes crypto files directly, so don't compile them separately
add_executable(pixiewps 
    ${PIXIEWPS_SOURCES}
    ${FRAMEWORK_SOURCES}
    ${TFM_SOURCES}
    ${TC_SOURCES}
    ${RANDOM_SOURCES}
)

# === TARGET PROPERTIES ===
set_target_properties(pixiewps PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    VERSION 1.2
    DESCRIPTION "WPS PIN cracker with ARM optimization for Termux"
)

# === INCLUDE DIRECTORIES ===
target_include_directories(pixiewps PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/tc
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/tfm
)

# === LINK LIBRARIES ===
target_link_libraries(pixiewps PRIVATE
    m
)

# Link threads
# Always use CMAKE_THREAD_LIBS_INIT for compatibility (works with Termux/Android)
if(CMAKE_THREAD_LIBS_INIT)
    target_link_libraries(pixiewps PRIVATE "${CMAKE_THREAD_LIBS_INIT}")
endif()

# OpenSSL if available
if(HAVE_OPENSSL)
    target_link_libraries(pixiewps PRIVATE OpenSSL::Crypto)
    target_compile_definitions(pixiewps PRIVATE USE_OPENSSL)
endif()

# OpenMP if available
if(OpenMP_C_FOUND)
    target_link_libraries(pixiewps PRIVATE OpenMP::OpenMP_C)
    target_compile_definitions(pixiewps PRIVATE ENABLE_OPENMP)
endif()

# === INSTALLATION ===
install(TARGETS pixiewps
    RUNTIME DESTINATION bin
    COMPONENT executable
)

# Install man page if available
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/pixiewps.1")
    install(FILES pixiewps.1
        DESTINATION share/man/man1
        COMPONENT documentation
    )
endif()

# === BUILD INFORMATION ===
message(STATUS "")
message(STATUS "╔════════════════════════════════════════════════════╗")
message(STATUS "║      Pixiewps Build Configuration (Enhanced)       ║")
message(STATUS "╠════════════════════════════════════════════════════╣")
message(STATUS "║ Architecture:        ${ARCH}")
message(STATUS "║ Build Type:          ${CMAKE_BUILD_TYPE}")
message(STATUS "║ C Compiler:          ${CMAKE_C_COMPILER}")
message(STATUS "║ C Compiler Flags:    ${CMAKE_C_FLAGS}")
message(STATUS "║ Install Prefix:      ${CMAKE_INSTALL_PREFIX}")
message(STATUS "║ OpenSSL Support:     ${HAVE_OPENSSL}")
message(STATUS "║ OpenMP Support:      ${OpenMP_C_FOUND}")
message(STATUS "║ Debug Symbols:       ${ENABLE_DEBUG}")
message(STATUS "║ Profiling:           ${ENABLE_PROFILING}")
message(STATUS "║ LTO Enabled:         ${ENABLE_LTO}")
message(STATUS "╚════════════════════════════════════════════════════╝")
message(STATUS "")
message(STATUS "Router modes supported (Legacy):")
message(STATUS "  1. RT/MT/CL (Ralink)")
message(STATUS "  2. eCos simple")
message(STATUS "  3. RTL819x (Realtek)")
message(STATUS "  4. eCos simplest")
message(STATUS "  5. eCos Knuth")
message(STATUS "")
message(STATUS "Router modes supported (2020-2024):")
message(STATUS "  6. MediaTek MT7620/7628")
message(STATUS "  7. Realtek RTL8710")
message(STATUS "  8. TP-Link Classic")
message(STATUS "  9. D-Link Enhanced")
message(STATUS "  10. Broadcom BCM")
message(STATUS "")
message(STATUS "Router modes supported (2025-2026 Latest):")
message(STATUS "  11. MediaTek Filogic MT7986/MT7988 (WiFi 6E/7)")
message(STATUS "  12. Qualcomm IPQ9574/IPQ5332 (WiFi 6E/7)")
message(STATUS "  13. Realtek RTL8720D/RTL8721D (WiFi 6E)")
message(STATUS "  14. TP-Link Archer AX/AXE/BE (WPA3 optimized)")
message(STATUS "  15. Tenda Modern AC/AX (Qualcomm base)")
message(STATUS "  16. Netgear RAXE500/RAXE520 (WiFi 6E)")
message(STATUS "  17. ARM Cortex-A73/A72 Generic (WiFi 6)")
message(STATUS "  18. Ubiquiti WiFi 6 Pro")
message(STATUS "  19. Synology MeshTalk")
message(STATUS "  20. Generic WPA3/OFDMA")
message(STATUS "")
message(STATUS "Build with: cmake --build . --config Release")
message(STATUS "Install with: cmake --install . --component executable")
message(STATUS "")
