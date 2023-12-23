cmake_minimum_required(VERSION 3.15)
project(BEKMP)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-Wall -Wformat -O3 -g")

# Find required packages
find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONC REQUIRED json-c)

add_executable(BEKMP
        main.c
        BEKMP.c
        BEKMP.h
        sha.c
        sha.h
        local_sha2.c
        local_sha2.h
        params.h
        micro-ecc/types.h
        micro-ecc/uECC.h
        micro-ecc/uECC_vli.h
        )

# Compile definitions
target_compile_definitions(BEKMP PUBLIC  uECC_SUPPORTS_secp160r1=0
                                            uECC_SUPPORTS_secp192r1=1
                                            uECC_SUPPORTS_secp224r1=0
                                            uECC_SUPPORTS_secp256r1=0
                                            uECC_SUPPORTS_secp256k1=0
                                            uECC_SUPPORTS_OPENSSL=0)

# Link libraries
target_link_libraries(BEKMP PUBLIC ${CURL_LIBRARIES} ${JSONC_LIBRARIES} ssl crypto pthread m)

# Include directories
include_directories(${CURL_INCLUDE_DIRS} ${JSONC_INCLUDE_DIRS})

# Compile options
add_compile_options(${JSONC_CFLAGS_OTHER})
