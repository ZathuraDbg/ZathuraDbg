cmake_minimum_required(VERSION 3.15)
project(icicle-cpp LANGUAGES C)

set(CARGO_MANIFEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/Cargo.toml")

# Resolve the target directory the same way cargo does.
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(CARGO_BUILD_FLAGS "")
    set(CARGO_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/target/debug")
else()
    set(CARGO_BUILD_FLAGS "--release")
    set(CARGO_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/target/release")
endif()

# Optional: set a cargo target triple for cross-compilation.
if(DEFINED CARGO_TARGET_TRIPLE)
    set(CARGO_TARGET_FLAGS "--target=${CARGO_TARGET_TRIPLE}")
    set(CARGO_TARGET_DIR "${CARGO_TARGET_DIR}/${CARGO_TARGET_TRIPLE}")
endif()

set(ICICLE_LIB "${CARGO_TARGET_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}icicle${CMAKE_STATIC_LIBRARY_SUFFIX}")

add_custom_command(
    OUTPUT  "${ICICLE_LIB}"
    COMMAND cargo build ${CARGO_BUILD_FLAGS} ${CARGO_TARGET_FLAGS} --manifest-path "${CARGO_MANIFEST_PATH}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Building icicle (Rust -> static library)"
    VERBATIM
)

add_custom_target(icicle_build DEPENDS "${ICICLE_LIB}")

add_library(icicle STATIC IMPORTED GLOBAL)
set_target_properties(icicle PROPERTIES
    IMPORTED_LOCATION             "${ICICLE_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}"
)
add_dependencies(icicle icicle_build)

# Platform-specific link dependencies.
if(WIN32)
    set(ICICLE_PLATFORM_LIBS ws2_32.lib Userenv.lib ntdll.lib Bcrypt.lib)
    set_target_properties(icicle PROPERTIES
        INTERFACE_LINK_LIBRARIES "${ICICLE_PLATFORM_LIBS}"
    )
endif()
