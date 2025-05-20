cmake_minimum_required(VERSION 3.15)
project(Icicle)

# Add an include directory (equivalent to HEADER_ARG = -I../)
include_directories("../")

# Set math library flag based on OS
if(WIN32)
    message(STATUS "Configuring for Windows")
    set(MATH_LIB "")  # Windows may not need -lm
else()
    message(STATUS "Configuring for Unix-like OS")
    set(MATH_LIB m)
endif()

# Function to create an executable target with common settings
function(add_icicle_test target_name source_file lib_path)
    add_executable(${target_name} ${source_file})
    # Set the link options to use the provided library path and exact library name
    target_link_options(${target_name} PRIVATE -L${lib_path} -l:libicicle.a)
    target_link_libraries(${target_name} PRIVATE ${MATH_LIB})
    target_include_directories(${target_name} PRIVATE "../")
endfunction()

# Debug executables: using ICICLE_ARGS_DEBUG = -L../src/target/debug -l:libicicle.a
add_icicle_test(tests_debug tests.c "../src/target/debug")
add_icicle_test(hook_tests_debug hook_tests.c "../src/target/debug")
add_icicle_test(snapshot_tests_debug snapshot_tests.c "../src/target/debug")
add_icicle_test(archs archs.cpp "../src/target/debug")

# Release executables: using ICICLE_ARGS_RELEASE = -L../src/target/release -l:libicicle.a
add_icicle_test(tests_release tests.c "../src/target/release")
add_icicle_test(hook_tests_release hook_tests.c "../src/target/release")
add_icicle_test(snapshot_tests_release snapshot_tests.c "../src/target/release")

# Custom target to run debug tests (similar to the 'run' target)
add_custom_target(run
        COMMAND tests_debug
        COMMAND hook_tests_debug
        COMMAND snapshot_tests_debug
        DEPENDS tests_debug hook_tests_debug snapshot_tests_debug
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running debug tests..."
)

# Custom target to run release tests (similar to 'run-release')
add_custom_target(run_release
        COMMAND tests_release
        COMMAND hook_tests_release
        COMMAND snapshot_tests_release
        DEPENDS tests_release hook_tests_release snapshot_tests_release
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running release tests..."
)

# Custom target to run both debug and release tests (similar to 'run-all')
add_custom_target(run_all
        COMMAND tests_debug
        COMMAND hook_tests_debug
        COMMAND snapshot_tests_debug
        COMMAND ${CMAKE_COMMAND} -E echo "Ran debug mode binary. Now running release mode binary..."
        COMMAND tests_release
        COMMAND hook_tests_release
        COMMAND snapshot_tests_release
        DEPENDS tests_debug hook_tests_debug snapshot_tests_debug tests_release hook_tests_release snapshot_tests_release
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running all tests..."
)