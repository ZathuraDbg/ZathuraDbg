cmake_minimum_required(VERSION 3.16)
project(Zathura)
enable_testing()

set(CMAKE_CXX_STANDARD 23)
set(OPTIMIZATION_LEVEL "O0" CACHE STRING "Optimization level (O0, Og, O1, O2, O3)")

include(${CMAKE_CURRENT_LIST_DIR}/cmake/BuildParallelism.cmake)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
    set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
    message(STATUS "ccache enabled: ${CCACHE_PROGRAM}")
endif()

set(PROJECT_ROOT ${CMAKE_SOURCE_DIR})
set(VENDOR_DIR ${PROJECT_ROOT}/../vendor)
set(APP_DIR ${PROJECT_ROOT}/app)
set(UTILS_DIR ${PROJECT_ROOT}/utils)

set(ZATHURA_COMMON_INCLUDES
    ${VENDOR_DIR}/imgui
    ${VENDOR_DIR}/imgui/backends
    ${VENDOR_DIR}/ImGuiColorTextEdit/vendor/regex/include
    ${VENDOR_DIR}/ordered-map/include
    ${VENDOR_DIR}/tinyfdialogue
    ${APP_DIR}/dialogs
    ${APP_DIR}/tasks
    ${APP_DIR}/arch
    ${APP_DIR}/windows
    ${VENDOR_DIR}/local/usr/local/include
    ${VENDOR_DIR}/keystone/include
    ${VENDOR_DIR}/whereami/src
    ${VENDOR_DIR}/icicle-cpp
    ${VENDOR_DIR}/http
)

# Source file groups
set(SRC_MAIN
        ${PROJECT_ROOT}/main.cpp
)

# ImGui core sources compile as one unity TU; backends stay separate (OpenGL/GLFW deps).
set(SRC_IMGUI_CORE
        ${VENDOR_DIR}/imgui/imgui.cpp
        ${VENDOR_DIR}/imgui/imgui_draw.cpp
        ${VENDOR_DIR}/imgui/imgui_tables.cpp
        ${VENDOR_DIR}/imgui/imgui_widgets.cpp
        ${VENDOR_DIR}/imgui/misc/cpp/imgui_stdlib.cpp
)

set(SRC_IMGUI_BACKENDS
        ${VENDOR_DIR}/imgui/backends/imgui_impl_glfw.cpp
        ${VENDOR_DIR}/imgui/backends/imgui_impl_opengl3.cpp
)

add_library(zathura_imgui_core STATIC ${SRC_IMGUI_CORE})
set_target_properties(zathura_imgui_core PROPERTIES UNITY_BUILD ON)
target_include_directories(zathura_imgui_core PUBLIC ${ZATHURA_COMMON_INCLUDES})
target_compile_options(zathura_imgui_core PRIVATE -Wformat -pipe)

add_library(zathura_imgui_backends STATIC ${SRC_IMGUI_BACKENDS})
target_include_directories(zathura_imgui_backends PUBLIC ${ZATHURA_COMMON_INCLUDES})
target_compile_options(zathura_imgui_backends PRIVATE -Wformat -pipe)

set(SRC_TEXT_EDITOR
        ${VENDOR_DIR}/ImGuiColorTextEdit/TextEditor.cpp
        ${VENDOR_DIR}/ImGuiColorTextEdit/LanguageDefinitions.cpp
)

set(SRC_DIALOGS
        ${APP_DIR}/dialogs/fileDialogs.cpp
)

set(SRC_APP
        ${APP_DIR}/buttons.cpp
        ${APP_DIR}/menuBar.cpp
        ${APP_DIR}/shortcuts.cpp
        ${APP_DIR}/app.cpp
        ${APP_DIR}/codeContextMenu.cpp
)

set(SRC_WINDOWS
        ${APP_DIR}/windows/registerWindow.cpp
        ${APP_DIR}/windows/consoleWindow.cpp
        ${APP_DIR}/windows/hexEditorWindow.cpp
        ${APP_DIR}/windows/sourceWindow.cpp
        ${APP_DIR}/windows/debugToolWindows.cpp
        ${APP_DIR}/windows/stackWindow.cpp
        ${APP_DIR}/windows/memoryMapView.cpp
)

set(SRC_ARCH
        ${APP_DIR}/arch/arch.cpp
        ${APP_DIR}/arch/arm.cpp
        ${APP_DIR}/arch/x86.cpp
)

set(SRC_INTEGRATION
    ${APP_DIR}/integration/debugBackend.cpp
    ${APP_DIR}/integration/debugState.cpp
    ${APP_DIR}/integration/elfLoader.cpp
    ${APP_DIR}/integration/linuxProcess.cpp
    ${APP_DIR}/integration/interpreter/interpreter.cpp
    ${APP_DIR}/integration/interpreter/registers.cpp
    ${APP_DIR}/integration/interpreter/vm.cpp
    ${APP_DIR}/integration/interpreter/execution.cpp
    ${APP_DIR}/integration/interpreter/breakpoints.cpp
    ${APP_DIR}/integration/gdb/gdbRemote.cpp
    ${APP_DIR}/integration/gdb/gdbPacket.cpp
    ${APP_DIR}/integration/gdb/elfSymbols.cpp
    ${APP_DIR}/integration/keystone/assembler.cpp
)

set(SRC_UTILS
        ${UTILS_DIR}/fonts.cpp
        ${UTILS_DIR}/logger.cpp
        ${UTILS_DIR}/runtimePaths.cpp
        ${UTILS_DIR}/stringHelper.cpp
        ${UTILS_DIR}/uiElements.cpp
)

set(SRC_TASKS
        ${APP_DIR}/tasks/fileTasks.cpp
        ${APP_DIR}/tasks/editorTasks.cpp
)

set(SRC_ACTIONS
        ${APP_DIR}/actions/actions.cpp
)

set(SRC_VENDOR_C
        ${VENDOR_DIR}/tinyexpr/tinyexpr.c
        ${VENDOR_DIR}/whereami/src/whereami.c
        ${VENDOR_DIR}/tinyfdialogue/tinyfiledialogs.c
)

# In the browser build, swap socket/dialog-dependent sources for inert stubs.
if (EMSCRIPTEN)
    list(REMOVE_ITEM SRC_INTEGRATION
            ${APP_DIR}/integration/gdb/gdbRemote.cpp
            ${APP_DIR}/integration/gdb/gdbPacket.cpp)
    list(APPEND SRC_INTEGRATION
            ${APP_DIR}/integration/gdb/gdbRemoteStub.cpp
            ${APP_DIR}/integration/wasm/browserFiles.cpp)
    list(REMOVE_ITEM SRC_VENDOR_C
            ${VENDOR_DIR}/tinyfdialogue/tinyfiledialogs.c
            ${VENDOR_DIR}/whereami/src/whereami.c)
    list(APPEND SRC_VENDOR_C
            ${APP_DIR}/dialogs/tinyfd_stub.c)
endif()

set(SRC_ZATHURA
        ${SRC_MAIN}
        ${SRC_DIALOGS}
        ${SRC_APP}
        ${SRC_WINDOWS}
        ${SRC_ARCH}
        ${SRC_INTEGRATION}
        ${SRC_UTILS}
        ${SRC_TASKS}
        ${SRC_ACTIONS}
        ${SRC_VENDOR_C}
)

set(OpenGL_GL_PREFERENCE GLVND)

# Define the output directory for the binary
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

# Locations of the wasm-compiled third-party static libraries. Defaults assume
# the icicle-wasm workspace sits next to this repo (../../icicle-wasm relative
# to src/); override with -DWASM_LIBS_ROOT=... if it lives elsewhere.
set(WASM_LIBS_ROOT "${CMAKE_SOURCE_DIR}/../../icicle-wasm" CACHE PATH "Root of prebuilt wasm libs")
set(WASM_ICICLE_LIB "${WASM_LIBS_ROOT}/icicle-cpp/src/target/wasm32-unknown-emscripten/release/libicicle.a" CACHE FILEPATH "wasm libicicle.a")
set(WASM_KEYSTONE_LIB "${WASM_LIBS_ROOT}/keystone-src/build-wasm/llvm/lib/libkeystone.a" CACHE FILEPATH "wasm libkeystone.a")
set(WASM_CAPSTONE_LIB "${WASM_LIBS_ROOT}/capstone/build-wasm/libcapstone.a" CACHE FILEPATH "wasm libcapstone.a")
set(WASM_CAPSTONE_INCLUDE "${WASM_LIBS_ROOT}/capstone/include" CACHE PATH "wasm capstone headers")
set(WASM_UNICORN_INCLUDE "${WASM_LIBS_ROOT}/unicorn-include" CACHE PATH "unicorn headers (enums only)")
set(WASM_FS_ROOT "${WASM_LIBS_ROOT}/zathura-fs" CACHE PATH "MEMFS staging dir to embed")

# Platform-specific options
if (EMSCRIPTEN)
    message("Emscripten (wasm)")
    # GLFW + WebGL2/GLES3 are provided by emscripten; only the emulator,
    # assembler and disassembler need to be the prebuilt wasm archives.
    set(LIBS ${WASM_ICICLE_LIB} ${WASM_KEYSTONE_LIB} ${WASM_CAPSTONE_LIB})
elseif (UNIX AND NOT APPLE)
    message("Linux")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GLFW REQUIRED glfw3)
    find_package(OpenGL REQUIRED)
    find_package(glfw3 REQUIRED)
    find_package(Threads REQUIRED)

    set(VENDORED_KEYSTONE_LIB ${CMAKE_SOURCE_DIR}/../vendor/local/usr/local/lib/libkeystone.so.0)
    link_directories(/usr/lib /usr/local/lib ${CMAKE_SOURCE_DIR}/../vendor/local/usr/local/lib)
    set(LIBS ${GLFW_LDFLAGS} -lGL -ldl -lstdc++ ${VENDORED_KEYSTONE_LIB} -lcapstone -lunicorn -L/usr/lib -L/usr/local/lib -L${CMAKE_SOURCE_DIR}/../vendor/local/usr/local/lib -licicle -lssl -lcrypto)
elseif (APPLE)
    message("Mac OS X")
    find_library(GLFW_LIB glfw3)
    set(LIBS ${GLFW_LIB} -framework OpenGL -framework Cocoa -framework IOKit -framework CoreVideo -L/usr/local/lib -L/opt/local/lib -L/opt/homebrew/lib)
elseif (WIN32)
    message("MinGW")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GLFW REQUIRED glfw3)
    set(LIBS -lglfw3 -lgdi32 -lopengl32 -limm32 -lstdc++ -lkeystone -lcapstone -lm -licicle -lws2_32 -lntdll -luserenv -lbcrypt -lssl -lcrypto -lcrypt32)
endif()

add_library(zathura_textedit STATIC ${SRC_TEXT_EDITOR})
target_include_directories(zathura_textedit PUBLIC ${ZATHURA_COMMON_INCLUDES})
target_compile_options(zathura_textedit PRIVATE -Wformat -pipe)

add_executable(${PROJECT_NAME} ${SRC_ZATHURA})
target_link_libraries(${PROJECT_NAME} PRIVATE zathura_imgui_core zathura_imgui_backends zathura_textedit)
target_compile_definitions(${PROJECT_NAME} PRIVATE ZATHURA_REQUIRE_LOGGER_ADAPTER)

# Target include directories (replaces global include_directories)
target_include_directories(${PROJECT_NAME} PRIVATE ${ZATHURA_COMMON_INCLUDES})

# Precompiled header: parse imgui/unicorn/capstone/STL once instead of per-TU.
# pch.hpp is Emscripten-safe (no desktop-GL includes), and force-including it
# keeps parity with the native build where every TU sees these headers.
target_precompile_headers(${PROJECT_NAME} PRIVATE ${PROJECT_ROOT}/pch.hpp)
set_source_files_properties(${SRC_VENDOR_C} PROPERTIES SKIP_PRECOMPILE_HEADERS ON)

# Debug info comes from CMAKE_*_FLAGS_DEBUG; avoid passing -g twice.
target_compile_options(${PROJECT_NAME} PRIVATE -Wformat -pipe)

if (NOT WIN32 AND NOT EMSCRIPTEN)
    add_executable(zathura_elf_symbols_test
            ${APP_DIR}/integration/gdb/elfSymbols.cpp
            ${PROJECT_ROOT}/tests/elfSymbolsTest.cpp
    )
    set_target_properties(zathura_elf_symbols_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    target_include_directories(zathura_elf_symbols_test PRIVATE ${APP_DIR})
    add_test(NAME zathura_elf_symbols_test COMMAND zathura_elf_symbols_test)
endif()

# Platform-specific target settings
if (EMSCRIPTEN)
    set(ZATHURA_EM_FLAGS
            -O2
            -fexceptions
            -sUSE_GLFW=3)
    foreach(tgt ${PROJECT_NAME} zathura_imgui_core zathura_imgui_backends zathura_textedit)
        target_compile_options(${tgt} PRIVATE ${ZATHURA_EM_FLAGS})
        # capstone (cs_arch enums) + unicorn (UC_MODE_* enums) are referenced in
        # headers even though neither engine is linked in the wasm build.
        target_include_directories(${tgt} PRIVATE ${WASM_CAPSTONE_INCLUDE} ${WASM_UNICORN_INCLUDE})
    endforeach()

    target_link_options(${PROJECT_NAME} PRIVATE
            -O2
            -fexceptions
            -sUSE_GLFW=3
            -sMIN_WEBGL_VERSION=2
            -sMAX_WEBGL_VERSION=2
            -sFULL_ES3=1
            -sALLOW_MEMORY_GROWTH=1
            -sINITIAL_MEMORY=536870912   # 512 MiB: emulator heap + embedded MEMFS headroom; grows on demand
            -sSTACK_SIZE=8388608         # 8 MiB: sleigh spec compilation recurses deeply
            -sFORCE_FILESYSTEM=1
            -sEXIT_RUNTIME=0
            -sASSERTIONS=1
            -sEXPORTED_RUNTIME_METHODS=ccall,cwrap,FS,UTF8ToString,HEAPU8
            # --preload-file (vs --embed-file) keeps the ~6MB sleigh/asset data
            # out of the wasm: it ships as a separate Zathura.data fetched in
            # parallel and cached independently. The loader populates MEMFS
            # before main() runs, so no code change is needed.
            "SHELL:--preload-file ${WASM_FS_ROOT}@/"
            "SHELL:--shell-file ${PROJECT_ROOT}/wasm-shell.html")
    set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX ".html")
    # Relink when the shell template changes.
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_DEPENDS ${PROJECT_ROOT}/wasm-shell.html)
elseif (UNIX AND NOT APPLE)
    set_target_properties(${PROJECT_NAME} PROPERTIES
            BUILD_RPATH "${CMAKE_SOURCE_DIR}/../vendor/local/usr/local/lib")
    target_include_directories(${PROJECT_NAME} PRIVATE ${OPENGL_INCLUDE_DIR})
    target_include_directories(zathura_imgui_core PRIVATE ${OPENGL_INCLUDE_DIR})
    target_include_directories(zathura_imgui_backends PRIVATE ${OPENGL_INCLUDE_DIR})
    target_include_directories(zathura_textedit PRIVATE ${OPENGL_INCLUDE_DIR})
    target_compile_options(${PROJECT_NAME} PRIVATE ${GLFW_CFLAGS})
    target_compile_options(zathura_imgui_core PRIVATE ${GLFW_CFLAGS})
    target_compile_options(zathura_imgui_backends PRIVATE ${GLFW_CFLAGS})
    target_compile_options(zathura_textedit PRIVATE ${GLFW_CFLAGS})
    target_compile_options(${PROJECT_NAME} PRIVATE -${OPTIMIZATION_LEVEL})
    target_compile_options(zathura_imgui_core PRIVATE -${OPTIMIZATION_LEVEL})
    target_compile_options(zathura_imgui_backends PRIVATE -${OPTIMIZATION_LEVEL})
    target_compile_options(zathura_textedit PRIVATE -${OPTIMIZATION_LEVEL})
    target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads)
elseif (APPLE)
    target_include_directories(${PROJECT_NAME} PRIVATE /usr/local/include /opt/local/include /opt/homebrew/include)
elseif (WIN32)
    target_compile_options(${PROJECT_NAME} PRIVATE ${GLFW_CFLAGS} -O3)
    target_compile_options(zathura_imgui_core PRIVATE -O3)
    target_compile_options(zathura_imgui_backends PRIVATE -O3)
    target_compile_options(zathura_textedit PRIVATE -O3)
endif()

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBS})

# Custom targets
add_custom_target(run
        COMMAND ${PROJECT_NAME}
        DEPENDS ${PROJECT_NAME}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target(clean-all
        COMMAND ${CMAKE_COMMAND} -P clean.cmake
)

# Clean command
file(WRITE ${CMAKE_BINARY_DIR}/clean.cmake "
file(REMOVE
    ${CMAKE_BINARY_DIR}/bin/${PROJECT_NAME}
    ${CMAKE_BINARY_DIR}/CMakeFiles
    ${CMAKE_BINARY_DIR}/cmake_install.cmake
    ${CMAKE_BINARY_DIR}/Makefile
)
")
