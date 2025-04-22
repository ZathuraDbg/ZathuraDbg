cmake_minimum_required(VERSION 3.10)
project(Zathura)

set(CMAKE_CXX_STANDARD 23)

set(PROJECT_ROOT ${CMAKE_SOURCE_DIR})
set(VENDOR_DIR ${PROJECT_ROOT}/../vendor)
set(APP_DIR ${PROJECT_ROOT}/app)
set(UTILS_DIR ${PROJECT_ROOT}/utils)

# Source file groups
set(SRC_MAIN
        ${PROJECT_ROOT}/main.cpp
)

set(SRC_IMGUI
        ${VENDOR_DIR}/imgui/imgui.cpp
        ${VENDOR_DIR}/imgui/imgui_draw.cpp
        ${VENDOR_DIR}/imgui/imgui_tables.cpp
        ${VENDOR_DIR}/imgui/imgui_widgets.cpp
        ${VENDOR_DIR}/imgui/backends/imgui_impl_glfw.cpp
        ${VENDOR_DIR}/imgui/backends/imgui_impl_opengl3.cpp
        ${VENDOR_DIR}/imgui/misc/cpp/imgui_stdlib.cpp
)

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
        ${APP_DIR}/shortcuts.hpp
        ${APP_DIR}/app.cpp
        ${APP_DIR}/codeContextMenu.cpp
        ${APP_DIR}/codeContextMenu.hpp
)

set(SRC_WINDOWS
        ${APP_DIR}/windows/registerWindow.cpp
        ${APP_DIR}/windows/consoleWindow.cpp
        ${APP_DIR}/windows/hexEditorWindow.cpp
        ${APP_DIR}/windows/stackWindow.cpp
        ${APP_DIR}/windows/memoryMapView.cpp
)

set(SRC_ARCH
        ${APP_DIR}/arch/arch.cpp
        ${APP_DIR}/arch/arch.hpp
        ${APP_DIR}/arch/arm.cpp
        ${APP_DIR}/arch/arm.hpp
        ${APP_DIR}/arch/x86.cpp
)

set(SRC_INTEGRATION
        ${APP_DIR}/integration/interpreter/interpreter.cpp
        ${APP_DIR}/integration/keystone/assembler.cpp
)

set(SRC_UTILS
        ${UTILS_DIR}/fonts.cpp
        ${UTILS_DIR}/stringHelper.cpp
        ${UTILS_DIR}/stringHelper.hpp
        ${UTILS_DIR}/uiElements.cpp
        ${UTILS_DIR}/uiElements.h
        ${UTILS_DIR}/stb_image.h
)

set(SRC_TASKS
        ${APP_DIR}/tasks/fileTasks.cpp
        ${APP_DIR}/tasks/editorTasks.cpp
)

set(SRC_ACTIONS
        ${APP_DIR}/actions/actions.cpp
        ${APP_DIR}/actions/actions.hpp
)

set(SRC_VENDOR_MISC
        ${VENDOR_DIR}/tinyexpr/tinyexpr.c
        ${VENDOR_DIR}/tinyexpr/tinyexpr.h
        ${VENDOR_DIR}/whereami/src/whereami.c
        ${VENDOR_DIR}/tinyfdialogue/tinyfiledialogs.c
        ${VENDOR_DIR}/json/json.hpp
)

# Combine all
set(SOURCES
        ${SRC_MAIN}
        ${SRC_IMGUI}
        ${SRC_TEXT_EDITOR}
        ${SRC_DIALOGS}
        ${SRC_APP}
        ${SRC_WINDOWS}
        ${SRC_ARCH}
        ${SRC_INTEGRATION}
        ${SRC_UTILS}
        ${SRC_TASKS}
        ${SRC_ACTIONS}
        ${SRC_VENDOR_MISC}
)

# Include directories
include_directories(
        ${CMAKE_SOURCE_DIR}/../vendor/imgui
        ${CMAKE_SOURCE_DIR}/../vendor/imgui/backends
        ${CMAKE_SOURCE_DIR}/../vendor/ImGuiColorTextEdit/vendor/regex/include
        ${CMAKE_SOURCE_DIR}/../vendor/ordered-map/include
        ${CMAKE_SOURCE_DIR}/../vendor/tinyfdialogue
        ${CMAKE_SOURCE_DIR}/app/dialogs
        ${CMAKE_SOURCE_DIR}/app/tasks
        ${CMAKE_SOURCE_DIR}/app/arch
        ${CMAKE_SOURCE_DIR}/app/windows
        ${CMAKE_SOURCE_DIR}/../vendor/unicorn/include
        ${CMAKE_SOURCE_DIR}/../vendor/keystone/include
        ${CMAKE_SOURCE_DIR}/../vendor/capstone/include
        ${CMAKE_SOURCE_DIR}/../vendor/whereami/src
        ${CMAKE_SOURCE_DIR}/../vendor/icicle-cpp
)

set(OpenGL_GL_PREFERENCE GLVND)
# Compiler options
#add_compile_options(-g -Wformat -DLOG_TO_FILE=\".Zathura.zlog\")
# Define the output directory for the binary
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

# Platform-specific options
if (UNIX AND NOT APPLE)
    message("Linux")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GLFW REQUIRED glfw3)
    find_package(OpenGL REQUIRED)
    find_package(glfw3 REQUIRED)

   
    include_directories(${OPENGL_INCLUDE_DIR})
    link_libraries(${OPENGL_LIBRARIES} glfw)
    link_libraries(${GLFW_LIBRARIES})
    link_directories(/usr/lib /usr/local/lib)
    add_compile_options(${GLFW_CFLAGS})
    
  set(LIBS ${GLFW_LDFLAGS} -lGL -ldl -lstdc++ -lkeystone -lcapstone -L/usr/lib -L/usr/local/lib -licicle
    -pthread -std=c++23)
elseif (APPLE)
    message("Mac OS X")
    find_library(GLFW_LIB glfw3)
    link_libraries(${GLFW_LIB})
    add_compile_options(-I/usr/local/include -I/opt/local/include -I/opt/homebrew/include)
    set(LIBS -framework OpenGL -framework Cocoa -framework IOKit -framework CoreVideo -L/usr/local/lib -L/opt/local/lib -L/opt/homebrew/lib)
elseif (WIN32)
    message("MinGW")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GLFW REQUIRED glfw3)
    link_libraries(${GLFW_LIBRARIES})
    add_compile_options(${GLFW_CFLAGS} -g -O0)
    set(LIBS -lglfw3 -lgdi32 -lopengl32 -limm32 -lstdc++ -lkeystone -lcapstone -lm -licicle -lws2_32 -lntdll -luserenv -lbcrypt)
endif()

# Define the executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Link libraries
target_link_libraries(${PROJECT_NAME} ${LIBS})

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