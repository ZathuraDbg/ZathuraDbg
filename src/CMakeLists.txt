cmake_minimum_required(VERSION 3.10)
project(Zathura)

set(CMAKE_CXX_STANDARD 23)

set(SOURCES
        ${CMAKE_SOURCE_DIR}/main.cpp
        ${CMAKE_SOURCE_DIR}/../vendor/imgui/imgui.cpp
        ${CMAKE_SOURCE_DIR}/../vendor/tinyexpr/tinyexpr.c
        ${CMAKE_SOURCE_DIR}/../vendor/imgui/imgui_draw.cpp
        ${CMAKE_SOURCE_DIR}/../vendor/imgui/imgui_tables.cpp
        ${CMAKE_SOURCE_DIR}/../vendor/imgui/imgui_widgets.cpp
        ${CMAKE_SOURCE_DIR}/../vendor/imgui/backends/imgui_impl_glfw.cpp
        ${CMAKE_SOURCE_DIR}/../vendor/imgui/backends/imgui_impl_opengl3.cpp
        ${CMAKE_SOURCE_DIR}/../vendor/imgui/misc/cpp/imgui_stdlib.cpp
        ${CMAKE_SOURCE_DIR}/../vendor/ImGuiColorTextEdit/TextEditor.cpp
        ${CMAKE_SOURCE_DIR}/../vendor/ImGuiColorTextEdit/LanguageDefinitions.cpp
        ${CMAKE_SOURCE_DIR}/app/dialogs/fileDialogs.cpp
        ${CMAKE_SOURCE_DIR}/app/buttons.cpp
        ${CMAKE_SOURCE_DIR}/app/windows/registerWindow.cpp
        ${CMAKE_SOURCE_DIR}/app/windows/consoleWindow.cpp
        ${CMAKE_SOURCE_DIR}/app/windows/hexEditorWindow.cpp
        ${CMAKE_SOURCE_DIR}/app/windows/stackWindow.cpp
        ${CMAKE_SOURCE_DIR}/app/menuBar.cpp
        ${CMAKE_SOURCE_DIR}/app/arch/arch.cpp
        ${CMAKE_SOURCE_DIR}/app/arch/arch.hpp
        ${CMAKE_SOURCE_DIR}/app/arch/arch.hpp
        ${CMAKE_SOURCE_DIR}/app/arch/arch.cpp
        ${CMAKE_SOURCE_DIR}/app/arch/arm.cpp
        ${CMAKE_SOURCE_DIR}/app/arch/arm.hpp
        ${CMAKE_SOURCE_DIR}/app/arch/arm.hpp
        ${CMAKE_SOURCE_DIR}/app/integration/interpreter/interpreter.cpp
        ${CMAKE_SOURCE_DIR}/app/integration/keystone/assembler.cpp
        ${CMAKE_SOURCE_DIR}/app/arch/x86.cpp
        ${CMAKE_SOURCE_DIR}/../vendor/whereami/src/whereami.c
        app/app.cpp
        ../vendor/code/tinyfiledialogs.c
        app/tasks/fileTasks.cpp
        app/tasks/editorTasks.cpp
        utils/fonts.cpp
        ../vendor/json/json.hpp
        utils/stringHelper.cpp
        utils/stringHelper.hpp
        app/integration/interpreter/errorHandler.cpp
        app/integration/interpreter/errorHandler.hpp
        app/shortcuts.cpp
        app/shortcuts.hpp
        app/actions/actions.cpp
        app/actions/actions.hpp
        ${CMAKE_SOURCE_DIR}/../vendor/tinyexpr/tinyexpr.h
        app/codeContextMenu.cpp
        app/codeContextMenu.hpp
        utils/stb_image.h
        app/windows/memoryMapView.cpp
        utils/uiElements.cpp
        utils/uiElements.h
)

# Include directories
include_directories(
        ${CMAKE_SOURCE_DIR}/../vendor/imgui
        ${CMAKE_SOURCE_DIR}/../vendor/imgui/backends
        ${CMAKE_SOURCE_DIR}/../vendor/ImGuiColorTextEdit/vendor/regex/include
        ${CMAKE_SOURCE_DIR}/../vendor/ordered-map/include
        ${CMAKE_SOURCE_DIR}/app/dialogs
        ${CMAKE_SOURCE_DIR}/app/tasks
        ${CMAKE_SOURCE_DIR}/app/arch
        ${CMAKE_SOURCE_DIR}/app/windows
        ${CMAKE_SOURCE_DIR}/../vendor/unicorn/include
        ${CMAKE_SOURCE_DIR}/../vendor/keystone/include
        ${CMAKE_SOURCE_DIR}/../vendor/capstone/include
        ${CMAKE_SOURCE_DIR}/../vendor/whereami/src
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
    
  set(LIBS ${GLFW_LDFLAGS} -lGL -ldl -lstdc++ -lunicorn -lkeystone -lcapstone
    #    -L${CMAKE_SOURCE_DIR}/../vendor/keystone -l:libkeystone.a  
    # -L${CMAKE_SOURCE_DIR}/../vendor/capstone -l:libcapstone.a 
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
    add_compile_options(${GLFW_CFLAGS} )
    set(LIBS -lglfw3 -lgdi32 -lopengl32 -limm32 -lstdc++ -lunicorn -lkeystone -lcapstone -lm -Wl,--stack,16777216)
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