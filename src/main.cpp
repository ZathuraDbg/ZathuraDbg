#define IMGUI_DEFINE_MATH_OPERATORS
#include "../vendor/imgui/imgui_internal.h"
#include "../vendor/imgui/imgui.h"
#include "../vendor/imgui/backends/imgui_impl_glfw.h"
#include "../vendor/imgui/backends/imgui_impl_opengl3.h"
#include <cstdio>
#include "../vendor/ImGuiColorTextEdit/TextEditor.h"
#include "app/app.hpp"
#include "../vendor/whereami/src/whereami.h"
#define GL_SILENCE_DEPRECATION
#if defined(IMGUI_IMPL_OPENGL_ES2)
#include <GLES2/gl2.h>
#endif
#include <GLFW/glfw3.h> // Will drag system OpenGL headers
#include <fstream>
#include <chrono>
#include <thread>
#include <filesystem>

GLFWwindow* window = nullptr;
#if defined(_MSC_VER) && (_MSC_VER >= 1900) && !defined(IMGUI_DISABLE_WIN32_FUNCTIONS)
#pragma comment(lib, "legacy_stdio_definitions")
#endif

static void glfw_error_callback(int error, const char* description)
{
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

void destroyWindow(){
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();
}

float frameRate = 120;

int main(int argc, const char** argv)
{
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit())
        return 1;

#if defined(IMGUI_IMPL_OPENGL_ES2)
    // GL ES 2.0 + GLSL 100
    const char* glsl_version = "#version 100";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 2);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
    glfwWindowHint(GLFW_CLIENT_API, GLFW_OPENGL_ES_API);
#elif defined(__APPLE__)
    // GL 3.2 + GLSL 150
    const char* glsl_version = "#version 150";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);  // 3.2+ only
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);            // Required on Mac
#else
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
#endif

    window = glfwCreateWindow(glfwGetVideoMode(glfwGetPrimaryMonitor())->width, glfwGetVideoMode(glfwGetPrimaryMonitor())->height, "Zathura!", glfwGetPrimaryMonitor(), nullptr);
    glfwSetWindowSizeLimits(window, 980, 435, GLFW_DONT_CARE, GLFW_DONT_CARE);

    if (window == nullptr)
        return 1;

    glfwHideWindow(window);
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    {
        int dirnameLength;

        int length = wai_getExecutablePath(nullptr, 0, &dirnameLength);
        if (length > 0) {
            char* path = nullptr;
            path = static_cast<char *>(malloc(length + 1));
            if (path == nullptr) {
                tinyfd_messageBox("Whereami error!", "Failed to get executable path!", "ok", "error", 0);
                return 1;
            }
            wai_getExecutablePath(path, length, &dirnameLength);
            path[dirnameLength] = '\0';
            executablePath = std::string(path);
            selectedFile = relativeToRealPath(executablePath, "test.asm");
            free(path);
        }
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = "config.zlyt";
    const char* currentPath = executablePath.c_str();
	io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

    loadIniFile();
    io = setupIO();

    ImGuiStyle& style = ImGui::GetStyle();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {
        style.WindowRounding = 2.0f;
        style.Colors[ImGuiCol_WindowBg].w = 1.0f;
    }

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    ImVec4 clearColor = hexToImVec4("101010");
    setupAppStyle();
    setupEditor();

    MEMORY_EDITOR_BASE = ENTRY_POINT_ADDRESS;

    memoryEditorWindow.WriteFn = &hexWriteFunc;
    stackEditor.WriteFn = &stackWriteFunc;
    stackEditor.OptShowAscii = false;
    stackEditor.Cols = 8;

    if (!createStack(&uc)){
        tinyfd_messageBox("Keystone Engine error!", "Unable to initialize the stack. If the issue persists please create a GitHub issue and report your logs.", "ok", "error", 0);
        LOG_ERROR("Failed to create stack!");
        exit(-1);
    }

    glfwShowWindow(window);

    while (!glfwWindowShouldClose(window))
    {
        glfwWaitEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        io.ConfigDockingWithShift = true;
        io.ConfigDockingAlwaysTabBar = true;
        isRunning = true;

        mainWindow();

        if (!isRunning){
            LOG_ERROR("Quitting!");
            glfwSetWindowShouldClose(window, 1);
        }

        int displayW, displayH;
        glfwGetFramebufferSize(window, &displayW, &displayH);
        glViewport(0, 0, displayW, displayH);
        glClearColor(clearColor.x * clearColor.w, clearColor.y * clearColor.w, clearColor.z * clearColor.w, clearColor.w);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

       if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
       {
           GLFWwindow* backupCurrentContext = glfwGetCurrentContext();
           ImGui::UpdatePlatformWindows();
           ImGui::RenderPlatformWindowsDefault();
           glfwMakeContextCurrent(backupCurrentContext);
       }

       glfwSwapBuffers(window);
    }

    if (isCodeRunning) {
        debugStop = true;
        runActions();
    }

    uc_close(uc);
    destroyWindow();
    return 0;
}
