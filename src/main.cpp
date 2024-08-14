#define IMGUI_DEFINE_MATH_OPERATORS
#include "../vendor/imgui/imgui_internal.h"
#include "../vendor/imgui/imgui.h"
#include "../vendor/imgui/backends/imgui_impl_glfw.h"
#include "../vendor/imgui/backends/imgui_impl_opengl3.h"
#include <cstdio>
#include "../vendor/ImGuiColorTextEdit/TextEditor.h"
#include "app/app.hpp"
#define GL_SILENCE_DEPRECATION
#if defined(IMGUI_IMPL_OPENGL_ES2)
#include <GLES2/gl2.h>
#endif
#include <GLFW/glfw3.h> // Will drag system OpenGL headers
#include <fstream>
#include <chrono>
#include <thread>

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
int main(int, char**)
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

    window = glfwCreateWindow(1280, 720, "Zathura!", nullptr, nullptr);
    glfwSetWindowSizeLimits(window, 980, 435, GLFW_DONT_CARE, GLFW_DONT_CARE);

    if (window == nullptr)
        return 1;

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = "/home/rc/Zathura-UI/src/config.zlyt";
	io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

    LoadIniFile();
    io = setupIO();
    // When viewports are enabled we tweak WindowRounding/WindowBg so platform windows can look identical to regular ones.
    ImGuiStyle& style = ImGui::GetStyle();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {
        style.WindowRounding = 2.0f;
        style.Colors[ImGuiCol_WindowBg].w = 1.0f;
    }

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    ImVec4 clear_color = hexToImVec4("101010");

    SetupImGuiStyle();
    setupEditor();
//    ImGui::PopFont();
    memoryEditorWindow.WriteFn = &hexWriteFunc;
    stackEditor.OptShowAscii = false;
    stackEditor.Cols = 8;
    stackEditor.WriteFn = &stackWriteFunc;
    MEMORY_EDITOR_BASE = ENTRY_POINT_ADDRESS;
//    stackEditor.BgColorFn = &bgColorFn;
//    stackEditor.InteractFn = &interactFn;

    if (!createStack(&uc)){
        tinyfd_messageBox("Keystone Engine error!", "Unable to initialize the stack. If the issue persists please create a GitHub issue and report your logs.", "ok", "error", 0);
        LOG_ERROR("Failed to create stack!");
        exit(-1);
    }

    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        io.ConfigDockingWithShift = true;
        io.ConfigDockingAlwaysTabBar = true;
        isRunning = true;

        mainWindow();

        if (!isRunning){
            glfwSetWindowShouldClose(window, 1);
        }

        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

       if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
       {
           GLFWwindow* backup_current_context = glfwGetCurrentContext();
           ImGui::UpdatePlatformWindows();
           ImGui::RenderPlatformWindowsDefault();
           glfwMakeContextCurrent(backup_current_context);
       }

       glfwSwapBuffers(window);
    }
    uc_close(uc);

    destroyWindow();
    return 0;
}
