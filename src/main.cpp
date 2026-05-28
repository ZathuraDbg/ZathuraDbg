#define IMGUI_DEFINE_MATH_OPERATORS
#include "../vendor/imgui/imgui_internal.h"
#include "../vendor/imgui/imgui.h"
#include "../vendor/imgui/backends/imgui_impl_glfw.h"
#include "../vendor/imgui/backends/imgui_impl_opengl3.h"
#include <cstdio>
#include "../vendor/ImGuiColorTextEdit/TextEditor.h"
#include "app/app.hpp"
#include "app/arch/arch.hpp"
#include "app/integration/gdb/gdbRemote.hpp"
#include "app/shortcuts.hpp"
#include "utils/runtimePaths.hpp"
#include "../vendor/whereami/src/whereami.h"
#include "app/windows/windows.hpp" // Make sure this imports the stack window functions
#include <map>
#include <cstdint>
#define GL_SILENCE_DEPRECATION
#if defined(IMGUI_IMPL_OPENGL_ES2)
#include <GLES2/gl2.h>
#endif
#include <GLFW/glfw3.h> // Will drag system OpenGL headers
#include <chrono>
#include <thread>
#include <filesystem>
#include <system_error>
#include <iostream>
GLFWwindow* window = nullptr;
#if defined(_MSC_VER) && (_MSC_VER >= 1900) && !defined(IMGUI_DISABLE_WIN32_FUNCTIONS)
#pragma comment(lib, "legacy_stdio_definitions")
#endif
#define STB_IMAGE_IMPLEMENTATION
#include "utils/stb_image.h"

static void glfw_error_callback(int error, const char* description)
{
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

namespace {

constexpr std::uintmax_t MAX_LOG_FILE_SIZE = 3 * 1024 * 1024;

void rotateLogFile(const std::filesystem::path &logPath) {
    std::error_code error;
    const auto logSize = std::filesystem::file_size(logPath, error);
    if (error || logSize <= MAX_LOG_FILE_SIZE) {
        return;
    }

    std::filesystem::remove(logPath, error);
    if (!error) {
        LOG_ALERT("Logging restarted!");
    }
}

void reportStartupWarning(const std::string &message) {
    if (message.empty()) {
        return;
    }

    std::cerr << message << '\n';
    tinyfd_messageBox("ZathuraDbg startup warning", message.c_str(), "ok", "warning", 0);
}

}

void destroyWindow(){
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();
}

float frameRate = 120;

// Declare these as null pointers since some code might still reference them
bool stackArraysZeroed = false;

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
    glfwWindowHint(GLFW_DECORATED, GLFW_TRUE);
    window = glfwCreateWindow(glfwGetVideoMode(glfwGetPrimaryMonitor())->width, glfwGetVideoMode(glfwGetPrimaryMonitor())->height, "Zathura!", nullptr, nullptr);
    glfwSetWindowSizeLimits(window, 980, 435, GLFW_DONT_CARE, GLFW_DONT_CARE);

    if (window == nullptr)
        return 1;

    glfwHideWindow(window);
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    {
        int dirnameLength;

        if (const int length = wai_getExecutablePath(nullptr, 0, &dirnameLength); length > 0) {
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

    std::string startupWarning;
    Zathura::RuntimePaths::ensureUserDirectories(&startupWarning);
    Zathura::RuntimePaths::migrateConfigIfNeeded(executablePath, &startupWarning);
    Zathura::Logger::initialize(Zathura::RuntimePaths::logFile(), &startupWarning);
    reportStartupWarning(startupWarning);
    rotateLogFile(Zathura::Logger::logFilePath());

#ifdef _WIN32
    std::stringstream ss{};
    ss << "GHIDRA_SRC=" << relativeToRealPath(executablePath, "../vendor/ghidra");
    _putenv(ss.str().c_str());
#elif __linux__
    setenv("GHIDRA_SRC", relativeToRealPath(executablePath, "../vendor/ghidra/").c_str(), 1);
#endif

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    static const std::string iniFilePath = Zathura::RuntimePaths::configFile().string();
    io.IniFilename = iniFilePath.c_str();
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

    GLFWimage icons[1];
    icons[0].pixels = stbi_load(relativeToRealPath(executablePath, "../assets/ZathuraDbg.png").c_str(), &icons[0].width, &icons[0].height, nullptr, 4);
    glfwSetWindowIcon(window, 1, icons); // Set icon
    stbi_image_free(icons[0].pixels);

    ImVec4 clearColor = hexToImVec4("101010");
    setupAppStyle();
    setupEditor();

    initArch();

    remote_gdb::setRemoteLogSink([](const std::string& text) {
        consoleWriteThreadSafe(text);
    });
    remote_gdb::setRemoteArchHook([](const std::string& alias) {
        if (alias == "x86_64") {
            codeInformation.archIC = IC_ARCH_X86_64;
            codeInformation.archKS = KS_ARCH_X86;
            codeInformation.archCS = CS_ARCH_X86;
            codeInformation.mode = UC_MODE_64;
            codeInformation.modeKS = KS_MODE_64;
            codeInformation.modeCS = CS_MODE_64;
            codeInformation.syntax = KS_OPT_SYNTAX_NASM;
            codeInformation.archStr = "x86_64";
        } else if (alias == "aarch64") {
            codeInformation.archIC = IC_ARCH_AARCH64;
            codeInformation.archKS = KS_ARCH_ARM64;
            codeInformation.archCS = CS_ARCH_ARM64;
            codeInformation.mode = UC_MODE_ARM;
            codeInformation.modeKS = KS_MODE_LITTLE_ENDIAN;
            codeInformation.modeCS = CS_MODE_LITTLE_ENDIAN;
            codeInformation.archStr = "aarch64";
        } else if (alias == "arm") {
            codeInformation.archIC = IC_ARCH_ARM;
            codeInformation.archKS = KS_ARCH_ARM;
            codeInformation.archCS = CS_ARCH_ARM;
            codeInformation.mode = UC_MODE_ARM;
            codeInformation.modeKS = KS_MODE_ARM;
            codeInformation.modeCS = CS_MODE_ARM;
            codeInformation.archStr = "arm";
        }
        initArch();
    });

    MEMORY_EDITOR_BASE = ENTRY_POINT_ADDRESS;

    memoryEditorWindow.WriteFn = &hexWriteFunc;
    stackEditor.WriteFn = &stackWriteFunc;
    stackEditor.OptShowAscii = false;
    stackEditor.Cols = 8;
    stackArraysZeroed = false;

    glfwShowWindow(window);

    if (!getenv("GHIDRA_SRC")) {
        tinyfd_messageBox("Environment variable missing!", "The environment variable GHIDRA_SRC is missing. The emulator can\'t run without this.", "ok", "warning", 0);
    }

    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();

        static float prevFontScale = 1.0f;
        static ImGuiStyle baseStyle = ImGui::GetStyle();
        if (gFontScale != prevFontScale) {
            ImGui::GetStyle() = baseStyle;
            ImGui::GetStyle().ScaleAllSizes(gFontScale);
            prevFontScale = gFontScale;
        }
        io.FontGlobalScale = gFontScale;

        ImGui::NewFrame();

        io.ConfigDockingWithShift = true;
        io.ConfigDockingAlwaysTabBar = true;
        isRunning = true;

        processUIUpdates();
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

    if (icicle != nullptr)
    {
        icicle_free(icicle);
    }

    destroyWindow();
    return 0;
}
