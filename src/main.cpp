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
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <emscripten/html5.h>
#include "app/integration/wasm/browserFiles.hpp"
#endif
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

// Clear color, set once in main() and used by every rendered frame. Hoisted to
// file scope so the Emscripten main-loop callback can reach it.
static ImVec4 gClearColor;

#ifdef __EMSCRIPTEN__
// HiDPI: size the canvas backing store to CSS-size x devicePixelRatio so the
// browser doesn't upscale a 1x bitmap (blurry on Retina). Returns the dpr.
static double updateHiDpiCanvas()
{
    const double dpr = emscripten_get_device_pixel_ratio();
    double cssW = 0.0, cssH = 0.0;
    if (emscripten_get_element_css_size("#canvas", &cssW, &cssH) != EMSCRIPTEN_RESULT_SUCCESS) {
        return dpr;
    }
    const int bw = static_cast<int>(cssW * dpr + 0.5);
    const int bh = static_cast<int>(cssH * dpr + 0.5);
    int curW = 0, curH = 0;
    emscripten_get_canvas_element_size("#canvas", &curW, &curH);
    if (bw > 0 && bh > 0 && (curW != bw || curH != bh)) {
        emscripten_set_canvas_element_size("#canvas", bw, bh);
    }
    return dpr;
}
#endif

// One rendered frame. Native builds call this from a while loop; the Emscripten
// build registers it with emscripten_set_main_loop so the browser drives it.
static void renderFrame()
{
    ImGuiIO& io = ImGui::GetIO();

    glfwPollEvents();
#ifdef __EMSCRIPTEN__
    const double gDpr = updateHiDpiCanvas();
#endif
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
#ifdef __EMSCRIPTEN__
    // The Emscripten GLFW shim reports window==framebuffer, so the backend sets
    // a framebuffer scale of 1. Override it with the real devicePixelRatio so
    // ImGui renders draw data into the dpr-scaled backing store (crisp on
    // Retina). DisplaySize stays in CSS units, so layout/mouse are unaffected.
    io.DisplayFramebufferScale = ImVec2(static_cast<float>(gDpr), static_cast<float>(gDpr));
#endif

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
#ifdef __EMSCRIPTEN__
    // Persist editor program + window layout to localStorage.
    browserPersistTick();
#endif
    if (!isRunning){
        LOG_ERROR("Quitting!");
        glfwSetWindowShouldClose(window, 1);
    }

    int displayW, displayH;
#ifdef __EMSCRIPTEN__
    // Use the actual canvas backing size (CSS x dpr) for the clear viewport; the
    // GLFW shim's framebuffer size does not reflect the dpr-scaled backing.
    emscripten_get_canvas_element_size("#canvas", &displayW, &displayH);
#else
    glfwGetFramebufferSize(window, &displayW, &displayH);
#endif
    glViewport(0, 0, displayW, displayH);
    glClearColor(gClearColor.x * gClearColor.w, gClearColor.y * gClearColor.w, gClearColor.z * gClearColor.w, gClearColor.w);
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

// Declare these as null pointers since some code might still reference them
bool stackArraysZeroed = false;

int main(int argc, const char** argv)
{
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit())
        return 1;

#if defined(__EMSCRIPTEN__)
    // WebGL2 / GLES 3.0 + GLSL ES 3.00
    const char* glsl_version = "#version 300 es";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
    glfwWindowHint(GLFW_CLIENT_API, GLFW_OPENGL_ES_API);
#elif defined(IMGUI_IMPL_OPENGL_ES2)
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
#ifdef __EMSCRIPTEN__
    // Size to the canvas; the browser/CSS controls the actual displayed size.
    window = glfwCreateWindow(1280, 720, "Zathura!", nullptr, nullptr);
#else
    window = glfwCreateWindow(glfwGetVideoMode(glfwGetPrimaryMonitor())->width, glfwGetVideoMode(glfwGetPrimaryMonitor())->height, "Zathura!", nullptr, nullptr);
    glfwSetWindowSizeLimits(window, 980, 435, GLFW_DONT_CARE, GLFW_DONT_CARE);
#endif

    if (window == nullptr)
        return 1;

#ifndef __EMSCRIPTEN__
    glfwHideWindow(window);
#endif
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

#ifdef __EMSCRIPTEN__
    // No real executable path in the browser; use the fixed MEMFS layout that
    // build-wasm.sh embeds (binary dir at /app/bin, assets at /app/assets).
    executablePath = "/app/bin";
    selectedFile = relativeToRealPath(executablePath, "test.asm");
#else
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
#endif

    std::string startupWarning;
    Zathura::RuntimePaths::ensureUserDirectories(&startupWarning);
    Zathura::RuntimePaths::migrateConfigIfNeeded(executablePath, &startupWarning);
    Zathura::Logger::initialize(Zathura::RuntimePaths::logFile(), &startupWarning);
    reportStartupWarning(startupWarning);
    rotateLogFile(Zathura::Logger::logFilePath());

#ifdef __EMSCRIPTEN__
    // Sleigh specs are embedded at /ghidra/Ghidra/Processors in MEMFS.
    setenv("GHIDRA_SRC", "/ghidra/", 1);
#elif defined(_WIN32)
    std::stringstream ss{};
    ss << "GHIDRA_SRC=" << relativeToRealPath(executablePath, "../vendor/ghidra");
    _putenv(ss.str().c_str());
#elif __linux__
    setenv("GHIDRA_SRC", relativeToRealPath(executablePath, "../vendor/ghidra/").c_str(), 1);
#endif

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
#ifdef __EMSCRIPTEN__
    // Manage layout persistence manually via localStorage (no writable ini file
    // in MEMFS); see browserRestoreLayout() / browserPersistTick().
    io.IniFilename = nullptr;
#else
    static const std::string iniFilePath = Zathura::RuntimePaths::configFile().string();
    io.IniFilename = iniFilePath.c_str();
#endif
	io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

#ifdef __EMSCRIPTEN__
    browserRestoreLayout();
#else
    loadIniFile();
#endif
    io = setupIO();
#ifdef __EMSCRIPTEN__
    // The native build sets Cmd-vs-Ctrl behaviour from __APPLE__ at compile
    // time; the wasm build is one binary for all platforms, so detect Apple at
    // runtime and use Cmd as the shortcut modifier there (matches expectations
    // and stops Ctrl+K etc. firing debugger actions on a Mac).
    io.ConfigMacOSXBehaviors = browserIsApplePlatform();
#endif

    ImGuiStyle& style = ImGui::GetStyle();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {
        style.WindowRounding = 2.0f;
        style.Colors[ImGuiCol_WindowBg].w = 1.0f;
    }

    ImGui_ImplGlfw_InitForOpenGL(window, true);
#ifdef __EMSCRIPTEN__
    browserInstallClipboardHandlers();
    // Track the browser canvas: resizes the GLFW window (and thus ImGui's
    // display size) whenever the canvas / window / fullscreen state changes.
    ImGui_ImplGlfw_InstallEmscriptenCallbacks(window, "#canvas");
#endif
    ImGui_ImplOpenGL3_Init(glsl_version);

#ifndef __EMSCRIPTEN__
    GLFWimage icons[1];
    icons[0].pixels = stbi_load(relativeToRealPath(executablePath, "../assets/ZathuraDbg.png").c_str(), &icons[0].width, &icons[0].height, nullptr, 4);
    glfwSetWindowIcon(window, 1, icons); // Set icon
    stbi_image_free(icons[0].pixels);
#endif

    gClearColor = hexToImVec4("101010");
    setupAppStyle();
#ifdef __EMSCRIPTEN__
    // Program precedence: shared URL (#code=...) > localStorage autosave >
    // default sample. Whichever wins, setupEditor() loads selectedFile.
    if (!browserLoadCodeFromUrl()) {
        browserRestoreSavedCode();
    }
#endif
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

#ifdef __EMSCRIPTEN__
    // The browser owns the event loop; hand it renderFrame and never return.
    // (Viewports/multi-window are disabled in the wasm build — single canvas.)
    emscripten_set_main_loop(renderFrame, 0, 1);
#else
    while (!glfwWindowShouldClose(window))
    {
        renderFrame();
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
#endif
}
