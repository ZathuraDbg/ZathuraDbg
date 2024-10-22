#include "fonts.hpp"
#include "../app/app.hpp"
#include "../../vendor/imgui/imgui.h"

static std::string normalizePath(const std::string& s) {
    std::filesystem::path canonicalPath = std::filesystem::weakly_canonical(std::filesystem::path(s));
    return canonicalPath.make_preferred().string();
}

static std::string relativeToRealPath(const char *s) {
    std::string r = normalizePath(std::filesystem::path(executablePath + "/" + std::string(s)));
    return r;
}

ImGuiIO& setupIO(){
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;         // Enable Docking
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigDockingWithShift = true;

    io.ConfigViewportsNoAutoMerge = true;
    io.ConfigViewportsNoTaskBarIcon = true;
    io.Fonts->AddFontDefault();
    io.Fonts->AddFontFromFileTTF(relativeToRealPath("../assets/Satoshi-Variable.ttf").c_str(), 16.0f);
    io.Fonts->AddFontFromFileTTF(relativeToRealPath("../assets/Satoshi-Variable.ttf").c_str(), 18.0f);
    io.Fonts->AddFontFromFileTTF(relativeToRealPath("../assets/JetBrainsMono.ttf").c_str(),    20.0f);
    io.Fonts->AddFontFromFileTTF(relativeToRealPath("../assets/Rubik-Regular.ttf").c_str(),    16.0f);
    io.Fonts->AddFontFromFileTTF(relativeToRealPath("../assets/Satoshi-Bold.ttf").c_str(),     18.0f);
    io.Fonts->AddFontFromFileTTF(relativeToRealPath("../assets/Satoshi-Medium.ttf").c_str(),   18.0f);
    constexpr float baseFontSize = 24.0f;
    constexpr float iconFontSize = baseFontSize * 2.0f / 3.0f; // FontAwesome fonts need to have their sizes reduced by 2.0f/3.0f in order to align correctly

// merge in icons from Font Awesome
    static const ImWchar icons_ranges[] = { ICON_MIN_CI, ICON_MAX_16_CI, 0 };
    ImFontConfig icons_config;
    icons_config.MergeMode = true;
    icons_config.PixelSnapH = true;
    icons_config.GlyphMaxAdvanceX = -1.3;
    io.Fonts->AddFontFromFileTTF(relativeToRealPath("../assets/codicon.ttf").c_str(), iconFontSize, &icons_config, icons_ranges );

    io.Fonts->AddFontFromFileTTF(relativeToRealPath("../assets/Satoshi-Regular.ttf").c_str(),  16.0f);
    io.Fonts->AddFontFromFileTTF(relativeToRealPath("../assets/JetBrainsMono.ttf").c_str(),    24.0f);
    io.Fonts->AddFontFromFileTTF(relativeToRealPath("../assets/Satoshi-Bold.ttf").c_str(),     19.0f);
    return io;
}
