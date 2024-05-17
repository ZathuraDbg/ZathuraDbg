#include "fonts.hpp"

ImGuiIO& setupIO(){
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;         // Enable Docking
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigDockingWithShift = true;

    io.ConfigViewportsNoAutoMerge = true;
    io.ConfigViewportsNoTaskBarIcon = true;
    io.Fonts->AddFontDefault();
    io.Fonts->AddFontFromFileTTF("../assets/Satoshi-Variable.ttf", 16.0f);
    io.Fonts->AddFontFromFileTTF("../assets/Satoshi-Variable.ttf", 18.0f);
    io.Fonts->AddFontFromFileTTF("../assets/JetBrainsMono.ttf", 20.0f);
    io.Fonts->AddFontFromFileTTF("../assets/Rubik-Regular.ttf", 16.0f);
    io.Fonts->AddFontFromFileTTF("../assets/Satoshi-Bold.ttf", 18.0f);
    io.Fonts->AddFontFromFileTTF("../assets/Satoshi-Medium.ttf", 18.0f);
    float baseFontSize = 24.0f; // 13.0f is the size of the default font. Change to the font size you use.
    float iconFontSize = baseFontSize * 2.0f / 3.0f; // FontAwesome fonts need to have their sizes reduced by 2.0f/3.0f in order to align correctly

// merge in icons from Font Awesome
    static const ImWchar icons_ranges[] = { ICON_MIN_CI, ICON_MAX_16_CI, 0 };
    ImFontConfig icons_config;
    icons_config.MergeMode = true;
    icons_config.PixelSnapH = true;
    icons_config.GlyphMinAdvanceX = iconFontSize;
    io.Fonts->AddFontFromFileTTF( "../assets/codicon.ttf", iconFontSize, &icons_config, icons_ranges );

    io.Fonts->AddFontFromFileTTF("../assets/Satoshi-Regular.ttf", 16.0f);
    return io;
}

