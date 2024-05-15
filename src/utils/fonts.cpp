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
    io.Fonts->AddFontFromFileTTF("../assets/Rubik-Regular.ttf", 20.0f);
    io.Fonts->AddFontFromFileTTF("../assets/Satoshi-Bold.ttf", 18.0f);
    io.Fonts->AddFontFromFileTTF("../assets/Satoshi-Medium.ttf", 18.0f);
    return io;
}

