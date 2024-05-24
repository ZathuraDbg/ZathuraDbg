#include "windows.hpp"

void consoleWindow()
{
    std::vector<std::string> test = {};
    const float footer_height_to_reserve = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();
    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footer_height_to_reserve), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);

    for (auto &t: test){
        ImGui::Text("%s", t.c_str());
    }

    ImGui::EndChild();
    char input[500]{};
    ImGui::PushID(&input);

    if (ImGui::InputText("Command", input, ImGuiInputTextFlags_AllowTabInput)){
        test.emplace_back(input);
    }

    ImGui::PopID();
    ImGui::End();
}