#include "app.hpp"

bool setupButtons() {
    using namespace ImGui;

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[6]);

    if (ImGui::Button(ICON_CI_FOLDER_OPENED, ImVec2(20, 20))) {
        fileOpenTask(openFileDialog());
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();

    if (ImGui::Button(ICON_CI_SAVE, ImVec2(20, 20))) {
        fileSaveTask(selectedFile);
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();

    if (ImGui::Button(ICON_CI_DEBUG_RESTART, ImVec2(20, 20))){
        resetState();
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();

    if (ImGui::Button(ICON_CI_DEBUG_START, ImVec2(20, 20))){
        fileRunTask(0);
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();

    if (ImGui::Button(ICON_CI_DEBUG_CONTINUE, ImVec2(20, 20))){
        if (context == nullptr){
            fileRunTask(1);
        }
        else{
            stepCode();
        }
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();
    ImGui::Button(ICON_CI_DEBUG_PAUSE, ImVec2(20, 20));
    ImGui::PopFont();
    return true;
}
