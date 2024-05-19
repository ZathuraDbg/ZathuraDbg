#include "app.hpp"

void setupButtons() {
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[6]);
    ImGui::Separator();

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
    ImGui::Button(ICON_CI_DEBUG_RESTART, ImVec2(20, 20));
    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();
    ImGui::Button(ICON_CI_DEBUG_START, ImVec2(20, 20));
    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();
    ImGui::Button(ICON_CI_DEBUG_CONTINUE, ImVec2(20, 20));
    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();
    ImGui::Button(ICON_CI_DEBUG_PAUSE, ImVec2(20, 20));
    ImGui::PopFont();
}

