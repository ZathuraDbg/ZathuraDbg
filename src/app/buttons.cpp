#include "app.hpp"
bool enableDebugMode = false;
bool openFile = false;
bool saveFile = false;
bool saveFileAs = false;

bool setupButtons() {
    using namespace ImGui;

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[6]);

    if (ImGui::Button(ICON_CI_FOLDER_OPENED, ImVec2(20, 20))) {
        openFile = true;
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

    if (ImGui::Button(ICON_CI_DEBUG_START, ImVec2(20, 20))){
        debugRun = true;
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();


    if (!debugModeEnabled){
        if (ImGui::Button(ICON_CI_DEBUG, ImVec2(20, 20))){
            enableDebugMode = true;
        }
    }
    else{
        if (ImGui::Button(ICON_CI_DEBUG_RERUN, ImVec2(20, 20))){
            debugRestart = true;
        }

        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();

        if (ImGui::Button(ICON_CI_DEBUG_CONTINUE, ImVec2(20, 20))){
            debugContinue = true;
        }

        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();

        if (ImGui::Button(ICON_CI_DEBUG_STEP_OVER, ImVec2(20, 20))){
            debugStepOver = true;
        }

        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();

        if (ImGui::Button(ICON_CI_DEBUG_STEP_INTO, ImVec2(20, 20))){
            debugStepIn = true;
        }

        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();

        if (ImGui::Button(ICON_CI_DEBUG_PAUSE, ImVec2(20, 20))){
            debugPause = true;
        }

        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();

        if (ImGui::Button(ICON_CI_DEBUG_STOP, ImVec2(20, 20))){
            debugStop = true;
       }
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();

    if (!debugModeEnabled){
        if (ImGui::Button(ICON_CI_DEBUG_RESTART, ImVec2(20, 20))){
            resetState();
        }
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::PopFont();
    return true;
}
