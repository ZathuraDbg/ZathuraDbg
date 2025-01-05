#include "app.hpp"
bool enableDebugMode = false;
bool openFile = false;
bool saveFile = false;
bool saveFileAs = false;


bool showRequiredButton(const std::string& buttonName, bool state){
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[6]);
    if (buttonName == "Preview"){
        if (ImGui::Button(!state ? (ICON_CI_TRIANGLE_UP) : (ICON_CI_TRIANGLE_DOWN), {20, 30})){
            ImGui::PopFont();
            return true;
        }
        ImGui::PopFont();
        return false;
    }
    else if (buttonName == "Case"){
        if (ImGui::Button(ICON_CI_TEXT_SIZE, {20, 30})){
            ImGui::PopFont();
            return true;
        }
        ImGui::PopFont();
        return false;
    }
    else if (buttonName == "Ascii"){
        if (ImGui::Button(ICON_CI_SYMBOL_KEY, {20, 30})){
            ImGui::PopFont();
            return true;
        }
        ImGui::PopFont();
        return false;
    }
    else if (buttonName == "Options"){
        if (ImGui::Button(ICON_CI_ELLIPSIS, {20, 30})){
            ImGui::PopFont();
            return true;
        }
        ImGui::PopFont();
        return false;
    }
    ImGui::PopFont();
    return false;
}

bool setupButtons() {
    using namespace ImGui;

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[6]);

    if (ImGui::Button(ICON_CI_FILE_CODE, ImVec2(20, 20))) {
        openFile = true;
    }

    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::Text("Open File (CTRL+O)");
        ImGui::EndTooltip();
    }


    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();

    if (ImGui::Button(ICON_CI_SAVE, ImVec2(20, 20))) {
        fileSaveTask(selectedFile);
    }


    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::Text("Save File (CTRL+S)");
        ImGui::EndTooltip();
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();

    if (ImGui::Button(ICON_CI_DEBUG_START, ImVec2(20, 20))){
        debugRun = true;
    }

     if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::Text("Run (F10)");
        ImGui::EndTooltip();
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();

    if (!debugModeEnabled){
        if (ImGui::Button(ICON_CI_DEBUG, ImVec2(20, 20))){
            enableDebugMode = true;
        }

        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::Text("Start Debugging (F5)");
            ImGui::EndTooltip();
        }

    }
    else{
        if (ImGui::Button(ICON_CI_DEBUG_RERUN, ImVec2(20, 20))){
            debugRestart = true;
        }

        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::Text("Restart Debugging (CTRL+F5)");
            ImGui::EndTooltip();
        }

        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();

        if (ImGui::Button(ICON_CI_DEBUG_CONTINUE, ImVec2(20, 20))){
            debugContinue = true;
        }

        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::Text("Debug Continue (F5)");
            ImGui::EndTooltip();
        }

        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();

        if (ImGui::Button(ICON_CI_DEBUG_STEP_OVER, ImVec2(20, 20))){
            debugStepOver = true;
        }

        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::Text("Step Over (CTRL+K)");
            ImGui::EndTooltip();
        }

        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();

        if (ImGui::Button(ICON_CI_DEBUG_STEP_INTO, ImVec2(20, 20))){
            debugStepIn = true;
        }

        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::Text("Step In (CTRL+J)");
            ImGui::EndTooltip();
        }

        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();

        if (ImGui::Button(ICON_CI_DEBUG_PAUSE, ImVec2(20, 20))){
            debugPause = true;
        }

        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::Text("Pause (F6)");
            ImGui::EndTooltip();
        }

        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();

        if (ImGui::Button(ICON_CI_DEBUG_STOP, ImVec2(20, 20))){
            debugStop = true;
       }

        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::Text("Stop Debugging (Shift+F5)");
            ImGui::EndTooltip();
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
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::Text("Restart Debugging (CTRL+F5)");
        ImGui::EndTooltip();
    }
    ImGui::SameLine();
    ImGui::Separator();
    ImGui::PopFont();
    return true;
}
