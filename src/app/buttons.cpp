#include "app.hpp"
bool setupButtons() {
    using namespace ImGui;

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[6]);

    if (ImGui::Button(ICON_CI_FOLDER_OPENED, ImVec2(20, 20))) {
        resetState();
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

    if (ImGui::Button(ICON_CI_DEBUG_START, ImVec2(20, 20))){
        resetState();
        fileRunTask(0);
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();


    if (!debugModeEnabled){
        if (ImGui::Button(ICON_CI_DEBUG, ImVec2(20, 20))){
            resetState();
            debugModeEnabled = true;
            LOG_DEBUG("Context is empty!");
            fileRunTask(1);
        }
    }
    else{
        if (ImGui::Button(ICON_CI_DEBUG_RERUN, ImVec2(20, 20))){
            resetState();
            fileRunTask(1);
        }

        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();

        if (ImGui::Button(ICON_CI_DEBUG_CONTINUE, ImVec2(20, 20))){
            stepCode(0);
        }


        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();

        if (ImGui::Button(ICON_CI_DEBUG_STEP_OVER, ImVec2(20, 20))){
            uint64_t rip;
            int lineNo;

            uc_context_restore(uc, context);
            uc_context_reg_read(context, regNameToConstant("RIP"), &rip);
            std::string str = addressLineNoMap[std::to_string(rip)];

            if (!str.empty()){
                lineNo = std::stoi(str);
                breakpointLines.push_back(lineNo + 1);
                stepCode(0);
                continueOverBreakpoint = true;
            }
        }

        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();

        if (ImGui::Button(ICON_CI_DEBUG_STEP_INTO, ImVec2(20, 20))){
            stepCode();
        }

        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();

        if (ImGui::Button(ICON_CI_DEBUG_PAUSE, ImVec2(20, 20))){
            uc_context_save(uc, context);
            uc_emu_stop(uc);
        }

        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();

        if (ImGui::Button(ICON_CI_DEBUG_STOP, ImVec2(20, 20))){
            debugModeEnabled = false;
            resetState();
        }
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();

    if (ImGui::Button(ICON_CI_DEBUG_RESTART, ImVec2(20, 20))){
        resetState();
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::PopFont();
    return true;
}
