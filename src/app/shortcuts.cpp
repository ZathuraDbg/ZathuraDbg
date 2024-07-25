#include "shortcuts.hpp"

void manageShortcuts(){
    using namespace ImGui;
    ImGuiIO& io = ImGui::GetIO();
    auto isOSX = io.ConfigMacOSXBehaviors;
    auto alt = io.KeyAlt;
    auto ctrl = io.KeyCtrl;
    auto shift = io.KeyShift;
    auto super = io.KeySuper;

    auto isCtrlShortcut = (isOSX ? (super && !ctrl) : (ctrl && !super)) && !alt && !shift;
    auto isCtrlShiftShortcut = (isOSX ? (super && !ctrl) : (ctrl && !super)) && shift && !alt;
    auto isWordMoveKey = isOSX ? alt : ctrl;
    auto isAltOnly = alt && !ctrl && !shift && !super;
    auto isCtrlOnly = ctrl && !alt && !shift && !super;
    auto isShiftOnly = shift && !alt && !ctrl && !super;

    io.WantCaptureKeyboard = true;
    io.WantTextInput = true;

    if (isCtrlShortcut && (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_S)))){
        saveFile = true;
    }
    if (isCtrlShiftShortcut && (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_S)))){
        saveFileAs = true;
    }
    if (isCtrlShortcut && (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_O)))){
        openFile = true;
    }
    if (isCtrlShortcut && (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_Period)))){
        changeEmulationSettingsOpt = true;
    }
    if (isCtrlShiftShortcut && (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_M)))){
       saveContextToFile = true;
    }
    if (isCtrlShiftShortcut && (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_O)))){
        fileLoadContext = true;
    }
    if (isShiftOnly && (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_F5)))){
        if (isCodeRunning){
            debugStop = true;
        }
        return;
    }
    else if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_F5))){
        if (!debugModeEnabled){
            enableDebugMode = true;
        }
        else if ((isCtrlShortcut) &&ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_F5))){
            debugRestart = true;
        }
        else{
            debugContinue = true;
        }
    }
    if (isCtrlShortcut && (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_J)))){
        debugStepIn = true;
    }
    if (isCtrlShortcut && (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_K)))){
        debugStepOver = true;
    }
    if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_F9))){
        toggleBreakpoint = true;
    }
    if (IsKeyPressed(GetKeyIndex(ImGuiKey_F3))){
        runSelectedCode = true;
    }
    if (IsKeyPressed(GetKeyIndex(ImGuiKey_F4))){
        goToDefinition = true;
    }
}