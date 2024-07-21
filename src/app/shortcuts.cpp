#include "shortcuts.hpp"

void manageShortcuts(){
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
        fileSaveTask(selectedFile);
    }
    if (isCtrlShiftShortcut && (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_S)))){
        fileSaveAsTask(saveAsFileDialog());
    }
    if (isCtrlShortcut && (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_O)))){
        fileOpenTask(openFileDialog());
    }

    if (isCtrlShortcut && (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_Period)))){
        changeEmulationSettings();
    }

    if (isCtrlShiftShortcut && (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_M)))){
        fileSaveUCContextAsJson(saveAsFileDialog());
    }

    if (isCtrlShiftShortcut && (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_O)))){
        fileLoadUCContextFromJson(openFileDialog());
    }
}