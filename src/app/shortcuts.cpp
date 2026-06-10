#include "shortcuts.hpp"

float gFontScale = 1.0f;

void manageShortcuts(){
    using namespace ImGui;
    ImGuiIO& io = ImGui::GetIO();
    const auto isOSX = io.ConfigMacOSXBehaviors;
    const auto alt = io.KeyAlt;
    const auto ctrl = io.KeyCtrl;
    const auto shift = io.KeyShift;
    const auto super = io.KeySuper;

    const auto isCtrlShortcut = (isOSX ? (super && !ctrl) : (ctrl && !super)) && !alt && !shift;
    const auto isCtrlShiftShortcut = (isOSX ? (super && !ctrl) : (ctrl && !super)) && shift && !alt;
    const auto isWordMoveKey = isOSX ? alt : ctrl;
    const auto isAltOnly = alt && !ctrl && !shift && !super;
    const auto isCtrlOnly = ctrl && !alt && !shift && !super;
    const auto isShiftOnly = shift && !alt && !ctrl && !super;

    io.WantCaptureKeyboard = true;
    io.WantTextInput = true;

    if (isCtrlShortcut && (ImGui::IsKeyPressed(ImGuiKey_S))){
        saveFile = true;
    }
    if (isCtrlShiftShortcut && (ImGui::IsKeyPressed(ImGuiKey_S))){
        saveFileAs = true;
    }
    if (isCtrlShortcut && (ImGui::IsKeyPressed(ImGuiKey_O))){
        openFile = true;
    }
    if (isCtrlShortcut && (ImGui::IsKeyPressed(ImGuiKey_Period))){
        changeEmulationSettingsOpt = true;
    }
    if (isCtrlShortcut && (ImGui::IsKeyDown(ImGuiKey_F7)))
    {
        memoryMapsUI = true;
    }
    if (isCtrlShiftShortcut && (ImGui::IsKeyPressed(ImGuiKey_M))){
       saveContextToFile = true;
    }
    if (isCtrlShiftShortcut && (ImGui::IsKeyPressed(ImGuiKey_O))){
        fileSerializeState = true;
    }
    if (isCtrlOnly && IsKeyPressed(ImGuiKey_GraveAccent)){
        use32BitLanes = !use32BitLanes;
        updateRegistersOnLaneChange();
    }
    const auto noMod = !alt && !ctrl && !shift && !super;

    // --- Debugger controls: standard IDE keys (VS Code / Visual Studio) ------
    // These avoid the Ctrl+J/Ctrl+K bindings that browsers steal (Downloads,
    // search bar) and match what developers expect everywhere.
    //
    //   F5            Start debugging / Continue
    //   Shift+F5      Stop
    //   Ctrl+F5       Run without debugging
    //   Ctrl+Shift+F5 Restart
    //   F10           Step over
    //   F11           Step into
    //   Shift+F11     Step back (time-travel)
    //   F9            Toggle breakpoint
    //   F6            Pause
    if (isShiftOnly && IsKeyPressed(ImGuiKey_F5)){
        if (debugModeEnabled){
            debugStop = true;
        }
        return;
    }
    if (isCtrlShiftShortcut && IsKeyPressed(ImGuiKey_F5)){
        if (debugModeEnabled){
            debugRestart = true;
        }
        return;
    }
    if (isCtrlShortcut && IsKeyPressed(ImGuiKey_F5)){
        debugRun = true;
        return;
    }
    if (noMod && IsKeyPressed(ImGuiKey_F5)){
        if (!debugModeEnabled){
            enableDebugMode = true;
        }
        else{
            debugContinue = true;
        }
    }

    if (debugModeEnabled){
        if (noMod && IsKeyPressed(ImGuiKey_F10)){
            debugStepOver = true;
        }
        if (noMod && IsKeyPressed(ImGuiKey_F11)){
            debugStepIn = true;
        }
        if (ttdEnabled && isShiftOnly && IsKeyPressed(ImGuiKey_F11)){
            debugStepBack = true;
        }
    }

    if (noMod && IsKeyPressed(ImGuiKey_F9)){
        toggleBreakpoint = true;
    }
    if (noMod && IsKeyPressed(ImGuiKey_F6)){
        debugPause = true;
    }
    if (noMod && IsKeyPressed(ImGuiKey_F3)){
        runSelectedCode = true;
    }
    if (noMod && IsKeyPressed(ImGuiKey_F4)){
        goToDefinition = true;
    }

    if (isCtrlShiftShortcut && IsKeyPressed(ImGuiKey_Equal)) {
        gFontScale = gFontScale < 2.5f ? gFontScale + 0.1f : 2.5f;
    }
    if (isCtrlShiftShortcut && IsKeyPressed(ImGuiKey_Minus)) {
        gFontScale = gFontScale > 0.5f ? gFontScale - 0.1f : 0.5f;
    }
    if (isCtrlShiftShortcut && IsKeyPressed(ImGuiKey_0)) {
        gFontScale = 1.0f;
    }
}