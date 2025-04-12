#include "app.hpp"
bool firstTime = true;
//
// const char* architectureStrings[] = {"Intel x86", "ARM", "RISC-V", "PowerPC"};
// const cs_arch csArchs[]    = {CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_RISCV, CS_ARCH_PPC};
// const char* ksSyntaxOptStr[] = {"Intel", "AT&T", "NASM", "GAS"};
// const ks_opt_value ksSyntaxOpts[] = {KS_OPT_SYNTAX_INTEL, KS_OPT_SYNTAX_ATT, KS_OPT_SYNTAX_NASM, KS_OPT_SYNTAX_GAS};
//
// const char* x86ModeStr[] = {"16 bit", "32 bit", "64 bit"};
// const uc_mode x86UCModes[] = {UC_MODE_16, UC_MODE_32, UC_MODE_64};
// const ks_mode x86KSModes[] = {KS_MODE_16, KS_MODE_32, KS_MODE_64};
// const cs_mode x86CSModes[] = {CS_MODE_16, CS_MODE_32, CS_MODE_64};
//
// const char* armModeStr[]   = {"926", "946", "1176"};
// const uc_mode armUCModes[] = {UC_MODE_ARM926, UC_MODE_ARM946, UC_MODE_ARM1176};
// const ks_mode armKSModes[] = {KS_MODE_ARM, KS_MODE_THUMB, KS_MODE_V8, KS_MODE_V9};
// const cs_mode armCSMOdes[] = {CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_V8, CS_MODE_V9};

bool debugRestart = false;
bool memoryMapsUI = false;
bool debugStepIn = false;
bool debugStepOver = false;
bool debugContinue = false;
bool debugPause = false;
bool debugStop = false;
bool debugRun = false;
bool saveContextToFile = false;
bool fileLoadContext = false;
bool changeEmulationSettingsOpt = false;
bool showEmuSettings = false;

// void changeEmulationSettings(){
//     showEmuSettings = true;
//     ImGui::OpenPopup("Emulation Settings");
//     static int selectedArch = 0;
//     static int selectedMode = 2;
//     static int selectedSyntax = 2;
//     static auto headerText = "Architecture settings";
//
//     static uc_arch ucArch;
//     static uc_mode ucMode;
//     static ks_mode ksMode;
//     static ks_arch ksArch;
//     static cs_arch csArch;
//     static cs_mode csMode;
//
//     ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold18]);
//     ImGui::PushStyleVar(ImGuiStyleVar_PopupBorderSize, 5.0f);
//     auto windowTextPos = ImGui::CalcTextSize(headerText);
//
//     // {width, height}
//     ImVec2 popup_size = ImVec2(240, 175);
//     ImGui::SetNextWindowSize(popup_size);
//     ImGui::PushStyleColor(ImGuiCol_PopupBg, ImColor(0x1e, 0x20, 0x2f).Value);
//     ImVec2 window_size = ImGui::GetIO().DisplaySize;
//     ImVec2 popup_pos = ImVec2((window_size.x - popup_size.x) * 0.5f, (window_size.y - popup_size.y) * 0.5f);
//
//     ImGui::SetNextWindowPos(popup_pos, ImGuiCond_Appearing);
//     if (ImGui::BeginPopup("Emulation Settings")){
//         const ImVec2 windowSize = ImGui::GetWindowSize();
//         ImGui::SetCursorPosX((windowSize.x - windowTextPos.x) * 0.5f);
//         ImGui::Text("%s", headerText);
//         ImGui::SeparatorEx(ImGuiSeparatorFlags_Horizontal, 3);
//         ImGui::Dummy(ImVec2(0.0f, 10.0f));
//         ImGui::NewLine();
//         ImGui::SameLine(0, 10);
//         ImGui::Text("Architecture: ");
//         ImGui::SameLine(0, 4);
//         ImGui::SetNextItemWidth(ImGui::CalcTextSize(architectureStrings[selectedArch]).x * 2);
//
//         ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiMedium18]);
//         ImGui::Combo("##Dropdown", &selectedArch, architectureStrings, IM_ARRAYSIZE(architectureStrings));
//         ImGui::PopFont();
//         ImGui::Dummy({0, 1});
//         ImGui::SameLine(0, 10);
//         ImGui::Text("Mode: ");
//         ImGui::SameLine(0, ImGui::CalcTextSize("Architecture: ").x - ImGui::CalcTextSize("Mode: ").x + 4);
//
//         ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiMedium18]);
//         if (selectedArch == arch::x86){
//             ImGui::SetNextItemWidth(ImGui::CalcTextSize(x86ModeStr[selectedMode]).x * 2 + 10);
//             ImGui::Combo("##Dropdown2", &selectedMode, x86ModeStr, IM_ARRAYSIZE(x86ModeStr));
//             ucArch = UC_ARCH_X86;
//             ksArch = KS_ARCH_X86;
//             csArch = CS_ARCH_X86;
//             ucMode = x86UCModes[selectedMode];
//             ksMode = x86KSModes[selectedMode];
//             csMode = x86CSModes[selectedMode];
//         }
//         // will be implemented later
//         // else if (selectedArch == arch::ARM){
//         //     ImGui::SetNextItemWidth(ImGui::CalcTextSize(armModeStr[selectedMode]).x * 2 + 10);
//         //     ImGui::Combo("##Dropdown2", &selectedMode, armModeStr, IM_ARRAYSIZE(armModeStr));
//         //     ucArch = UC_ARCH_ARM;
//         //     ksArch = KS_ARCH_ARM;
//         //     csArch = CS_ARCH_ARM;
//         //     ucMode = armUCModes[selectedMode];
//         //     ksMode = armKSModes[selectedMode];
//         // }
//         else {
//             tinyfd_messageBox("Unsupported Architecture!", "Only x86 Architecture is supported with ZathuraDbg at this point."
//                                                            "\nOther will be coming sooner.", "ok", "info", 0);
//             selectedArch = arch::x86;
//             ucMode = UC_MODE_64;
//             ksMode = KS_MODE_64;
//             csMode = CS_MODE_64;
//         }
//
//         ImGui::Dummy({0, 1});
//         ImGui::SameLine(0, 10);
//         ImGui::Text("Syntax: ");
//         ImGui::SameLine(0, ImGui::CalcTextSize("Architecture: ").x - ImGui::CalcTextSize("Mode: ").x + 2);
//         ImGui::SetNextItemWidth(ImGui::CalcTextSize(ksSyntaxOptStr[selectedSyntax]).x * 2 + 10);
//         ImGui::Combo("##Dropdown3", &selectedSyntax, ksSyntaxOptStr, IM_ARRAYSIZE(ksSyntaxOpts));
//
//         ImGui::PopFont();
//
//         ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold18]);
//         ImGui::Dummy({60, 4});
//
//         ImGui::SetCursorPosX(windowSize.y - 50);
//         if (ImGui::Button("OK")){
//             codeInformation.archIC = ucArch;
//             codeInformation.mode = ucMode;
//             codeInformation.modeKS = ksMode;
//             codeInformation.archKS = ksArch;
//             codeInformation.syntax = ksSyntaxOpts[selectedSyntax];
//             codeInformation.archCS = csArch;
//             codeInformation.modeCS = csMode;
//             registerValueMap.clear();
//             registerValueMap = {};
//             onArchChange();
//             resetState();
//             editor->HighlightBreakpoints(-1);
//             breakpointLines.clear();
//             breakpointLines = {};
//             ImGui::CloseCurrentPopup();
//             showEmuSettings = false;
//             changeEmulationSettingsOpt = false;
//         }
//         ImGui::SameLine();
//         if (ImGui::Button("CANCEL")){
//             ImGui::CloseCurrentPopup();
//             showEmuSettings = false;
//             changeEmulationSettingsOpt = false;
//         }
//
//         ImGui::PopFont();
//         ImGui::EndPopup();
//     }
//     ImGui::PopStyleVar();
//     ImGui::PopStyleColor();
//     ImGui::PopFont();
// }
//

void appMenuBar()
{
    bool quit = false;  // not using exit because it's a function from std to avoid confusion

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[RubikRegular16]);
    if (ImGui::BeginMainMenuBar())
    {
        if (ImGui::BeginMenu("File"))
        {
            ImGui::MenuItem("Open", "Ctrl+O", &openFile);
            ImGui::MenuItem("Save", "Ctrl+S", &saveFile);
            ImGui::MenuItem("Save As", "Ctrl+Shift+S", &saveFileAs);
            ImGui::MenuItem("Save context to file", "Ctrl+Shift+M", &saveContextToFile);
            ImGui::MenuItem("Load context from file", "Ctrl+Shift+O", &fileLoadContext);
            ImGui::Separator();
            ImGui::MenuItem("Exit", "Alt+F4", &quit);
            ImGui::Separator();
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Edit"))
        {
            if (ImGui::MenuItem("Undo", "CTRL+Z")) {
                if (editor->CanUndo()){
                    editor->Undo();
                    LOG_INFO("Editor serviced undo");
                }
                else{
                    LOG_ERROR("Undo requested but couldn't be fulfilled by editor");
                }
            }
            if (ImGui::MenuItem("Redo", "CTRL+Y", false)) {
                if (editor->CanRedo()){
                    editor->Redo();
                    LOG_INFO("Editor serviced redo");
                }
                else{
                    LOG_ERROR("Redo requested but couldn't be fulfilled by editor");
                }

            }
            ImGui::Separator();
            if (ImGui::MenuItem("Cut", "CTRL+X")) {
                editor->Cut();
                LOG_INFO("Editor cut to clipboard");
            }
            if (ImGui::MenuItem("Copy", "CTRL+C")) {
                editor->Copy();
                LOG_INFO("Editor copied to clipboard");
            }
            if (ImGui::MenuItem("Paste", "CTRL+V")) {
                editor->Paste();
                LOG_INFO("Editor pasted from clipboard");
            }
            ImGui::Separator();
            ImGui::MenuItem("Change emulation settings", "CTRL+.", &changeEmulationSettingsOpt);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Debug")){
            if (!debugModeEnabled){
                ImGui::MenuItem("Debug", "F5", &enableDebugMode);
            }
            else{
                ImGui::MenuItem("Stop debugging", "Shift+F5", &debugStop);
            }
            ImGui::MenuItem("Step In", "CTRL+J", &debugStepIn, debugModeEnabled ? true : false);
            ImGui::MenuItem("Step Over", "CTRL+K", &debugStepOver, debugModeEnabled ? true : false);
            ImGui::MenuItem("Continue", debugModeEnabled ? "F5" : nullptr, &debugContinue, debugModeEnabled ? true : false);
            ImGui::MenuItem("Restart debugging", "CTRL+F5", &debugRestart, debugModeEnabled ? true : false);
            ImGui::MenuItem("Memory maps", "CTRL+F7", &memoryMapsUI, true);
            ImGui::Separator();
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
    }

    if (quit){
        isRunning = false;
    }

    ImGui::PopFont();
}