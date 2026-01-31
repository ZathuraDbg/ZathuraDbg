#include "app.hpp"
bool firstTime = true;
//
const char* architectureStrings[] = {"Intel x86_64", "AArch32", "AArch64", "RISC-V", "PowerPC"};
const char* ksSyntaxOptStr[] = {"Intel", "AT&T", "NASM", "GAS"};
const ks_opt_value ksSyntaxOpts[] = {KS_OPT_SYNTAX_INTEL, KS_OPT_SYNTAX_ATT, KS_OPT_SYNTAX_NASM, KS_OPT_SYNTAX_GAS};
// ARM architecture modes
const char* armModeStr[] = {"ARM", "Thumb"};
const ks_mode armKSModes[] = {KS_MODE_ARM, KS_MODE_THUMB};
const cs_mode armCSModes[] = {CS_MODE_ARM, CS_MODE_THUMB};

bool debugRestart = false;
bool memoryMapsUI = false;
bool debugStepIn = false;
bool debugStepOver = false;
bool debugContinue = false;
bool debugPause = false;
bool debugStop = false;
bool debugRun = false;
bool saveContextToFile = false;
bool fileSerializeState = false;
bool fileDeserializeState = false;
bool changeEmulationSettingsOpt = false;
bool debugStepBack = false;
bool ttdEnabled = false;
bool showUpdateWindow = false;
bool showEmuSettings = false;

void changeEmulationSettings(){
    showEmuSettings = true;
    ImGui::OpenPopup("Emulation Settings");
    static int selectedArch = 0;
    static int selectedMode = 0;
    static int selectedSyntax = 2;
    static auto headerText = "Architecture settings";

    static icArch icArch;
    static uc_mode ucMode;
    static ks_mode ksMode;
    static ks_arch ksArch;
    static cs_arch csArch;
    static cs_mode csMode;

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold18]);
    ImGui::PushStyleVar(ImGuiStyleVar_PopupBorderSize, 5.0f);
    auto windowTextPos = ImGui::CalcTextSize(headerText);

    // {width, height}
    constexpr auto popupSize = ImVec2(270, 150);
    ImGui::SetNextWindowSize(popupSize);
    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImColor(0x1e, 0x20, 0x2f).Value);
    ImVec2 windowSize = ImGui::GetIO().DisplaySize;
    ImVec2 popupPos = ImVec2((windowSize.x - popupSize.x) * 0.5f, (windowSize.y - popupSize.y) * 0.5f);

    ImGui::SetNextWindowPos(popupPos, ImGuiCond_Appearing);
    if (ImGui::BeginPopup("Emulation Settings")){
        const ImVec2 windowSize = ImGui::GetWindowSize();
        ImGui::SetCursorPosX((windowSize.x - windowTextPos.x) * 0.5f);
        ImGui::Text("%s", headerText);
        ImGui::SeparatorEx(ImGuiSeparatorFlags_Horizontal, 3);
        ImGui::Dummy(ImVec2(0.0f, 10.0f));
        ImGui::NewLine();
        ImGui::SameLine(0, 10);
        ImGui::Text("Architecture: ");
        ImGui::SameLine(0, 4);
        ImGui::SetNextItemWidth(150);

        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiMedium18]);
        ImGui::Combo("##Dropdown", &selectedArch, architectureStrings, IM_ARRAYSIZE(architectureStrings));
        ImGui::PopFont();

        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiMedium18]);
        if (selectedArch == arch::x86){
            ImGui::Dummy({0, 1});
            ImGui::SameLine(0, 10);
            ImGui::Text("Syntax: ");
            ImGui::SameLine(0, ImGui::CalcTextSize("Architecture: ").x - ImGui::CalcTextSize("Mode: ").x + 2);
            ImGui::SetNextItemWidth(ImGui::CalcTextSize(ksSyntaxOptStr[selectedSyntax]).x * 2 + 10);
            ImGui::Combo("##Dropdown3", &selectedSyntax, ksSyntaxOptStr, IM_ARRAYSIZE(ksSyntaxOpts));
            icArch = IC_ARCH_X86_64;
            ksArch = KS_ARCH_X86;
            csArch = CS_ARCH_X86;
            ksMode = KS_MODE_64;
            csMode = CS_MODE_64;
            ucMode = UC_MODE_64;
            codeInformation.syntax = KS_OPT_SYNTAX_NASM;
            codeInformation.archStr = "x86_64";
            currentDefinitionId = TextEditor::LanguageDefinitionId::Asm;
        }
        else if (selectedArch == arch::ARM)
        {
            ImGui::Dummy({0, 1});
            ImGui::SameLine(0, 10);
            ImGui::Text("Mode: ");
            ImGui::SameLine(0, 50);
            ImGui::SetNextItemWidth(150);
            ImGui::Combo("##Dropdown2", &selectedMode, armModeStr, IM_ARRAYSIZE(armModeStr));
            ksArch = KS_ARCH_ARM;
            csArch = CS_ARCH_ARM;

            if (selectedMode == 0) {
                icArch = IC_ARCH_ARM;
                ksMode = armKSModes[selectedMode];
                csMode = armCSModes[selectedMode];
                codeInformation.syntax = KS_OPT_SYNTAX_RADIX16;
                codeInformation.archStr = "arm";
            }
            else if (selectedMode == 1)
            {
                icArch = IC_ARCH_THUMBV7M;
                ksMode = armKSModes[selectedMode];
                csMode = armCSModes[selectedMode];
                codeInformation.syntax = KS_OPT_SYNTAX_RADIX16;
                codeInformation.archStr = "thumbv7m";
            }

            currentDefinitionId = TextEditor::LanguageDefinitionId::AsmArm;
        }
        else if (selectedArch == arch::ARM64)
        {
            icArch = IC_ARCH_AARCH64;
            ksArch = KS_ARCH_ARM64;
            csArch = CS_ARCH_ARM64;
            ksMode = KS_MODE_LITTLE_ENDIAN;
            csMode = CS_MODE_LITTLE_ENDIAN;
            // codeInformation.syntax = KS_OPT_SYNTAX_RADIX16;
            codeInformation.archStr = "aarch64";
            ImGui::Dummy({20, 25});
            currentDefinitionId = TextEditor::LanguageDefinitionId::AsmArm;
        }
        else {
            tinyfd_messageBox("Unsupported Architecture!", "Only x86 and ARM Architectures are supported with ZathuraDbg at this point."
                                                           "\nOthers will be coming sooner.", "ok", "info", 0);
            selectedArch = arch::x86;
            ucMode = UC_MODE_64;
            ksMode = KS_MODE_64;
            csMode = CS_MODE_64;
        }

        ImGui::PopFont();
        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold18]);
        ImGui::SetCursorPosX(windowSize.y);
        if (ImGui::Button("OK")){
            codeInformation.archIC = icArch;
            codeInformation.mode = ucMode;
            codeInformation.modeKS = ksMode;
            codeInformation.archKS = ksArch;
            codeInformation.archCS = csArch;
            codeInformation.modeCS = csMode;
            registerValueMap.clear();
            registerValueMap = {};
            onArchChange();
            resetState();
            editor->HighlightBreakpoints(-1);
            breakpointLines.clear();
            breakpointLines = {};
            ImGui::CloseCurrentPopup();
            showEmuSettings = false;
            changeEmulationSettingsOpt = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("CANCEL")){
            ImGui::CloseCurrentPopup();
            showEmuSettings = false;
            changeEmulationSettingsOpt = false;
        }

        ImGui::PopFont();
        ImGui::EndPopup();
    }
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    ImGui::PopFont();
}


void appMenuBar()
{
    bool quit = false;

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[RubikRegular16]);
    if (ImGui::BeginMainMenuBar())
    {
        if (ImGui::BeginMenu("File"))
        {
            ImGui::MenuItem("Open", "Ctrl+O", &openFile);
            ImGui::MenuItem("New File", "Ctrl+N", &createFile);
            ImGui::MenuItem("Save", "Ctrl+S", &saveFile);
            ImGui::MenuItem("Save As", "Ctrl+Shift+S", &saveFileAs);
            ImGui::MenuItem("Save State To File", "Ctrl+Shift+M", &fileSerializeState);
            ImGui::MenuItem("Load State From File", "Ctrl+Shift+O", &fileDeserializeState);
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
            ImGui::MenuItem("Check for updates", nullptr, &showUpdateWindow, true);
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
            ImGui::MenuItem("Memory maps", "CTRL+F7", &memoryMapsUI, debugModeEnabled ? true : false);
            ImGui::MenuItem("Enable time travel debugging", nullptr, &ttdEnabled, true);
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