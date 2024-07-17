#include "app.hpp"
bool firstTime = true;

const char* items[] = {"Intel x86", "ARM", "RISC-V", "Really long text frfr"};
const char* x86ModeStr[] = {"16 bit", "32 bit", "64 bit"};
const uc_mode x86Modes[] = {UC_MODE_16, UC_MODE_32, UC_MODE_64};
const char* armModeStr[] = {"926", "946", "1176"};
const uc_mode armModes[] = {UC_MODE_ARM926, UC_MODE_ARM946, UC_MODE_ARM1176};

void appMenuBar()
{
    bool fileOpen = false;
    bool fileSave = false;
    bool fileSaveAs = false;
    bool saveContextToFile = false;
    bool fileLoadContext = false;
    bool changeEmulationSettings = false;
    bool quit = false;  // not using exit because it's a function from std to avoid confusion

    bool debugReset = false;
    bool debugStep = false;
    bool debugRun = false;

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[RubikRegular16]);
    if (ImGui::BeginMainMenuBar())
    {
        if (ImGui::BeginMenu("File"))
        {
            ImGui::MenuItem("Open", "Ctrl+O", &fileOpen);
            ImGui::MenuItem("Save", "Ctrl+S", &fileSave);
            ImGui::MenuItem("Save As", "Ctrl+Shift+S", &fileSaveAs);
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
            ImGui::MenuItem("Change emulation settings", "CTRL+,", &changeEmulationSettings);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Debug")){
            ImGui::MenuItem("Reset", "CTRL+Shift+R", &debugReset);
            ImGui::MenuItem("Run", "CTRL+R", &debugRun);
            ImGui::MenuItem("Step", "CTRL+J", &debugStep);
            ImGui::Separator();
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
    }

    if (fileOpen)
    {
        LOG_INFO("File open dialog requested!");
        fileOpenTask(openFileDialog());
    }
    if (fileSaveAs) {
        LOG_INFO("File save as dialog requested!");
        fileSaveAsTask( saveAsFileDialog());
    }
    if (fileSave){
        LOG_INFO("File save requested for the file: " << selectedFile);
        fileSaveTask(selectedFile);
    }
    if (quit){
        isRunning = false;
    }
    if (debugRun){
        fileRunTask();
    }
    if (debugStep){
        if (context == nullptr){
            LOG_DEBUG("Context is empty!");
            fileRunTask(1);
        }
        else{
            LOG_DEBUG("Context is not empty!");
            stepCode();
        }
    }
    if (debugReset){
        resetState();
    }
    if (saveContextToFile){
        fileSaveUCContextAsJson(saveAsFileDialog());
    }
    if (fileLoadContext){
        fileLoadUCContextFromJson(openFileDialog());
        uint64_t rip;
        int lineNumber;

        uc_reg_read(uc, regNameToConstant("RIP"), &rip);
        std::string str =  addressLineNoMap[std::to_string(rip)];
        if (!str.empty()) {
            lineNumber = std::atoi(str.c_str());
            editor->HighlightDebugCurrentLine(lineNumber - 1);
        }
    }
    if (changeEmulationSettings){
        ImGui::OpenPopup("Emulation Settings");
    }

    static int currentItem = 0;
    static int currentItem2 = 0;
    static const char* headerText = "Architecture settings";
    static uc_arch arch;
    static uc_mode mode;
    ImVec2 windowSize;
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold18]);
    ImGui::PushStyleVar(ImGuiStyleVar_PopupBorderSize, 5.0f);
    auto windowTextPos = ImGui::CalcTextSize(headerText);
    ImGui::SetNextWindowSize({240, 150});
    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImColor(0x1e, 0x20, 0x2f).Value);
    ImVec2 window_size = ImGui::GetIO().DisplaySize;
    ImVec2 popup_size = ImVec2(300, 150); // Define your popup size here
    ImVec2 popup_pos = ImVec2((window_size.x - popup_size.x) * 0.5f, (window_size.y - popup_size.y) * 0.5f);

    // Set next window position to center the popup
    ImGui::SetNextWindowPos(popup_pos, ImGuiCond_Appearing);
    if (ImGui::BeginPopup("Emulation Settings")){
        windowSize = ImGui::GetWindowSize();
        ImGui::SetCursorPosX((windowSize.x - windowTextPos.x) * 0.5f);
        ImGui::Text("%s", headerText);
        ImGui::SeparatorEx(ImGuiSeparatorFlags_Horizontal, 3);
        ImGui::Dummy(ImVec2(0.0f, 10.0f));
        ImGui::NewLine();
        ImGui::SameLine(0, 10);
        ImGui::Text("Architecture: ");
        ImGui::SameLine(0, 4);
        ImGui::SetNextItemWidth(ImGui::CalcTextSize(items[currentItem]).x * 2);
        ImGui::Combo("##Dropdown", &currentItem, items, IM_ARRAYSIZE(items));
        ImGui::Dummy({0, 1});
        ImGui::SameLine(0, 10);
        ImGui::Text("Mode: ");
        ImGui::SameLine(0, ImGui::CalcTextSize("Architecture: ").x - ImGui::CalcTextSize("Mode: ").x + 4);

        if (currentItem == arch::x86){
            ImGui::SetNextItemWidth(ImGui::CalcTextSize(x86ModeStr[currentItem2]).x * 2);
            ImGui::Combo("##Dropdown2", &currentItem2, x86ModeStr, IM_ARRAYSIZE(x86ModeStr));
            arch = UC_ARCH_X86;
            mode = x86Modes[currentItem2];
        }
        else if (currentItem == arch::ARM){
            ImGui::SetNextItemWidth(ImGui::CalcTextSize(armModeStr[currentItem2]).x * 2);
            ImGui::Combo("##Dropdown2", &currentItem2, armModeStr, IM_ARRAYSIZE(armModeStr));
            arch = UC_ARCH_ARM;
            mode = armModes[currentItem2];
        }

        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold18]);
        ImGui::Dummy({60, 4});

        ImGui::SetCursorPosX(windowSize.y - 55);
        if (ImGui::Button("CANCEL")){
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("APPLY")){
            codeInformation.arch = arch;
            codeInformation.mode = mode;
            ImGui::CloseCurrentPopup();
       }

        ImGui::PopFont();
        ImGui::EndPopup();
    }
    ImGui::PopStyleColor();
    codeInformation;
    ImGui::PopFont();
    ImGui::PopStyleVar();
    ImGui::PopFont();
}