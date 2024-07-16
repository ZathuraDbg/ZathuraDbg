#include "app.hpp"
bool firstTime = true;

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
        ImGui::OpenPopup("EmulationSettings");
    }
    const char* items[] = {"Intel x86", "ARM", "RISC-V", "Really long text frfr"};
    const char* bits[] = {"16 bit", "32 bit", "64 bit"};
    enum arch{
        x86,
        ARM,
        RISCV
    };

    static int currentItem = 0;
    static int currentItem2 = 0;

    ImGui::SetNextWindowSize({250, 120});
    if (ImGui::BeginPopupModal("EmulationSettings")){
        ImGui::Text("Architecture: ");
        ImGui::SameLine(0, 4);
        ImGui::SetNextItemWidth(ImGui::CalcTextSize(items[currentItem]).x * 2);
        ImGui::Combo("##Dropdown", &currentItem, items, IM_ARRAYSIZE(items));
        if (currentItem == 0){
            ImGui::Text("Mode: ");
            ImGui::SameLine(0, ImGui::CalcTextSize("Architecture: ").x - ImGui::CalcTextSize("Mode: ").x + 4);
            ImGui::SetNextItemWidth(ImGui::CalcTextSize(bits[currentItem2]).x * 2);
            ImGui::Combo("##Dropdown2", &currentItem2, bits, IM_ARRAYSIZE(bits));
            ImGui::Text("You selected %s", bits[currentItem2]);
        }
        ImGui::EndPopup();
    }

    ImGui::PopFont();
}