#include "app.hpp"
#include "tasks/editorTasks.hpp"
bool toggleBreakpoint = false;
bool runUntilHere = false;
bool isRunning = true;
bool lineNumbersShown = true;
bool runSelectedCode = false;
bool goToDefinition = false;
std::string executablePath;
#include "codeContextMenu.hpp"

void setupEditor() {
    LOG_INFO("Setting up the editor...");
    auto selectedFileStream = std::ifstream(selectedFile);


    editor = new TextEditor();
    editor->SetLanguageDefinition(TextEditor::LanguageDefinitionId::Asmx86_64);
    editor->SetPalette(TextEditor::PaletteId::Catppuccin);
    editor->SetShowWhitespacesEnabled(false);
    editor->SetReadOnlyEnabled(false);
    editor->SetTabSize(4);

    if (!selectedFileStream.good()) {
        selectedFile = "";
        editor->SetText("; Press CTRL + O to open a file...");
    }
    else
    {
        std::string str((std::istreambuf_iterator<char>(selectedFileStream)), std::istreambuf_iterator<char>());
        editor->SetText(str);
    }

    LOG_INFO("Editor setup complete!");
}

void setupViewPort() {
    // set the position of the window just next to the menu bar (top left) using docking
    const ImGuiViewport *viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(viewport->Pos.x, viewport->Pos.y + ImGui::GetFrameHeight()));
    ImGui::SetNextWindowSize(ImVec2(500, 600));
    ImGui::SetNextWindowViewport(viewport->ID);
}


void loadIniFile() {
    std::string filename = relativeToRealPath(executablePath, "config.zlyt");
    const std::filesystem::path dir(filename);
    ImGui::LoadIniSettingsFromDisk(dir.string().c_str());
    LOG_DEBUG("Loaded config file from " << dir.string());
}

std::string getDataToCopy(std::stringstream &selectedAsmText, const bool asArray) {
    LOG_INFO("Getting data to copy...");
    const std::string bytes = getBytes(selectedAsmText);
    std::string dataToCopy;
    std::stringstream hexStream;
    hexStream << std::hex << std::uppercase << std::setfill('0');

    if (asArray){
        if (!bytes.empty()) {

            hexStream << "{";
            for (size_t i = 0; i < bytes.length(); ++i) {
                hexStream << "0x" << std::setw(2) << (static_cast<unsigned int>(bytes[i]) & 0xFF);
                hexStream << ", ";
            }
            dataToCopy = hexStream.str().erase(hexStream.str().length() - 2, 2);
            dataToCopy.append("}");
        }
    }
    else{
        for (size_t i = 0; i < bytes.length(); ++i) {
            hexStream << "\\x" << std::setw(2) << (static_cast<unsigned int>(bytes[i]) & 0xFF);
            dataToCopy = hexStream.str();
        }
    }

    LOG_INFO("Data acquired. Returning...");
    return dataToCopy;
}

void pushFont(){
    const ImGuiIO &io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[SatoshiBold18]);
}

void mainWindow() {
    const ImGuiIO &io = ImGui::GetIO();
    bool keepWindow = true;

    setupAppStyle();
    ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport());

    appMenuBar();
    setupViewPort();

    ImGui::Begin("Code", &keepWindow, ImGuiWindowFlags_NoCollapse);

    setupButtons();

    if (!editor->FontInit){
        editor->FontInit = pushFont;
        editor->CreateLabelLineMap = createLabelLineMapCallback;
        editor->ParseStrIntoCoordinates = parseStrIntoCoordinates;
        editor->CompletionCallback = reinterpret_cast<ImGuiInputTextCallback (*)(
                ImGuiInputTextCallbackData *)>(labelCompletionCallback);
        editor->PasteCallback = pasteCallback;
    }

    ImGui::PushFont(io.Fonts->Fonts[JetBrainsMono24]);
    editor->Render("Editor");
    ImGui::PopFont();
    contextMenu();

    ImGui::Begin("Register Values", &keepWindow, ImGuiWindowFlags_NoCollapse);
    registerWindow();

    ImGui::Begin("Console", &keepWindow, ImGuiWindowFlags_NoCollapse);
    consoleWindow();

    ImGui::End();
    hexEditorWindow();

    ImGui::Begin("Stack", &keepWindow, ImGuiWindowFlags_NoCollapse);
    stackEditorWindow();
    ImGui::End();

    manageShortcuts();
    runActions();
    //    Utils::LayoutManager::save(CONFIG_NAME);
    ImGui::Render();
}
