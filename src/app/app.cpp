#include "app.hpp"
#include "tasks/editorTasks.hpp"
#include "../utils/runtimePaths.hpp"
bool toggleBreakpoint = false;
bool runUntilHere = false;
bool isRunning = true;
bool lineNumbersShown = true;
bool runSelectedCode = false;
bool goToDefinition = false;
std::string executablePath;
#include "codeContextMenu.hpp"
TextEditor::LanguageDefinitionId currentDefinitionId = TextEditor::LanguageDefinitionId::Asm;

namespace {
bool remoteEditorViewActive = false;
std::string cachedLocalEditorText{};
TextEditor::LanguageDefinitionId cachedLocalDefinitionId = TextEditor::LanguageDefinitionId::Asm;
}

void setupEditor() {
    LOG_INFO("Setting up the editor...");
    auto selectedFileStream = std::ifstream(selectedFile);


    editor = new TextEditor();
    editor->SetLanguageDefinition(currentDefinitionId);
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
        const std::string str((std::istreambuf_iterator<char>(selectedFileStream)), std::istreambuf_iterator<char>());
        editor->SetText(str);
    }

    LOG_INFO("Editor setup complete!");
}

bool editorShowingRemoteDisassembly() {
    return remoteEditorViewActive;
}

void showRemoteDisassemblyInEditor(const std::string& text, const int currentLine) {
    if (editor == nullptr) {
        return;
    }

    if (!remoteEditorViewActive) {
        cachedLocalEditorText = editor->GetText();
        cachedLocalDefinitionId = currentDefinitionId;
        remoteEditorViewActive = true;
    }

    editor->SetReadOnlyEnabled(false);
    editor->SetLanguageDefinition(currentDefinitionId);
    if (editor->GetText() != text) {
        editor->SetText(text);
    }
    editor->SetReadOnlyEnabled(true);

    editor->ClearCustomLineNumberLabels();

    if (currentLine >= 0) {
        editor->SetCursorPosition(currentLine, 0);
    }
}

void showRemoteDisassemblyInEditor(const std::string& text, const int currentLine,
                                   const std::map<int, std::string>& lineAddressLabels) {
    showRemoteDisassemblyInEditor(text, currentLine);
    if (editor != nullptr) {
        editor->SetCustomLineNumberLabels(lineAddressLabels);
    }
}

void showRemoteDisassemblyInEditor(const std::string& text, const int currentLine,
                                   const std::map<int, std::string>& lineOffsetLabels,
                                   const std::map<int, std::string>& lineAddressLabels) {
    showRemoteDisassemblyInEditor(text, currentLine);
    if (editor != nullptr) {
        editor->SetCustomLineNumberLabels(lineOffsetLabels, lineAddressLabels);
    }
}

void restoreLocalEditorAfterRemoteSession() {
    if (editor == nullptr || !remoteEditorViewActive) {
        return;
    }

    editor->SetReadOnlyEnabled(false);
    currentDefinitionId = cachedLocalDefinitionId;
    editor->SetLanguageDefinition(currentDefinitionId);
    editor->SetText(cachedLocalEditorText.empty() ? "; Press CTRL + O to open a file..." : cachedLocalEditorText);
    editor->HighlightDebugCurrentLine(-1);
    editor->HighlightBreakpoints(-1, true);

    cachedLocalEditorText.clear();
    remoteEditorViewActive = false;
}

void setupViewPort() {
    // set the position of the window just next to the menu bar (top left) using docking
    const ImGuiViewport *viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(viewport->Pos.x, viewport->Pos.y + ImGui::GetFrameHeight()));
    ImGui::SetNextWindowSize(ImVec2(500, 600));
    ImGui::SetNextWindowViewport(viewport->ID);
}


void loadIniFile() {
    const std::filesystem::path dir = Zathura::RuntimePaths::configFile();
    ImGui::LoadIniSettingsFromDisk(dir.string().c_str());
    LOG_DEBUG("Loaded config file from " << dir.string());
}

std::string getDataToCopy(const std::stringstream &selectedAsmText, const bool asArray) {
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

#ifdef __EMSCRIPTEN__
// First-run docking layout for the browser build, which starts with no saved
// imgui.ini. Splits the viewport so the editor, registers, memory, stack and
// console all fill the screen. The layout is responsive: it is sized to the
// current viewport and ImGui rescales it on resize.
static void buildDefaultDockLayout(ImGuiID rootId) {
    ImGui::DockBuilderRemoveNode(rootId);
    ImGui::DockBuilderAddNode(rootId, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(rootId, ImGui::GetMainViewport()->Size);

    ImGuiID right;
    const ImGuiID left = ImGui::DockBuilderSplitNode(rootId, ImGuiDir_Left, 0.58f, nullptr, &right);

    ImGuiID leftBottom;
    const ImGuiID leftTop = ImGui::DockBuilderSplitNode(left, ImGuiDir_Up, 0.72f, nullptr, &leftBottom);

    ImGuiID rightBottom;
    const ImGuiID rightTop = ImGui::DockBuilderSplitNode(right, ImGuiDir_Up, 0.45f, nullptr, &rightBottom);

    ImGuiID rightBottomRight;
    const ImGuiID rightBottomLeft = ImGui::DockBuilderSplitNode(rightBottom, ImGuiDir_Left, 0.5f, nullptr, &rightBottomRight);

    ImGui::DockBuilderDockWindow("Code", leftTop);
    ImGui::DockBuilderDockWindow("Console", leftBottom);
    ImGui::DockBuilderDockWindow("Remote Source", leftBottom);
    ImGui::DockBuilderDockWindow("Breakpoints", leftBottom);
    ImGui::DockBuilderDockWindow("Watchpoints", leftBottom);
    ImGui::DockBuilderDockWindow("State Changes", leftBottom);
    ImGui::DockBuilderDockWindow("Register Values", rightTop);
    ImGui::DockBuilderDockWindow("Memory Editor", rightBottomLeft);
    ImGui::DockBuilderDockWindow("Memory Mappings", rightBottomLeft);
    ImGui::DockBuilderDockWindow("Stack", rightBottomRight);

    ImGui::DockBuilderFinish(rootId);
}
#endif

std::mutex updateMutex{};
void mainWindow() {
    const ImGuiIO &io = ImGui::GetIO();
    bool keepWindow = true;

    if (currentVersion.empty())
    {
        executeInBackground([]
        {
            updateMutex.lock();
            currentVersion = getLatestVersion();
            updateMutex.unlock();
        });
    }
    setupAppStyle();
    const ImGuiID dockId = ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport());
#ifdef __EMSCRIPTEN__
    // On the first frame, if no docking layout was loaded from a saved ini,
    // build a sensible full-viewport default so the UI isn't a pile of
    // overlapping windows in the top-left corner.
    static bool dockLayoutInit = false;
    if (!dockLayoutInit) {
        dockLayoutInit = true;
        const ImGuiDockNode* node = ImGui::DockBuilderGetNode(dockId);
        if (node == nullptr || node->IsLeafNode()) {
            buildDefaultDockLayout(dockId);
        }
    }
#endif

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
    editor->SetLanguageDefinition(currentDefinitionId);
    editor->Render("Editor");
    ImGui::PopFont();
    contextMenu();

    ImGui::Begin("Register Values", &keepWindow, ImGuiWindowFlags_NoCollapse);
    registerWindow();

    ImGui::Begin("Console", &keepWindow,
                 ImGuiWindowFlags_NoCollapse |
                     ImGuiWindowFlags_NoScrollbar |
                     ImGuiWindowFlags_NoScrollWithMouse);
    consoleWindow();

    ImGui::End();
    hexEditorWindow();

    ImGui::Begin("Remote Source", &keepWindow, ImGuiWindowFlags_NoCollapse);
    remoteSourceWindow();
    ImGui::End();

    if (breakpointsUI) {
        ImGui::Begin("Breakpoints", &breakpointsUI, ImGuiWindowFlags_NoCollapse);
        breakpointManagerWindow();
        ImGui::End();
    }

    if (watchpointsUI) {
        ImGui::Begin("Watchpoints", &watchpointsUI, ImGuiWindowFlags_NoCollapse);
        watchpointWindow();
        ImGui::End();
    }

    if (stateChangesUI) {
        ImGui::Begin("State Changes", &stateChangesUI, ImGuiWindowFlags_NoCollapse);
        stateChangesWindow();
        ImGui::End();
    }

    ImGui::Begin("Stack", &keepWindow, ImGuiWindowFlags_NoCollapse);
    stackEditorWindow();
    ImGui::End();

    manageShortcuts();
    runActions();
    //    Utils::LayoutManager::save(CONFIG_NAME);
    ImGui::Render();
}
