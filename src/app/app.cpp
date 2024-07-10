#include "app.hpp"
#include "tasks/editorTasks.hpp"

bool isRunning = true;
bool lineNumbersShown = true;

void setupEditor() {
    editor = new TextEditor();
    editor->SetLanguageDefinition(TextEditor::LanguageDefinitionId::Asmx86_64);
    editor->SetPalette(TextEditor::PaletteId::Catppuccin);
    editor->SetShowWhitespacesEnabled(false);
    editor->SetReadOnlyEnabled(false);
    editor->SetTabSize(4);

    {
        std::ifstream t("test.asm");
        if (t.good()) {
            std::string str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
            editor->SetText(str);
        }
    }
}

void setupViewPort() {
//    set the position of the window just next to the menu bar (top left) using docking
    ImGuiViewport *viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(viewport->Pos.x, viewport->Pos.y + ImGui::GetFrameHeight()));
    ImGui::SetNextWindowSize(ImVec2(500, 600));
    ImGui::SetNextWindowViewport(viewport->ID);
}


void LoadIniFile() {
    std::string filename = "/home/rc/Zathura-UI/src/config.zlyt";
    std::filesystem::path dir(filename);
    ImGui::LoadIniSettingsFromDisk(dir.string().c_str());
    LOG_DEBUG("Loaded config file from " << dir.string());
}

std::string getDataToCopy(std::stringstream &selectedAsmText, bool asArray) {
    std::string bytes = getBytes(selectedAsmText);
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

    return dataToCopy;
}

void pushFont(){
    ImGuiIO &io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[RubikRegular16]);
}

void mainWindow() {
    ImGuiIO &io = ImGui::GetIO();

    bool k = true;
    SetupImGuiStyle();
    ImGui::DockSpaceOverViewport(ImGui::GetMainViewport());

    appMenuBar();
    setupViewPort();

    ImGui::Begin("Code", &k, ImGuiWindowFlags_NoCollapse);
    setupButtons();

    if (!editor->FontInit){
        editor->FontInit = pushFont;
        editor->CreateLabelLineMap = createLabelLineMapCallback;
        editor->ParseStrIntoCoordinates = parseStrIntoCoordinates;
        editor->CompletionCallback = reinterpret_cast<ImGuiInputTextCallback (*)(
                ImGuiInputTextCallbackData *)>(labelCompletionCallback);
    }

    ImGui::PushFont(io.Fonts->Fonts[JetBrainsMono24]);
    editor->Render("Editor");
    ImGui::PopFont();
    ImGui::GetStyle().Colors[ImGuiCol_PopupBg] = ImColor(0x1e, 0x20, 0x30);

    ImGui::GetStyle().Colors[ImGuiCol_HeaderHovered] = ImColor(0x18, 0x19, 0x26);
    ImGui::PushFont(io.Fonts->Fonts[RubikRegular16]);
    if (ImGui::BeginPopupContextItem("TextEditorContextMenu")) {
        if (ImGui::MenuItem("Copy", "Ctrl + C", false)) // Enable only if there is a selection
        {
            editor->Copy();
            LOG_DEBUG("Copied text to clipboard");
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Cut", "Ctrl + X", false)) // Enable only if there is a selection
        {
            editor->Cut();
            LOG_DEBUG("Cut text to clipboard");
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Paste", "Ctrl + V", false)) // Enable only if not read-only and clipboard has text
        {
            editor->Paste();
            LOG_DEBUG("Pasted text from clipboard");
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Undo", "Ctrl + Z", false)) // Enable only if not read-only and clipboard has text
        {
            if (editor->CanUndo()) {
                editor->Undo();
                LOG_DEBUG("Performed undo!");
            }
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Redo", "Ctrl + Y", false)) // Enable only if not read-only and clipboard has text
        {
            if (editor->CanRedo()) {
                editor->Redo();
                LOG_DEBUG("Performed redo!");
            }
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Toggle breakpoint", "F9", false)) {
            int line, _;
            editor->GetCursorPosition(line, _);
            auto idx = (std::find(breakpointLines.begin(), breakpointLines.end(), line + 1));
            if (idx != breakpointLines.end()){
                breakpointLines.erase(idx);
                editor->RemoveHighlight(line);
            }
            else{
                breakpointLines.push_back(line + 1);
                editor->HighlightBreakpoints(line);
            }
        }


        ImGui::Separator();

        if (!lineNumbersShown) {
            if (ImGui::MenuItem("Show line numbers", nullptr, false)) {
                editor->SetShowLineNumbersEnabled(true);
                lineNumbersShown = true;
            }
        } else {
            if (ImGui::MenuItem("Hide line numbers", nullptr,
                                false))
            {
                editor->SetShowLineNumbersEnabled(false);
                lineNumbersShown = false;
            }
        }

        ImGui::Separator();

        if (ImGui::BeginMenu("Copy as")) {
            std::stringstream selectedAsmText(editor->GetSelectedText());
            if (ImGui::MenuItem("C array")){
                if (!selectedAsmText.str().empty()) {
                    ImGui::SetClipboardText(getDataToCopy(selectedAsmText, true).c_str());
                }
            }

            if (ImGui::MenuItem("Hex")){
                std::stringstream selectedAsmText(editor->GetSelectedText());
                if (!selectedAsmText.str().empty()) {
                    ImGui::SetClipboardText(getDataToCopy(selectedAsmText, false).c_str());
                }
            }
            ImGui::EndMenu();
        }

        ImGui::Separator();
        if (!debugModeEnabled){
            if (ImGui::MenuItem("Run selected code", nullptr, false)){
                std::stringstream selectedAsmText(editor->GetSelectedText());
                if (!selectedAsmText.str().empty()) {
                    std::string bytes = getBytes(selectedAsmText);
                    if (!bytes.empty()) {
                        runTempCode(bytes);
                    }
                }
            }
        }

        if (ImGui::MenuItem("Go to definition")){
            editor->SelectLabelDefinition(false);
        }

        ImGui::EndPopup();
    }
    ImGui::PopFont();
    ImGui::End();

    ImGui::Begin("Register Values", &k, ImGuiWindowFlags_NoCollapse);
    registerWindow();

    ImGui::Begin("Console", &k, ImGuiWindowFlags_NoCollapse);
    consoleWindow();

    ImGui::End();
    hexEditorWindow();

    ImGui::Begin("Stack", &k, ImGuiWindowFlags_NoCollapse);
    stackEditorWindow();

    ImGui::End();
//    Utils::LayoutManager::save(CONFIG_NAME);
    ImGui::Render();
}
