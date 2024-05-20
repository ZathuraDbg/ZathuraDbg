#include "app.hpp"

void setupEditor(){
    editor = new TextEditor();
    editor->SetLanguageDefinition(TextEditor::LanguageDefinitionId::Asmx86_64);
    editor->SetPalette(TextEditor::PaletteId::Dark);
    editor->SetShowWhitespacesEnabled(false);
    editor->SetReadOnlyEnabled(false);
    editor->SetTabSize(4);

    {
        std::ifstream t("test.asm");
        if (t.good())
        {
            std::string str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
            editor->SetText(str);
        }
    }
}

void setupViewPort() {
//    set the poisition of the window just next to the menu bar (top left) using docking
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(viewport->Pos.x, viewport->Pos.y + ImGui::GetFrameHeight()));
    ImGui::SetNextWindowSize(ImVec2(500, 600));
    ImGui::SetNextWindowViewport(viewport->ID);
}


void LoadIniFile()
{
    std::string filename = "/home/rc/Zathura-UI/src/config.zlyt";
	std::filesystem::path dir(filename);
	ImGui::LoadIniSettingsFromDisk(dir.string().c_str());
    LOG_DEBUG("Loaded config file from " << dir.string());
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

    ImGui::PushFont(io.Fonts->Fonts[JetBrainsMono20]);
    editor->Render("Editor");
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