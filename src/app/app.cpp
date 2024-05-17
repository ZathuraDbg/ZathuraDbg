#include "app.hpp"
#include <string>
#include <filesystem>
#include <tsl/ordered_map.h>

TextEditor *editor = nullptr;

bool writeEditorToFile(const std::string& filePath) {
    std::ofstream out(filePath, std::ios::out | std::ios::trunc);

    if (out.good()){
        out << editor->GetText();
        out.close();
        return true;
    }
    return false;
}

bool readFileIntoEditor(const std::string& filePath){
    std::ifstream t(filePath);

    if (t.good())
    {
        std::string str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
        editor->SetText(str);
        t.close();
        return true;
    }

    return false;
}

void appMenuBar()
{
    bool fileOpen = false;
    bool fileSave = false;
    bool fileSaveAs = false;
    bool quit = false;  // not using exit because it's a function from std to avoid confusion

    bool debugRestart = false;
    bool debugStep = false;
    bool debugRun = false;
    bool debugPause = false;

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[4]);
    if (ImGui::BeginMainMenuBar())
    {
        if (ImGui::BeginMenu("File"))
        {
            ImGui::Separator();
            ImGui::MenuItem("Open", "Ctrl+O", &fileOpen);
            ImGui::MenuItem("Save", "Ctrl+S", &fileSave);
            ImGui::MenuItem("Save As", "Ctrl+Shift+S", &fileSaveAs);
            ImGui::Separator();
            ImGui::MenuItem("Exit", "Alt+F4", &quit);
            ImGui::Separator();
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Edit"))
        {
            if (ImGui::MenuItem("Undo", "CTRL+Z")) {
                if (editor->CanUndo())
                    editor->Undo();
            }
            if (ImGui::MenuItem("Redo", "CTRL+Y", false)) {
                if (editor->CanRedo())
                    editor->Redo();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Cut", "CTRL+X")) {
                editor->Cut();
            }
            if (ImGui::MenuItem("Copy", "CTRL+C")) {
                editor->Copy();
            }
            if (ImGui::MenuItem("Paste", "CTRL+V")) {
                editor->Paste();
            }
            ImGui::Separator();
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Debug")){
            ImGui::Separator();
            ImGui::MenuItem("Restart", "CTRL+R", &debugRestart);
            ImGui::MenuItem("Step", "CTRL+J", &debugStep);
            ImGui::MenuItem("Pause", "CTRL+P", &debugPause);
            ImGui::Separator();
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
    }

    if (fileOpen)
    {
        auto f = openFileDialog();
        std::cout << "Selected files:";
        if (!f.empty()){
            std::cout << " " + f << "\n";
            if (!readFileIntoEditor(f)){
                pfd::message("File read error!",
                             "Sorry, the file you selected couldn't be opened or read.\nPlease make sure "
                             "no other program is using this file and you have the correct permissions to access the file and try again!",
                             pfd::choice::ok,
                             pfd::icon::error);
            }
        }
    }
    if (fileSaveAs){
        auto fileName = saveAsFileDialog();
        if (!fileName.empty()){
            if (!writeEditorToFile(fileName)){
                pfd::message("File write error!",
                             "Sorry, the file you selected couldn't be opened or written to.\nPlease make sure "
                             "no other program is using this file and you have the correct permissions to access the file and try again!",
                             pfd::choice::ok,
                             pfd::icon::error);
            }
        }
    }

    ImGui::PopFont();
}

void setupEditor(){
    editor = new TextEditor();
    editor->SetLanguageDefinition(TextEditor::LanguageDefinitionId::Asmx86_64);
    editor->SetPalette(TextEditor::PaletteId::Dark);
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

tsl::ordered_map<std::string, std::string> registerValueMap = {{"RIP", "0x00"}, {"RSP", "0x00"}, {"RBP", "0x00"},{"RAX", "0x00"}, {"RBX", "0x00"}, {"RCX", "0x00"}, {"RDX", "0x00"},
                                                        {"RSI", "0x00"}, {"RDI", "0x00"}, {"R8", "0x00"}, {"R9", "0x00"}, {"R10", "0x00"}, {"R11", "0x00"}, {"R12", "0x00"},
                                                        {"R13", "0x00"}, {"R14", "0x00"}, {"R15", "0x00"}, {"CS", "0x00"}, {"DS", "0x00"}, {"ES", "0x00"}, {"FS", "0x00"}, {"GS", "0x00"}, {"SS", "0x00"}};

void EditableTable()
{
    auto io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[SatoshiSmall]);
    if (ImGui::BeginTable("Table", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable, ImVec2(0, ImGui::GetTextLineHeightWithSpacing()), 500.0f)) {
        ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_NoSort | ImGuiTableColumnFlags_WidthStretch, 8.0f);
        ImGui::TableSetupColumn("Values", ImGuiTableColumnFlags_WidthStretch, ImGui::GetTextLineHeight());
        ImGui::TableHeadersRow();
        ImGui::PopFont();
        ImGui::PushFont(io.Fonts->Fonts[5]);

        int index = 0;
        for (auto& reg : registerValueMap) {
            ImGui::SetNextItemWidth(-1);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(reg.first.c_str());
            ImGui::Text("%s", reg.first.c_str());
            ImGui::PopID();

            ImGui::SetNextItemWidth(-1);
            ImGui::TableNextColumn();

            ImGui::PushID(index);
            char value[64] = {};
            strncpy(value, reg.second.c_str(), sizeof(value) - 1);
            value[sizeof(value) - 1] = '\0';
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
            if (ImGui::InputText(("##value" + std::to_string(index)).c_str(), value, IM_ARRAYSIZE(value), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase | ImGuiInputTextFlags_CharsNoBlank)) {
                if (strncmp(value, "0x", 2) != 0){
                    registerValueMap[reg.first] = "0x";
                    registerValueMap[reg.first].append(value);
                }
                else{
                    registerValueMap[reg.first] = value;
                }
            }
            ImGui::PopStyleVar();
            ImGui::PopID();
            index++;
        }
        ImGui::EndTable();
        ImGui::PopFont();
    }
    else{
        ImGui::PopFont();
    }

}

void consoleWindow()
{
    std::vector<std::string> test = {};
    const float footer_height_to_reserve = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();
    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footer_height_to_reserve), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);

    for (auto &t: test){
        ImGui::Text("%s", t.c_str());
    }

    ImGui::EndChild();
    char input[500]{};
    ImGui::PushID(&input);
    if (ImGui::InputText("Command", input, ImGuiInputTextFlags_AllowTabInput)){
        test.emplace_back(input);
    }
    ImGui::PopID();
    ImGui::End();
}

void hexEditorWindow(){
    auto io = ImGui::GetIO();
    static MemoryEditor mem_edit_2;
    ImGui::PushFont(io.Fonts->Fonts[3]);
    static char data[0x10000];
    size_t data_size = 0x10000;
    char *test = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce tortor urna, eleifend vel arcu vel, semper ultrices nisl. Aenean enim augue, dignissim at tempus vulputate, laoreet eget urna. Etiam aliquam, nibh non volutpat ultricies, massa tellus rutrum lectus, ut pellentesque purus enim vitae lorem. Vivamus cursus consequat turpis, sed convallis urna pretium at. Mauris fringilla lacus mi, ut gravida justo auctor vel. Nulla consectetur laoreet pharetra. Vivamus dui lectus, lobortis id ultricies vitae, viverra ut lacus. Fusce rutrum, erat consequat fringilla porttitor, mi elit sodales erat, a tempus turpis erat vel leo. Aenean ullamcorper blandit felis in sodales. Nunc sed massa sed erat luctus viverra. Suspendisse sem massa, pharetra pulvinar massa eu, rutrum vestibulum dui. Mauris sed posuere tellus. Curabitur ac placerat nunc, at pellentesque erat. Nam quis ligula pellentesque, rhoncus velit sed, pharetra leo. Ut tempor tincidunt orci, in scelerisque arcu tincidunt a. Sed eget sem et ligula finibus facilisis. Nunc vulputate mollis nulla, non ultrices libero faucibus non. Duis erat leo, pretium in tincidunt vel, placerat at nisl. Etiam elit velit, rutrum et sapien eget, efficitur egestas odio. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Sed viverra blandit ex at ultrices. Suspendisse potenti. Donec luctus metus sit amet augue elementum pellentesque. Sed rhoncus tincidunt arcu, nec congue mauris porta eget. Praesent id tellus neque. Mauris ultricies augue quis ante dapibus, eget lacinia nisi elementum. Fusce ornare condimentum mattis. Pellentesque ut congue mauris. Nullam et orci iaculis, malesuada lacus in, placerat nunc.";
    memcpy(data, test, data_size);
    mem_edit_2.DrawWindow("Memory Editor", data, data_size);
    ImGui::PopFont();
}


void stackEditorWindow(){
    auto io = ImGui::GetIO();
    static MemoryEditor mem_edit_2;
    mem_edit_2.OptShowAscii = false;
    mem_edit_2.Cols = 8;

    ImGui::PushFont(io.Fonts->Fonts[3]);
//  replace with stack stuff
    static char data[0x10000];
    size_t data_size = 0x10000;
    char *test = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce tortor urna, eleifend vel arcu vel, semper ultrices nisl. Aenean enim augue, dignissim at tempus vulputate, laoreet eget urna. Etiam aliquam, nibh non volutpat ultricies, massa tellus rutrum lectus, ut pellentesque purus enim vitae lorem. Vivamus cursus consequat turpis, sed convallis urna pretium at. Mauris fringilla lacus mi, ut gravida justo auctor vel. Nulla consectetur laoreet pharetra. Vivamus dui lectus, lobortis id ultricies vitae, viverra ut lacus. Fusce rutrum, erat consequat fringilla porttitor, mi elit sodales erat, a tempus turpis erat vel leo. Aenean ullamcorper blandit felis in sodales. Nunc sed massa sed erat luctus viverra. Suspendisse sem massa, pharetra pulvinar massa eu, rutrum vestibulum dui. Mauris sed posuere tellus. Curabitur ac placerat nunc, at pellentesque erat. Nam quis ligula pellentesque, rhoncus velit sed, pharetra leo. Ut tempor tincidunt orci, in scelerisque arcu tincidunt a. Sed eget sem et ligula finibus facilisis. Nunc vulputate mollis nulla, non ultrices libero faucibus non. Duis erat leo, pretium in tincidunt vel, placerat at nisl. Etiam elit velit, rutrum et sapien eget, efficitur egestas odio. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Sed viverra blandit ex at ultrices. Suspendisse potenti. Donec luctus metus sit amet augue elementum pellentesque. Sed rhoncus tincidunt arcu, nec congue mauris porta eget. Praesent id tellus neque. Mauris ultricies augue quis ante dapibus, eget lacinia nisi elementum. Fusce ornare condimentum mattis. Pellentesque ut congue mauris. Nullam et orci iaculis, malesuada lacus in, placerat nunc.";
    memcpy(data, test, data_size);
    mem_edit_2.DrawWindow("Stack", data, data_size);
    ImGui::PopFont();
}

void LoadIniFile()
{
    std::string filename = "/home/rc/Zathura-UI/src/config.zlyt";
	std::filesystem::path dir(filename);
	std::cout << "Ini File Directory: " << dir.string() << "\n";
	ImGui::LoadIniSettingsFromDisk(dir.string().c_str());
}

void setupButtons(){
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[6]);
    ImGui::Separator();

    if (ImGui::Button(ICON_CI_FOLDER_OPENED, ImVec2(20, 20))){

    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();

    if (ImGui::Button(ICON_CI_SAVE, ImVec2(20, 20))){
        auto fileName = saveAsFileDialog();
        if (!fileName.empty()){
            if (!writeEditorToFile(fileName)){
                pfd::message("File write error!",
                             "Sorry, the file you selected couldn't be opened or written to.\nPlease make sure "
                             "no other program is using this file and you have the correct permissions to access the file and try again!",
                             pfd::choice::ok,
                             pfd::icon::error);
            }
        }
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();
    ImGui::Button(ICON_CI_DEBUG_RESTART, ImVec2(20, 20));
    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();
    ImGui::Button(ICON_CI_DEBUG_START, ImVec2(20, 20));
    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();
    ImGui::Button(ICON_CI_DEBUG_CONTINUE, ImVec2(20, 20));
    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();
    ImGui::Button(ICON_CI_DEBUG_PAUSE, ImVec2(20, 20));
    ImGui::PopFont();
}

void mainWindow(){
    static ImGuiDockNodeFlags dockspace_flags = ImGuiDockNodeFlags_PassthruCentralNode;
    ImGuiIO& io = ImGui::GetIO();

    bool k = true;
    SetupImGuiStyle();
    ImGui::DockSpaceOverViewport(ImGui::GetMainViewport());

    appMenuBar();
    setupViewPort();

    ImGui::Begin("Code", &k, ImGuiWindowFlags_NoCollapse);
    setupButtons();

//    ImGui::Text("Application average %.3f ms/frame (%.1f FPS)", 1000.0f / io.Framerate, io.Framerate);
    ImGui::PushFont(io.Fonts->Fonts[3]);
    editor->Render("Editor");
    ImGui::PopFont();
    ImGui::End();

    ImGui::Begin("Register Values", &k, ImGuiWindowFlags_NoCollapse);
    EditableTable();

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
