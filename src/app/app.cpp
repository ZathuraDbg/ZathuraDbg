#include "app.hpp"
#include <string>
#include <filesystem>
#include <tsl/ordered_map.h>

TextEditor *editor = nullptr;

bool writeEditorToFile(const std::string& filePath) {
    std::ofstream out(filePath, std::ios::out | std::ios::trunc);

    if (out.good()){
        std::cout << editor->GetText() << std::endl;
        out << editor->GetText() << "\n";
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
    if (fileSaveAs) {
        auto fileName = saveAsFileDialog();
        if (!fileName.empty()) {
            if (!writeEditorToFile(fileName)) {
                pfd::message("File write error!",
                             "Sorry, the file you selected couldn't be opened or written to.\nPlease make sure "
                             "no other program is using this file and you have the correct permissions to access the file and try again!",
                             pfd::choice::ok,
                             pfd::icon::error);
            }
        }
    }
    if (fileSave){
        std::cout << "writing to " << selectedFile << std::endl;
        if (!writeEditorToFile(selectedFile)) {
            pfd::message("File write error!",
                         "Sorry, the file you selected couldn't be opened or written to.\nPlease make sure "
                         "no other program is using this file and you have the correct permissions to access the file and try again!",
                         pfd::choice::ok,
                         pfd::icon::error);
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

void testWindow(){
    using namespace ImGui;
    PushFont(GetIO().Fonts->Fonts[5]);
    ImGui::Begin("Window");

    float textHeight = ImGui::GetTextLineHeight();
    float inputHeight = ImGui::GetFrameHeight();
    float offset = (inputHeight - textHeight) / 2.0f;

    ImGui::Text("Label:");
    ImGui::SameLine();
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + offset); // Adjust vertical alignment
    static char inputText[128] = "";
    ImGui::InputText("##input", inputText, IM_ARRAYSIZE(inputText));

    ImGui::End();
    PopFont();
}
//void testWindow(){
//    using namespace ImGui;
//    PushFont(GetIO().Fonts->Fonts[5]);
//    PushStyleColor(ImGuiCol_ChildBg, (ImVec4)ImColor(40,44,52,255));
//    PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(15, 10));
//    PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(5, 5));
//    PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(10, 10));
//    ImGui::BeginChild("Register Value child", ImVec2(0, 600), true, ImGuiWindowFlags_HorizontalScrollbar);
//
//    PushStyleColor(ImGuiCol_FrameBg, (ImVec4)ImColor(24,25,38,255));
//    ImGuiStyle& style = ImGui::GetStyle();
//    ImGui::Columns(4);
////
////    ImGui::SetColumnWidth(0, 100); // Register Name
////    ImGui::SetColumnWidth(1, 200); // Value
////    ImGui::SetColumnWidth(2, 70); // Register Name 2
////    ImGui::SetColumnWidth(3, 150); // Value
//
//    int index = 0;
//    auto it = registerValueMap.begin();
//    while (it != registerValueMap.end()) {
//        const auto& [regName, regValue] = *it;
//
//        ImGui::PushID(regName.c_str());
//        ImGui::Text("%s", regName.c_str());
//        ImGui::PopID();
//        ImGui::NextColumn();
//
//        char buffer[64];
//        strncpy(buffer, regValue.c_str(), sizeof(buffer) - 1);
//        buffer[sizeof(buffer) - 1] = '\0';
//
//        ImGui::PushID(regName.c_str());
//
//        if (ImGui::InputText(("##value" + std::to_string(index)).c_str(), buffer, sizeof(buffer), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase)) {
//            registerValueMap[regName] = buffer;
//        }
//
//        ImGui::PopID();
//        ImGui::NextColumn();
//
//        ++it;
//        ++index;
//
//        if (it!=registerValueMap.end()){
//            auto [regName1, regValue1] = *it;
//
//            ImGui::PushID(std::to_string(index).c_str());
//            ImGui::Text("     %s", regName1.c_str());
//            ImGui::PopID();
//
//            ImGui::NextColumn();
//
//            ImGui::PushID(regName1.c_str());
//            if (ImGui::InputText(("##value1" + std::to_string(index)).c_str(), buffer, sizeof(buffer), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase)) {
//                registerValueMap[regName1] = buffer;
//            }
//            ImGui::PopID();
//            ImGui::NextColumn();
//            ++it;
//        }
//        ++index;
//        ImGui::SeparatorEx(ImGuiSeparatorFlags_Horizontal | ImGuiSeparatorFlags_SpanAllColumns, 4.0f);
//    }
//    PopStyleColor();
//    PopStyleColor();
//    PopStyleVar();
//    PopStyleVar();
//    PopStyleVar();
//    ImGui::PopFont();
//    ImGui::EndChild();
//}
//
//void registerWindow()
//{
//    auto io = ImGui::GetIO();
//    ImGui::PushFont(io.Fonts->Fonts[SatoshiSmall]);
//    if (ImGui::BeginTable("Table", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable, ImVec2(0, ImGui::GetTextLineHeightWithSpacing()), 500.0f)) {
//        ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_NoSort | ImGuiTableColumnFlags_WidthStretch, 8.0f);
//        ImGui::TableSetupColumn("Values", ImGuiTableColumnFlags_WidthStretch, ImGui::GetTextLineHeight());
//        ImGui::TableHeadersRow();
//        ImGui::PopFont();
//        ImGui::PushFont(io.Fonts->Fonts[5]);
//
//        int index = 0;
//        for (auto& reg : registerValueMap) {
//            ImGui::SetNextItemWidth(50);
//            ImGui::TableNextColumn();
//            ImGui::PushID(reg.first.c_str());
//            ImGui::Text("%s", reg.first.c_str());
//            ImGui::PopID();
//
//            ImGui::SetNextItemWidth(50);
//            ImGui::TableNextColumn();
//
//            ImGui::PushID(index);
//            char value[64] = {};
//            strncpy(value, reg.second.c_str(), sizeof(value) - 1);
//            value[sizeof(value) - 1] = '\0';
//            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
//            if (ImGui::InputText(("##value" + std::to_string(index)).c_str(), value, IM_ARRAYSIZE(value), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase | ImGuiInputTextFlags_CharsNoBlank)) {
//                if (strncmp(value, "0x", 2) != 0){
//                    registerValueMap[reg.first] = "0x";
//                    registerValueMap[reg.first].append(value);
//                }
//                else{
//                    registerValueMap[reg.first] = value;
//                }
//            }
////            ImGui::SameLine();
////            ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical | ImGuiSeparatorFlags_SpanAllColumns, 20.0f);
////            ImGui::SameLine();
////            ImGui::Text("abc");
////            ImGui::SameLine();
////            ImGui::Text(reg.second.c_str());
//            ImGui::PopStyleVar();
//            ImGui::PopID();
//            index++;
//        }
//        ImGui::EndTable();
//        ImGui::PopFont();
//    }
//    else{
//        ImGui::PopFont();
//    }
//}

void registerWindow() {
    auto io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[SatoshiSmall]);

    if (ImGui::BeginTable("RegistersTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
        // Setup columns headers
        ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        int index = 0;
        for (auto it = registerValueMap.begin(); it != registerValueMap.end(); ++index) {
            ImGui::TableNextRow();

            // First Register Name
            ImGui::TableSetColumnIndex(0);
            // Align text vertically centered with the input box
            float textHeight = ImGui::GetTextLineHeight();
            float frameHeight = ImGui::GetFrameHeight();
            float spacing = (frameHeight - textHeight) / 2.0f;
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + spacing);
            ImGui::Text("%s", it->first.c_str());

            // First Register Value
            ImGui::TableSetColumnIndex(1);
            static char value1[64] = {};
            strncpy(value1, it->second.c_str(), sizeof(value1) - 1);
            value1[sizeof(value1) - 1] = '\0';

            ImGui::PushID(index * 2);
            ImGui::SetNextItemWidth(-FLT_MIN); // Use the remaining space in the column
            if (ImGui::InputText(("##value1" + std::to_string(index)).c_str(), value1, IM_ARRAYSIZE(value1), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase | ImGuiInputTextFlags_CharsNoBlank)) {
                if (strncmp(value1, "0x", 2) != 0) {
                    registerValueMap[it->first] = "0x";
                    registerValueMap[it->first].append(value1);
                } else {
                    registerValueMap[it->first] = value1;
                }
            }
            ImGui::PopID();

            // Move to next element in map for the second register and its value
            ++it;
            if (it == registerValueMap.end()) break;

            // Second Register Name
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s", it->first.c_str());

            // Second Register Value
            ImGui::TableSetColumnIndex(3);
            static char value2[64] = {};
            strncpy(value2, it->second.c_str(), sizeof(value2) - 1);
            value2[sizeof(value2) - 1] = '\0';

            ImGui::PushID(index * 2 + 1);
            ImGui::SetNextItemWidth(-FLT_MIN); // Use the remaining space in the column
            if (ImGui::InputText(("##value2" + std::to_string(index)).c_str(), value2, IM_ARRAYSIZE(value2), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase | ImGuiInputTextFlags_CharsNoBlank)) {
                if (strncmp(value2, "0x", 2) != 0) {
                    registerValueMap[it->first] = "0x";
                    registerValueMap[it->first].append(value2);
                } else {
                    registerValueMap[it->first] = value2;
                }
            }
            ImGui::PopID();
            ++it;
            if (it == registerValueMap.end()) break;
        }

        ImGui::EndTable();
    }

    ImGui::PopFont();
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

void setupButtons() {
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[6]);
    ImGui::Separator();

    if (ImGui::Button(ICON_CI_FOLDER_OPENED, ImVec2(20, 20))) {
        auto f = openFileDialog();
        std::cout << "Selected files:";
        if (!f.empty()) {
            std::cout << " " + f << "\n";
            if (!readFileIntoEditor(f)) {
                pfd::message("File read error!",
                             "Sorry, the file you selected couldn't be opened or read.\nPlease make sure "
                             "no other program is using this file and you have the correct permissions to access the file and try again!",
                             pfd::choice::ok,
                             pfd::icon::error);
            }
        }
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();

    if (ImGui::Button(ICON_CI_SAVE, ImVec2(20, 20))) {
        if (!selectedFile.empty()) {
            std::cout << "writing to " << selectedFile << std::endl;
            if (!writeEditorToFile(selectedFile)) {
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

void mainWindow() {
    static ImGuiDockNodeFlags dockspace_flags = ImGuiDockNodeFlags_PassthruCentralNode;
    ImGuiIO &io = ImGui::GetIO();

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