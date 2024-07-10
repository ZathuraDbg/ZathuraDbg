#include "editorTasks.hpp"
#include "../integration/keystone/assembler.hpp"

TextEditor *editor = nullptr;

bool writeEditorToFile(const std::string& filePath) {
    LOG_DEBUG("Writing to file " << filePath);
    std::ofstream out(filePath, std::ios::out | std::ios::trunc);

    if (out.good()){
        out << editor->GetText();
        out.close();
        LOG_DEBUG("Done!");
        return true;
    }

    tinyfd_messageBox("File write error!", ("Unable to write to the file " + filePath + "!\nPlease check if the "
                                                                                        "file is not open in another program and/or you have the permissions to read it.").c_str(), "ok", "error", 0);
    return false;
}

bool readFileIntoEditor(const std::string& filePath){
    LOG_DEBUG("Read into editor");
    std::ifstream t(filePath);

    if (t.good())
    {
        std::string str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
        editor->SetText(str);
        t.close();
        return true;
    }
    tinyfd_messageBox("File read error!", ("Unable to read from the file " + filePath + "!\nPlease check if the "
                            "file is not open in another program and/or you have the permissions to read it.").c_str(), "ok", "error", 0);

    return false;
}

int labelCompletionCallback(ImGuiInputTextCallbackData* data){
    static std::string current_input;
    static int match_index = -1;
    if (labels.empty()){
        getBytes(selectedFile);
        initInsSizeInfoMap();
    }
    if (data->EventFlag == ImGuiInputTextFlags_CallbackCompletion) {
        if (data->EventKey == ImGuiKey_Tab) {
            std::string input(data->Buf, data->BufTextLen);

            if (input != current_input) {
                // Reset match index if input changes
                current_input = input;
                match_index = -1;
            }

            auto it = labels.end();
            for (auto& i: labels) {
                if (i.contains(current_input)){
                    it = std::find(labels.begin(), labels.end(), i);
                }
            }

            if (it != labels.end()) {
                if (match_index == -1 || std::distance(labels.begin(), it) != match_index) {
                    match_index = std::distance(labels.begin(), it);
                } else {
                    ++match_index;
                    if (match_index >= labels.size()) {
                        match_index = 0;
                    }
                }

                const std::string& match = labels[match_index];

                data->DeleteChars(0, data->BufTextLen);
                data->InsertChars(0, match.c_str());
                data->CursorPos = data->SelectionStart = data->SelectionEnd = match.length();
            }
        }
    }
    return 0;
}
