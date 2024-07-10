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
    std::vector<std::string> matches;

    if (labels.empty()){
        getBytes(selectedFile);
        initInsSizeInfoMap();
    }

    if (data->EventFlag == ImGuiInputTextFlags_CallbackCompletion) {
        if (data->EventKey == ImGuiKey_Tab) {
            std::string input(data->Buf, data->BufTextLen);

            auto it = labels.end();
            for (auto& i: labels) {
                if (i.contains(input) && (input != i)){
                    it = std::find(labels.begin(), labels.end(), i);
                    matches.push_back(*it);
                }
            }

            std::string out = input;
            if (!matches.empty()){
                out = *std::min_element(matches.begin(), matches.end(), [](const std::string &a, const std::string &b){
                    return (a.size() < b.size());
                });
            }

            data->DeleteChars(0, data->BufTextLen);
            data->InsertChars(0, out.c_str());
            data->CursorPos = data->SelectionStart = data->SelectionEnd = out.length();
        }
    }

    return 0;
}

void createLabelLineMapCallback(std::map<std::string, int>& labelVector){
    if (labelLineNoMapInternal.empty()){
        getBytes(selectedFile);
        initInsSizeInfoMap();
    }

    labelVector = labelLineNoMapInternal;
}

std::pair<int, int> parseStrIntoCoordinates(const std::string& popupInput){
    if (labelLineNoMapInternal.empty()){
        getBytes(selectedFile);
        initInsSizeInfoMap();
    }

    int lineNo = -1;
    int colNo = 0;

    std::string convStr;
    std::string labelStr;

    for (auto&c: popupInput){
        if (c == ':' && lineNo == -1){
            if (!convStr.empty()){
                try{
                    lineNo = stoi(convStr);
                }
                catch (std::invalid_argument& e){
                    labelStr = convStr;
                }
                catch (std::exception& e){
                    lineNo = 1;
                }
                convStr = "";
                convStr.clear();
            }
        }
        if (c!=' ' && c!=':'){
            convStr += c;
        }
    }

    if (!labelStr.empty()){
        if (labelLineNoMapInternal.contains(labelStr)){
            lineNo = labelLineNoMapInternal[labelStr];
        }
    }

    if (lineNo == -1 && !convStr.empty()){
        if (labelLineNoMapInternal.contains(convStr)){
            lineNo = labelLineNoMapInternal[convStr];
        }
        else{
            try{
                lineNo = stoi(convStr);
            }
            catch (std::exception& e){
                lineNo = 1;
            }
        }

        convStr = "";
        convStr.clear();
    }

    if (lineNo != -1){
        if (!convStr.empty()){
            try{
                colNo = stoi(convStr);
            }
            catch (std::exception& e){
                colNo = 1;
            }
        }
    }

    if (lineNo < 0){
        lineNo = 1;
    }
    else if (colNo < 0){
        colNo = 0;
    }

    return {lineNo - 1, colNo};
}