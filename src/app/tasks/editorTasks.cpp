#include "editorTasks.hpp"
#include "../integration/keystone/assembler.hpp"
#include "../app.hpp"

TextEditor *editor = nullptr;

bool writeEditorToFile(const std::string &filePath) {
    LOG_DEBUG("Writing to file " << filePath);
    std::ofstream fileToWrite(filePath, std::ios::out | std::ios::trunc);

    if (fileToWrite.good()) {
        fileToWrite << editor->GetText();
        fileToWrite.close();
        LOG_DEBUG("Write to file completed successfully!");
        return true;
    }

    tinyfd_messageBox("File write error!", ("Unable to write to the file " + filePath + "!\nPlease check if the "
                      "file is not open in another program and/or you have the permissions to read it.").c_str(),
                      "ok", "error", 0);
    return false;
}

bool readFileIntoEditor(const std::string &filePath) {
    LOG_DEBUG("Reading the file " << filePath);
    std::ifstream fileToRead(filePath);

    if (fileToRead.good()) {
        std::string fileContent((std::istreambuf_iterator<char>(fileToRead)), std::istreambuf_iterator<char>());
        editor->SetText(fileContent);
        fileToRead.close();
        LOG_DEBUG("Read from the file successfully!");
        return true;
    }

    tinyfd_messageBox("File read error!", "Unable to read the file you're trying to open. Please check if the "
                       "file is not open in another program and/or you have the permissions to read it.",
                      "ok", "error", 0);

    return false;
}

int labelCompletionCallback(ImGuiInputTextCallbackData *data) {
    if (labels.empty()) {
        getBytes(selectedFile);
        initInsSizeInfoMap();
    }

    if (data->EventFlag == ImGuiInputTextFlags_CallbackCompletion) {
        if (data->EventKey == ImGuiKey_Tab) {
            std::vector<std::string> matches;
            const std::string input(data->Buf, data->BufTextLen);

            auto it = labels.end();
            for (auto &i: labels) {
                if (i.contains(input) && (input != i)) {
                    it = std::ranges::find(labels, i);
                    matches.push_back(*it);
                }
            }

            std::string out = input;
            if (!matches.empty()) {
                out = *std::ranges::min_element(matches, [](const std::string &a, const std::string &b) {
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

void createLabelLineMapCallback(std::map<std::string, int> &labelVector) {
    if (labelLineNoMapInternal.empty()) {
        getBytes(selectedFile);
    }

    labelVector = labelLineNoMapInternal;
}

std::pair<int, int> parseStrIntoCoordinates(std::string &popupInput) {
    LOG_DEBUG("Parsing " << popupInput << "as coordinates...");
    if (labelLineNoMapInternal.empty()) {
        getBytes(selectedFile);
        initInsSizeInfoMap();
    }

    if (popupInput.contains('$')) {
        auto s = parseVals(popupInput);
        if (addressLineNoMap.contains((s))){
            popupInput = addressLineNoMap[(parseVals(popupInput))];
        }
        else{
            popupInput = '0';
        }
    }

    int lineNo = -1;
    int colNo = 0;

    std::string convStr;
    std::string labelStr;

    if (popupInput.contains("0x")){
        popupInput = std::to_string(hexStrToInt(popupInput));
    }

    for (const auto &c: popupInput) {
        if (c == ':' && lineNo == -1) {
            if (!convStr.empty()) {
                try {
                    lineNo = stoi(convStr);
                }
                catch (std::invalid_argument &e) {
                    labelStr = convStr;
                }
                catch (std::exception &e) {
                    lineNo = 1;
                }
                convStr = "";
                convStr.clear();
            }
        }
        if (c != ' ' && c != ':') {
            convStr += c;
        }
    }

    if (!labelStr.empty()) {
        if (labelLineNoMapInternal.contains(labelStr)) {
            lineNo = labelLineNoMapInternal[labelStr];
        }
    }

    if (lineNo == -1 && !convStr.empty()) {
        if (labelLineNoMapInternal.contains(convStr)) {
            lineNo = labelLineNoMapInternal[convStr];
        } else {
            try {
                lineNo = stoi(convStr);
            }
            catch (std::exception &e) {
                lineNo = 1;
            }
        }

        convStr = "";
        convStr.clear();
    }

    if (lineNo != -1) {
        if (!convStr.empty()) {
            try {
                colNo = stoi(convStr);
            }
            catch (std::exception &e) {
                colNo = 1;
            }
        }
    }

    if (lineNo <= 0) {
        lineNo = 1;
    } else if (colNo < 0) {
        colNo = 0;
    }

    LOG_DEBUG("Parsed into x = " << lineNo - 1 << ", y = " << colNo);
    return {lineNo - 1, colNo};
}

std::vector<uint8_t> hexToBytes(const std::string &hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 4) {
        if (hex[i] == '\\' && hex[i + 1] == 'x') {
            std::string byteString = hex.substr(i + 2, 2);
            auto byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }
    }
    return bytes;
}

void pasteCallback(const std::string clipboardText) {
    if (clipboardText.starts_with("\\x")) {
        csh handle{};
        cs_insn *instruction{};

        if (cs_open(codeInformation.archCS, codeInformation.modeCS, &handle) != CS_ERR_OK) {
            std::cerr << "Capstone failed to initialize!" << std::endl;
            return;
        }

        const std::vector<uint8_t> bytes = hexToBytes(clipboardText);
        const size_t count = cs_disasm(handle, bytes.data(), bytes.size(), ENTRY_POINT_ADDRESS, 0, &instruction);

        if (count == 0) {
            std::cerr << "Disassembly failed!" << std::endl;
            cs_close(&handle);
            return;
        }

        const int res = tinyfd_messageBox("Valid shellcode found!",
            "It looks like you are trying to paste shellcode.\n"
            "Do you want ZathuraDbg to automatically disassemble this shellcode?",
            "yesno", "question", 0);

        if (res) {
            std::vector<std::string> instructions{};
            for (size_t i = 0; i < count; i++) {
                std::string instrStr = instruction[i].mnemonic;
                instrStr += " ";
                instrStr += instruction[i].op_str;
                instructions.emplace_back(instrStr);
            }

            std::stringstream ss{};
            for (const auto &instr : instructions) {
                ss << "\t" << instr + "\n";
            }

            ImGui::SetClipboardText(ss.str().c_str());
        }

        // Always free resources
        cs_free(instruction, count);
        cs_close(&handle);
    }
}
