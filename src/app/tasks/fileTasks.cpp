#include "fileTasks.hpp"
#include "../app.hpp"

void fileOpenTask(const std::string& fileName){
    if (!fileName.empty()){
        LOG_DEBUG("Opening the file " << fileName);
        if (!readFileIntoEditor(fileName)){
            LOG_ERROR("Read operation failed on the file: " << fileName);
        }
        selectedFile = fileName;
        editor->HighlightBreakpoints(-1);
    }
}

void fileSaveAsTask(const std::string &fileName){
    if (!fileName.empty()) {
        LOG_DEBUG("Saving the file " << fileName);
        if (!writeEditorToFile(fileName)) {
            LOG_ERROR("Save as operation failed on the file: " << fileName << " !");
        }
        selectedFile = fileName;
    }
}

void fileSaveTask(const std::string &fileName){
    if (!fileName.empty()){
        LOG_DEBUG("Saving the file " << fileName);
        if (!writeEditorToFile(selectedFile)) {
            LOG_ERROR("Save operation failed on the file: " << fileName << " !");
        }
        selectedFile = fileName;
    }
}

void fileRunTask(uint64_t instructionCount){
    if (!selectedFile.empty()){
        LOG_DEBUG("Running code from: " << selectedFile);

        if (uc != nullptr){
            uc_close(uc);
            uc = nullptr;
        }

        if (createStack()){
            std::string bytes = getBytes(selectedFile);
            if (!bytes.empty()){

                if (!runCode(bytes, instructionCount)){
                    tinyfd_messageBox("Unicorn engine error!", "Unable to run the code, please try again or report the "
                                                               "issue on GitHub with your logs!", "ok", "error", 0);
                    LOG_ERROR("Unable to run code!");
                    return;
                }
            }
            else{
                return;
            }
        }
        else{
            LOG_ERROR("Unable to create stack!, quitting!");
        }
    }
    else{
        LOG_ERROR("No file selected to run!");
        tinyfd_messageBox("No file selected!", "Please open a file to run the code!", "ok", "error", 0);
    }
}

void fileSaveUCContextAsJson(const std::string& jsonFilename){
    json j;
    uint64_t value;

    for (auto& reg: x86RegInfoMap){
        j[reg.first] = getRegister(reg.first).second;
    }

    std::ofstream jsonFile(jsonFilename, std::ios::out);
    jsonFile << j.dump() << std::endl;
    jsonFile.close();
}

void fileLoadUCContextFromJson(const std::string& jsonFilename){
    if (jsonFilename.empty()){
        return;
    }

    std::ifstream jsonFile(jsonFilename);
    json j;
    std::stringstream jsonStream;

    jsonStream << jsonFile.rdbuf();
    auto j2 = json::parse(jsonStream.str());

    for (json::iterator it = j2.begin(); it != j2.end(); ++it){
        auto value = it.value().dump();

        if (value.empty() || value == "\"-\"" || value == "'-'"){
        // {"reg": '-'} signals to use the current value of the register
        // and make no changes to it
            continue;
        }

        char *ptr;
        auto ret = strtoul(value.data(), &ptr, 10);
        uc_reg_write(uc, regNameToConstant(it.key()), &ret);
        uc_context_reg_write(context, regNameToConstant(it.key()), value.c_str());
        uc_context_save(uc, context);
    }
}