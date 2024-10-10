#include "fileTasks.hpp"
#include "../app.hpp"

std::filesystem::path getTemporaryPath(){
    std::filesystem::path tempDir;
    try{
         tempDir = std::filesystem::temp_directory_path();
    }
    catch (const std::filesystem::filesystem_error& e){
        LOG_NOTICE("Temporary directory not found...\n"
                   "Using current directory for saving temp files");
        tempDir = std::filesystem::current_path();
    }

    return tempDir;
}

bool fileOpenTask(const std::string& fileName){
    if (!fileName.empty()){
        LOG_DEBUG("Opening the file " << fileName);
        if (!readFileIntoEditor(fileName)){
            LOG_ERROR("Read operation failed on the file: " << fileName);
            return false;
        }

        selectedFile = fileName;
        editor->HighlightBreakpoints(-1);
        LOG_INFO("The provided file " << fileName << " opened successfully.");
        return true;
    }

    return true;
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
bool fileRunTask(uint64_t instructionCount){
    if (!selectedFile.empty()){
        LOG_DEBUG("Running code from: " << selectedFile);

        if (uc != nullptr){
            uc_close(uc);
            uc = nullptr;
        }

        if (createStack(&uc)){
            if (instructionCount == 1){
                std::string bytes = getBytes(selectedFile);
                if (!bytes.empty()){
                     runCode(bytes, instructionCount);
                 }
                else {
                    LOG_ERROR("Unable to run the code. Either no code is present or invalid architecture is selected.");
                    return false;
                }
            }
            else if (instructionCount == -1){
                startDebugging();
                debugContinueAction(true);
                return true;
            }
        }
        else{
            tinyfd_messageBox("Stack creation failed!", "The app was unable to create the stack to run the code.\nPlease try restarting it or report this issue on github!",
                "ok", "error", 0);

            LOG_ERROR("Unable to create stack!, quitting!");
            return false;
        }
    }
    else{
        LOG_ERROR("No file selected to run!");
        tinyfd_messageBox("No file selected!", "Please open a file to run the code!", "ok", "error", 0);
        return false;
    }

    return true;
}

void fileSaveUCContextAsJson(const std::string& jsonFilename){
    LOG_INFO("Saving context as a file...");
    LOG_DEBUG("File name is " << jsonFilename);
    json contextJson;

    for (auto&[registerName, regInfo]: regInfoMap){
        if (isRegisterValid(registerName, codeInformation.mode) && (registerName != "INVALID")){
            registerValueT registerValue = getRegisterValue(registerName, false);
            if (regInfo.first <= 64){
                contextJson[registerName] = getRegister(registerName).registerValueUn.eightByteVal;
            }
            else if (regInfo.first == 128){
                // disable saving contexts before code has run
                if (use32BitLanes) {
                    for (int i = 1; i<5; i++) {
                        contextJson[registerName+ "[" + std::to_string(32 * (i - 1)) + ":" + std::to_string((32 * i) - 1) + "]"] = registerValue.info.arrays.floatArray[i-1];
                    }
                }
                else {
                    for (int i = 1; i<3; i++) {
                        contextJson[registerName+ "[" + std::to_string(64 * (i - 1)) + ":" + std::to_string((64  * i) - 1) + "]"] = registerValue.info.arrays.floatArray[i-1];
                    }
                }
            }
            else if (regInfo.first == 256) {
                if (use32BitLanes) {
                    for (int i = 1; i<9; i++) {
                        contextJson[registerName+ "[" + std::to_string(32 * (i - 1)) + ":" + std::to_string((32 * i) - 1) + "]"] = registerValue.info.arrays.floatArray[i-1];
                    }
                }
                else {
                    for (int i = 1; i<5; i++) {
                        contextJson[registerName+ "[" + std::to_string(64 * (i - 1)) + ":" + std::to_string((64  * i) - 1) + "]"] = registerValue.info.arrays.floatArray[i-1];
                    }
                }
            }
        }
    }

    std::ofstream jsonFile(jsonFilename, std::ios::out);
    jsonFile << contextJson.dump() << std::endl;
    jsonFile.close();
    LOG_INFO("Saved context successfully!");
}

void fileLoadUCContextFromJson(const std::string& jsonFilename){
    LOG_DEBUG("Loading context from file " << jsonFilename);
    if (jsonFilename.empty()){
        LOG_ERROR("Unable to load context because the file is empty!");
        tinyfd_messageBox("Context loading failed!", "Context loading has failed because the file you provided is empty",
            "ok", "error", 0);
        return;
    }

    std::ifstream jsonFile(jsonFilename);

    if (jsonFile.bad() || jsonFile.fail() || !jsonFile.is_open()){
         tinyfd_messageBox("Context loading failed!", "Context loading has failed because the file you provided has invalid json format!",
            "ok", "error", 0);
        LOG_ERROR("Unable to open the file: " << jsonFilename << " for loading the context!");
        return;
    }

    json j;
    std::stringstream jsonStream;

    if (context == nullptr){
        enableDebugMode = true;
        fileLoadContext = false;
        runActions();
    }

    jsonStream << jsonFile.rdbuf();
    auto j2 = json::parse(jsonStream.str());

    for (auto jsonIter = j2.begin(); jsonIter != j2.end(); ++jsonIter){
        auto value = jsonIter.value().dump();
        // auto s = jsonIter.key().c_str();

        if (value.empty() || value == "\"-\"" || value == "'-'"){
        // {"reg": '-'} signals to use the current value of the register
        // and make no changes to it
            continue;
        }

        char *ptr;
        auto ret = strtoul(value.data(), &ptr, 10);
        if (getRegisterActualSize(jsonIter.key()) > 64) {
            parseRegisterValueInput(jsonIter.key(), value.c_str(), true);
            continue;
        }
        uc_reg_write(uc, regNameToConstant(jsonIter.key()), &ret);
        // uc_context_reg_write(context, regNameToConstant(jsonIter.key()), value.c_str());
        // uc_context_save(uc, context);
    }

    LOG_DEBUG("Context loaded successfully from " << jsonFilename);
}