#include "fileTasks.hpp"
void fileOpenTask(const std::string& fileName){
    if (!fileName.empty()){
        LOG_DEBUG("Opening the file " << fileName);
        if (!readFileIntoEditor(fileName)){
            LOG_ERROR("Read operation failed on the file: " << fileName);
        }
    }
}

void fileSaveAsTask(const std::string &fileName){
    if (!fileName.empty()) {
        LOG_DEBUG("Saving the file " << fileName);
        if (!writeEditorToFile(fileName)) {
            LOG_ERROR("Save as operation failed on the file: " << fileName << " !");
        }
    }
}

void fileSaveTask(const std::string &fileName){
    if (!fileName.empty()){
        LOG_DEBUG("Saving the file " << fileName);
        if (!writeEditorToFile(selectedFile)) {
            LOG_ERROR("Save operation failed on the file: " << fileName << " !");
        }
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