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

void fileRunTask(){
    if (!selectedFile.empty()){
        LOG_DEBUG("Running code from: " << selectedFile);

        if (uc != nullptr){
            uc_close(uc);
            uc = nullptr;
        }

        if (createStack()){
            runCode(getBytes(selectedFile), 0);
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