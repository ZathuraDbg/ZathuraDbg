#include "fileTasks.hpp"

void fileOpenTask(const std::string& fileName){
    if (!fileName.empty()){
        LOG_DEBUG("Opening the file " << fileName);
        if (!readFileIntoEditor(fileName)){
            LOG_ERROR("Unable to read the requested file: " << fileName);
            pfd::message("File read error!",
                         "Sorry, the file you selected couldn't be opened or read.\nPlease make sure "
                         "no other program is using this file and you have the correct permissions to access the file and try again!",
                         pfd::choice::ok,
                         pfd::icon::error);
        }
    }
}

void fileSaveAsTask(const std::string &fileName){
    if (!fileName.empty()) {
        LOG_DEBUG("Saving the file " << fileName);
        if (!writeEditorToFile(fileName)) {
            LOG_ERROR("File can not be saved as " << fileName << " !");
            pfd::message("File write error!",
                         "Sorry, the file you selected couldn't be opened or written to.\nPlease make sure "
                         "no other program is using this file and you have the correct permissions to access the file and try again!",
                         pfd::choice::ok,
                         pfd::icon::error);
        }

    }
}

void fileSaveTask(const std::string &fileName){
    if (!fileName.empty()){
        LOG_DEBUG("Saving the file " << fileName);
        if (!writeEditorToFile(selectedFile)) {
                    LOG_ERROR(fileName << " cannot be saved!");
            pfd::message("File write error!",
                         "Sorry, the file you selected couldn't be opened or written to.\nPlease make sure "
                         "no other program is using this file and you have the correct permissions to access the file and try again!",
                         pfd::choice::ok,
                         pfd::icon::error);
        }
    }
}

void fileRunTask(){
    if (!selectedFile.empty()){
        LOG_DEBUG("Running code from: " << selectedFile);
        uc_close(uc);
        ucInit();
        createStack();
        runCode(getBytes(selectedFile), 0);
    }
    else{
        LOG_ERROR("No file selected to run!");
        pfd::message("No file selected!",
                     "Please open a file to run the code!",
                     pfd::choice::ok,
                     pfd::icon::info);
    }
}