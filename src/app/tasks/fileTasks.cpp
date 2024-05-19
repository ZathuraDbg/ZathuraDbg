#include "fileTasks.hpp"

void fileOpenTask(const std::string& fileName){
    std::cout << "Selected files:";
    if (!fileName.empty()){
        std::cout << " " + fileName << "\n";
        if (!readFileIntoEditor(fileName)){
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
        if (!writeEditorToFile(fileName)) {
            pfd::message("File write error!",
                         "Sorry, the file you selected couldn't be opened or written to.\nPlease make sure "
                         "no other program is using this file and you have the correct permissions to access the file and try again!",
                         pfd::choice::ok,
                         pfd::icon::error);
        }
    }
}

void fileSaveTask(const std::string &fileName){
    std::cout << "writing to " << selectedFile << std::endl;
    if (!writeEditorToFile(selectedFile)) {
        pfd::message("File write error!",
                     "Sorry, the file you selected couldn't be opened or written to.\nPlease make sure "
                     "no other program is using this file and you have the correct permissions to access the file and try again!",
                     pfd::choice::ok,
                     pfd::icon::error);
    }
}